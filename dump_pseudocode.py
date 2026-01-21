import ida_hexrays
import ida_funcs
import ida_auto
import ida_nalt
import idautils
import idc
import ida_segment
import ida_bytes
import ida_name
import os
import sys

def format_data_item(ea):
    name = idc.get_name(ea)
    if not name:
        name = f"unk_{hex(ea)[2:]}"
    
    if name.startswith("def_"):
        return None

    flags = ida_bytes.get_flags(ea)
    
    if ida_bytes.is_strlit(flags):
        content = idc.get_strlit_contents(ea)
        if content:
            try:
                str_content = content.decode('utf-8', 'ignore')
                str_content = str_content.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
                return f'char {name}[] = "{str_content}";'
            except:
                return f'// char {name}[] = <binary data>;'

    size = idc.get_item_size(ea)
    value = 0
    c_type = "unsigned char"
    
    if size == 1:
        value = ida_bytes.get_byte(ea)
        c_type = "uint8_t"
    elif size == 2:
        value = ida_bytes.get_word(ea)
        c_type = "uint16_t"
    elif size == 4:
        value = ida_bytes.get_dword(ea)
        c_type = "uint32_t"
    elif size == 8:
        value = ida_bytes.get_qword(ea)
        c_type = "uint64_t"
    else:
        return f"// {name} (Size: {size} bytes, Type: Complex/Struct)"

    comment = ""
    if size in [4, 8]:
        if ida_segment.getseg(value):
            target_name = idc.get_name(value)
            if target_name:
                comment = f" // -> {target_name}"

    return f"{c_type} {name} = {hex(value)};{comment}"

def dump_data_segments(f):
    f.write("// ========================================================\n")
    f.write("// DATA SECTIONS\n")
    f.write("// ========================================================\n\n")

    data_seg_names = [".data", ".rodata", ".bss", ".rdata", "__data", "__const"]

    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        seg_name = idc.get_segm_name(seg_ea)
        
        is_data = (seg.type == ida_segment.SEG_DATA or seg.type == ida_segment.SEG_BSS)
        name_match = any(s in seg_name.lower() for s in data_seg_names)

        if is_data or name_match:
            f.write(f"// Section: {seg_name} ({hex(seg.start_ea)} - {hex(seg.end_ea)})\n")
            
            for head in idautils.Heads(seg.start_ea, seg.end_ea):
                try:
                    line = format_data_item(head)
                    if line:
                        f.write(f"// Addr: {hex(head)}\n")
                        f.write(line + "\n")
                except Exception as e:
                    f.write(f"// Error parsing data at {hex(head)}: {e}\n")
            f.write("\n")

def dump_all_pseudocode(output_file):
    ida_auto.auto_wait()
    
    if not ida_hexrays.init_hexrays_plugin():
        print("Error: Hex-Rays decompiler plugin not found or load failed")
        return

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"// Decompiled from: {ida_nalt.get_input_file_path()}\n")

        try:
            dump_data_segments(f)
        except Exception as e:
            f.write(f"// Failed to dump data segments: {e}\n\n")

        f.write("// ========================================================\n")
        f.write("// FUNCTIONS\n")
        f.write("// ========================================================\n\n")

        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    f.write(f"// Address: {hex(func_ea)}\n")
                    f.write(f"// Function: {func_name}\n")
                    f.write(str(cfunc))
                    f.write("\n" + "-"*40 + "\n\n")
            except Exception as e:
                f.write(f"// Failed to decompile {func_name} at {hex(func_ea)}\n")
                f.write(f"// Error: {str(e)}\n\n")
                

if __name__ == "__main__": #..\idat.exe -c -A -S"dump_pseudocode.py" target_file
    root_name = ida_nalt.get_root_filename()
    if not root_name:
        if len(sys.argv) > 1:
            print("Running in interactive mode, assume file loaded.")
        else:
            print("Error: No target file loaded")
            idc.qexit(1)

    output_path = os.path.join(os.getcwd(), f"{root_name}.c")
    
    try:
        dump_all_pseudocode(output_path)
    except Exception as e:
        print(e)
    finally:
        idc.qexit(0)
