import ida_hexrays
import ida_funcs
import ida_auto
import ida_nalt
import idautils
import idc
import os
import sys

def dump_all_pseudocode(output_file):
    ida_auto.auto_wait()
    
    if not ida_hexrays.init_hexrays_plugin():
        print("Error: Hex-Rays decompiler plugin not found or load failed")
        return

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"// Decompiled from: {ida_nalt.get_input_file_path()}\n")

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
                
    print("Done.")

if __name__ == "__main__":
    root_name = ida_nalt.get_root_filename()
    if not root_name:
        print("Error: No target file loaded")
        print("Usage: idat.exe -c -A -S\"dump_pseudocode.py\" target_file")
        idc.qexit(1)

    output_path = os.path.join(os.getcwd(), f"{root_name}.c")
    
    try:
        dump_all_pseudocode(output_path)
        print(f"Pseudocode dumped to: {output_path}")
    except Exception as e:
        print(e)
    finally:
        idc.qexit(0)
