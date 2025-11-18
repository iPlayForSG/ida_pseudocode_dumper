# ida_pseudocode_dumper
A lightweight IDAPython script. Exports all pseudocode to a single C source file.
Useful for static analysis or dataset generation for LLMs.
For 64-bit binaries
```
idat64.exe -c -A -S"dump_pseudocode.py" <target_binary>
```

For 32-bit binaries or IDA 9.x
```
idat.exe -c -A -S"dump_pseudocode.py" <target_binary>
```
