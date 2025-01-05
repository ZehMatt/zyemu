## x86-64 emulation using JIT 

WIP x86-64 user mode emulation using Zydis. Instead of writing code for each instruction zyemu
will generate a specific function for the emulator to execute. 

For an instruction such as `mov r12, rax` it would generate following function to emulate it:
```asm
0000021CF4CB0000  mov         r11, qword ptr [rcx+18h]  ; Load value of rax from virtual context.
0000021CF4CB0004  mov         r10, r11                  ; r10 is used for r12
0000021CF4CB0007  mov         qword ptr [rcx+78h], r10  ; Store value of r12 in virtual context.
0000021CF4CB000B  add         qword ptr [rcx+8], 3      ; Update IP, length of this instruction is 3 bytes.
0000021CF4CB0010  mov         rax, 0                    ; Status code.
0000021CF4CB0017  ret  
```

