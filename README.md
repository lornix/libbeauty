libbeauty
=========

Decompiler and Reverse Engineering tool

The current aim has been changed to the following:
1) Take a x86_64 binary .o file as input.
2) Create an equivalent LLVM IR .o as output. Also referred to as .bc or .ll (llvm.org) file formats.
3) Add automated testing.

Once the above works, the aims will be expanded to include:
1) Also support x86_32 binary .o file as input.
2) Also support ARM binary .o file as input.
3) Create .c source code files from the LLVM IR .o file.
4) Implement support for self modifying code.

