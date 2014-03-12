libbeauty
=========

Decompiler and Reverse Engineering tool

The current aim has been changed to the following:<br>
1) Take a x86_64 binary .o file as input.<br>
2) Create an equivalent LLVM IR .o as output. Also referred to as .bc or .ll (llvm.org) file formats.<br>
3) Add automated testing.<br>

Once the above works, the aims will be expanded to include:<br>
1) Also support x86_32 binary .o file as input.<br>
2) Also support ARM binary .o file as input.<br>
3) Create .c source code files from the LLVM IR .o file.<br>
4) Implement support for self modifying code.<br>
<br>
TODO:<br>
1) Type inference propagation (TIP).<br>
	When registers are converted to SSA form, they are called "labels".<br>
	In order to get from ASM to LLVM IR, we need to know if labels are pointers or not.<br>
	Also, we need to know the bit width of labels.<br>
	If anyone can help me in this area I would appreciate it.<br>
<br>
Note: We only have this last todo item left, and this tool will become really useful!<br>

