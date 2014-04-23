/*
 *  Copyright (C) 2004  The revenge Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * 24-08-2013 Initial work.
 *   Copyright (C) 2004 James Courtier-Dutton James@superbug.co.uk
 *
 * This test_id program is to test the instruction decoder.
 * The conversion process from binary bytes to LLVM IR instructions is:
 * 1)	instruction decode: converts binary bytes into an intermediate format that
 *	represents a single target instruction as a single decoded instruction.
 *	This single decoded instruction has OPCODE, PARAMS_LIST_TYPE, LIST_OF_PARAMS.
 *	This single decoded instruction is target specific.
 * 2)	RTL: this stage takes the "instruction decode" and translates it into a number of RTL
 *	instructions. This is similar to, but not exactly like LLVM IR.
 *	The major difference is that it still contains the concept of flags.
 * 3)	LLVM IR: this stage takes the RTL, goes through a process of removing the flags 
 *	and replacing them with LLVM IR instructions that uses (1 bit integer) I1 registers instead of flags.
 * The reason to do 1+2 instead to straight from binary to 2 is to make it easier to test,
 * and also make updates easier when the RTL format changes.
 * A majority of the complexity is in step 1, so good testing of step 1 is vital.
 * It is difficult to test step 2 and step 3, but they are far less complex.
 * This program tests stage (1).
 * The test method will use a number of different methods:
 * 1) Fixed input set of bytes. Make sure the correct OPCODE, PARAMS_LIST_TYPE, LIST_OF_PARAMS is created
 *	by comparing it to the expected output product.
 * 2) Use binutils disassembler, parse the output to OPCODE, PARAMS_LIST_TYPE, LIST_OF_PARAMS, and then
 *	compare that output to the one form the instruction decoder.
 * 3) Use LLVM objdump disassembler, parse the output to OPCODE, PARAMS_LIST_TYPE, LIST_OF_PARAMS, and then
 *	compare that output to the one form the instruction decoder.
*/

/* Intel ia32 instruction format: -
 Instruction-Prefixes (Up to four prefixes of 1-byte each. [optional] )
 Opcode (1-, 2-, or 3-byte opcode)
 ModR/M (1 byte [if required] )
 SIB (Scale-Index-Base:1 byte [if required] )
 Displacement (Address displacement of 1, 2, or 4 bytes or none)
 Immediate (Immediate data of 1, 2, or 4 bytes or none)

 Naming convention taked from Intel Instruction set manual,
 Appendix A. 25366713.pdf
*/

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

//#include <rev.h>
//#include <bfl.h>

#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>
#include "instruction_low_level.h"
#include "decode_inst.h"
#include <rev.h>
#include <dis.h>
#include <convert_ll_inst_to_rtl.h>

#define EIP_START 0x40000000

//struct dis_instructions_s dis_instructions;
uint8_t *inst;
size_t inst_size = 0;
uint8_t *data;
size_t data_size = 0;
uint8_t *rodata;
size_t rodata_size = 0;
void *handle_void;
char *dis_flags_table[] = { " ", "f" };
uint64_t inst_log = 1;	/* Pointer to the current free instruction log entry. */
//struct self_s *self = NULL;

/* debug: 0 = no debug output. >= 1 is more debug output */
int debug_dis64 = 0;
int debug_input_bfd = 0;
int debug_input_dis = 0;
int debug_exe = 0;
int debug_analyse = 0;
int debug_analyse_paths = 0;
int debug_analyse_phi = 0;
int debug_output = 0;

struct test_data_s {
	int	valid;
	uint8_t bytes[16];
	int bytes_size;
	char *inst[10];
	int inst_size;
};

//#define ADD 1
//#define LEA 2
//#define PUSH 3
//#define MOV 4
//#define SHL 5
//#define NOP 6
//#define SAR 7

struct test_data_s test_data[] = {
	{
		.valid = 1,
		// addl    %edi, %eax
		.bytes = {0x01, 0xf8},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:ADDf r0x8/32, r0x40/32, r0x8/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// addb    $2, %al
		.bytes = {0x04, 0x02},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:ADDf r0x8/8, i0x2/8, r0x8/8",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// leal    291(%rdi), %eax
		.bytes = {0x8d, 0x87, 0x23, 0x01, 0, 0},
		.bytes_size = 6,
		.inst[0] = "// 0x0000:ADD  r0x40/64, i0x123/64, r0x160/64",
		.inst[1] = "// 0x0001:MOV  r0x160/64, r0x8/32",
		.inst_size = 2,
	},
	{
		.valid = 1,
		// movzbl  -96(%rbp), %esi
		.bytes = {0x0f, 0xb6, 0x75, 0xa0},
		.bytes_size = 6,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x60/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x160]/8, r0x160/64, r0x180/8",
		.inst[2] = "// 0x0002:MOV  r0x180/8, r0x38/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// movzbl  1061(%rbx), %edx
		.bytes = {0x0f, 0xb6, 0x93, 0x25, 0x04, 0x00, 0x00},
		.bytes_size = 7,
		.inst[0] = "// 0x0000:ADD  r0x20/64, i0x425/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  m[r0x160]/8, r0x160/64, r0x180/8",
		.inst[2] = "// 0x0002:MOV  r0x180/8, r0x18/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// movq    $0, %rdx
		.bytes = {0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00},
		.bytes_size = 7,
		.inst[0] = "// 0x0000:MOV  i0x0/64, r0x18/64",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// movl    $4294967201, -104(%rbp)
		.bytes = {0xc7, 0x45, 0x98, 0xa1, 0xff, 0xff, 0xff},
		.bytes_size = 7,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x68/64, r0x160/64",
		.inst[1] = "// 0x0001:MOV  i0xffffffa1/32, r0x180/32",
		.inst[2] = "// 0x0002:STORE  r0x180/32, r0x160/64, s[r0x160]/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// movb    $12, 1046(%r12)
		.bytes = {0x41, 0xc6, 0x84, 0x24, 0x16, 0x04, 0x00, 0x00, 0x0c},
		.bytes_size = 9,
		.inst[0] = "// 0x0000:ADD  r0x70/64, i0x416/64, r0x160/64",
		.inst[1] = "// 0x0001:MOV  i0xc/8, r0x180/8",
		.inst[2] = "// 0x0002:STORE  r0x180/8, r0x160/64, m[r0x160]/8",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// push   %rbp
		.bytes = {0x55},
		.bytes_size = 1,
		.inst[0] = "// 0x0000:SUB  r0x28/64, i0x8/64, r0x28/64",
		.inst[1] = "// 0x0001:STORE  r0x30/64, r0x28/64, s[r0x28]/64",
		.inst_size = 2,
	},
	{
		.valid = 1,
		// sarl	$2, %esi
		.bytes = {0xc1, 0xfe, 0x02},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:SARf r0x38/32, i0x2/8, r0x38/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// movslq %esi,%rsi
		.bytes = {0x48, 0x63, 0xf6},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:SEX  r0x38/32, r0x38/64",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// shlq    $0x2,%rsi
		.bytes = {0x48, 0xc1, 0xe6, 0x02},
		.bytes_size = 4,
		.inst[0] = "// 0x0000:SHLf r0x38/64, i0x2/8, r0x38/64",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// movq    %rsp,%rbp
		.bytes = {0x48, 0x89, 0xe5},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:MOV  r0x28/64, r0x30/64",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// addq   0x60(%rdi),%rsi
		.bytes = {0x48, 0x03, 0x77, 0x60},
		.bytes_size = 4,
		.inst[0] = "// 0x0000:ADD  r0x40/64, i0x60/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  m[r0x160]/64, r0x160/64, r0x180/64",
		.inst[2] = "// 0x0002:ADDf r0x38/64, r0x180/64, r0x38/64",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// mov    (%rsi),%eax
		.bytes = {0x8b, 0x06},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:ADD  r0x38/64, i0x0/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  m[r0x160]/32, r0x160/64, r0x180/32",
		.inst[2] = "// 0x0002:MOV  r0x180/32, r0x8/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// leaveq
		.bytes = {0xc9},
		.bytes_size = 1,
		.inst[0] = "// 0x0000:MOV  r0x30/64, r0x28/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x28]/64, r0x28/64, r0x30/64",
		.inst[2] = "// 0x0002:ADD  r0x28/64, i0x8/64, r0x28/64",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// retq
		.bytes = {0xc3},
		.bytes_size = 1,
		.inst[0] = "// 0x0000:LOAD  s[r0x28]/64, r0x28/64, r0x160/64",
		.inst[1] = "// 0x0001:ADD  r0x28/64, i0x8/64, r0x28/64",
		.inst[2] = "// 0x0002:NOP ",
		.inst[3] = "// 0x0003:MOV  r0x160/64, r0x48/64",
		.inst_size = 4,
	},
	{
		.valid = 1,
		// nopw   %cs:0x0(%rax,%rax,1)
		.bytes = {0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
		.bytes_size = 10,
		.inst_size = 0,
	},
	{
		.valid = 1,
		// subl   $0x1,-0x8(%rbp)
		.bytes = {0x83, 0x6d, 0xf8, 0x01},
		.bytes_size = 4,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x8/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x160]/32, r0x160/64, r0x180/32",
		.inst[2] = "// 0x0002:SUBf r0x180/32, i0x1/32, r0x180/32",
		.inst[3] = "// 0x0003:STORE  r0x180/32, r0x160/64, s[r0x160]/32",
		.inst_size = 4,
	},
	{
		.valid = 1,
		// addl   $0x1,-0x4(%rbp)
		.bytes = {0x83, 0x45, 0xfc, 0x01},
		.bytes_size = 4,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x4/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x160]/32, r0x160/64, r0x180/32",
		.inst[2] = "// 0x0002:ADDf r0x180/32, i0x1/32, r0x180/32",
		.inst[3] = "// 0x0003:STORE  r0x180/32, r0x160/64, s[r0x160]/32",
		.inst_size = 4,
	},
	{
		.valid = 1,
		// movl    $0x123,%eax
		.bytes = {0xb8, 0x23, 0x01, 0x00, 0x00},
		.bytes_size = 5,
		.inst[0] = "// 0x0000:MOV  i0x123/32, r0x8/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// movslq -0x4(%rsp),%rax
		.bytes = {0x48, 0x63, 0x44, 0x24, 0xfc},
		.bytes_size = 5,
		.inst[0] = "// 0x0000:SUB  r0x28/64, i0x4/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x160]/32, r0x160/64, r0x180/32",
		.inst[2] = "// 0x0002:SEX  r0x180/32, r0x8/64",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// jmpq   *%rax
		.bytes = {0xff, 0xe0},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:JMPT  r0x8/64, r0x48/64",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// mov    0x0700(,%rax,8),%rax
		.bytes = {0x48, 0x8b, 0x04, 0xc5, 0x00, 0x07, 0x00, 0x00},
		.bytes_size = 8,
		.inst[0] = "// 0x0000:IMUL  r0x8/64, i0x8/64, r0x160/64",
		.inst[1] = "// 0x0001:ADD  r0x160/64, i0x700/64, r0x160/64",
		.inst[2] = "// 0x0002:LOAD  m[r0x160]/64, r0x160/64, r0x180/64",
		.inst[3] = "// 0x0003:MOV  r0x180/64, r0x8/64",
		.inst_size = 4,
	},
	{
		.valid = 1,
		// imul   $0x7,-0x8(%rsp),%rdi
		.bytes = {0x48, 0x69, 0x7c, 0x24, 0xf8, 0x07, 0x00, 0x00, 0x00},
		.bytes_size = 9,
		.inst[0] = "// 0x0000:SUB  r0x28/64, i0x8/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x160]/64, r0x160/64, r0x180/64",
		.inst[2] = "// 0x0002:IMULf i0x7/64, r0x180/64, r0x40/64",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// imul   $0x7,%rdi,%rax
		.bytes = {0x48, 0x6b, 0xc7, 0x07},
		.bytes_size = 4,
		.inst[0] = "// 0x0000:IMULf i0x7/64, r0x40/64, r0x8/64",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// dec    %edi
		.bytes = {0xff, 0xcf},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:SUBf r0x40/32, i0x1/32, r0x40/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// mov    %eax,-0x4(%rbp)
		.bytes = {0x89, 0x45, 0xfc},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x4/64, r0x160/64",
		.inst[1] = "// 0x0001:MOV  r0x8/32, r0x180/32",
		.inst[2] = "// 0x0002:STORE  r0x180/32, r0x160/64, s[r0x160]/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// mov    -0x4(%rbp),%eax
		.bytes = {0x8b, 0x45, 0xfc},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x4/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x160]/32, r0x160/64, r0x180/32",
		.inst[2] = "// 0x0002:MOV  r0x180/32, r0x8/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// add    %eax,-0x4(%rbp)
		.bytes = {0x01, 0x45, 0xfc},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x4/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x160]/32, r0x160/64, r0x180/32",
		.inst[2] = "// 0x0002:ADDf r0x180/32, r0x8/32, r0x180/32",
		.inst[3] = "// 0x0003:STORE  r0x180/32, r0x160/64, s[r0x160]/32",
		.inst_size = 4,
	},
	{
		.valid = 1,
		// movl   $0x1,(%rax)
		.bytes = {0xc7, 0x00, 0x01, 0x00, 0x00, 0x00},
		.bytes_size = 6,
		.inst[0] = "// 0x0000:ADD  r0x8/64, i0x0/64, r0x160/64",
		.inst[1] = "// 0x0001:MOV  i0x1/32, r0x180/32",
		.inst[2] = "// 0x0002:STORE  r0x180/32, r0x160/64, m[r0x160]/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// callq  *0x8(%rbx)
		.bytes = {0xff, 0x53, 0x08},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:ADD  r0x20/64, i0x8/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  m[r0x160]/64, r0x160/64, r0x180/64",
		.inst[2] = "// 0x0002:CALL  (r0x180/64) ();",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// callq  *%rax
		.bytes = {0xff, 0xd0},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:CALL  (r0x8/64) ();",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// cmovne %edx,%eax
		.bytes = {0x0f, 0x45, 0xc2},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:IF   cond=6 JMP-REL=0x0",
		.inst[1] = "// 0x0001:MOV  r0x18/32, r0x8/32",
		.inst_size = 2,
	},
	{
		.valid = 1,
		// setne  -0x5b(%rbp)
		.bytes = {0x0f, 0x95, 0x45, 0xa5},
		.bytes_size = 4,
		.inst[0] = "// 0x0000:IF   cond=6 JMP-REL=0x0",
		.inst[1] = "// 0x0001:SUB  r0x30/64, i0x5b/64, r0x160/64",
		.inst[2] = "// 0x0002:MOV  i0x1/8, r0x180/8",
		.inst[3] = "// 0x0003:STORE  r0x180/8, r0x160/64, s[r0x160]/8",
		.inst[4] = "// 0x0004:IF   cond=5 JMP-REL=0x0",
		.inst[5] = "// 0x0005:SUB  r0x30/64, i0x5b/64, r0x160/64",
		.inst[6] = "// 0x0006:MOV  i0x0/8, r0x180/8",
		.inst[7] = "// 0x0007:STORE  r0x180/8, r0x160/64, s[r0x160]/8",
		.inst_size = 8,
	},
	{
		.valid = 1,
		// jmpq   *0x0(,%rax,8)
		.bytes = {0xff, 0x24, 0xc5, 0x00, 0x00, 0x00, 0x00},
		.bytes_size = 7,
		.inst[0] = "// 0x0000:IMUL  r0x8/64, i0x8/0, r0x160/64",
		.inst[1] = "// 0x0001:ADD  r0x160/64, i0x0/64, r0x160/64",
		.inst[2] = "// 0x0002:LOAD  m[r0x160]/64, r0x160/64, r0x180/64",
		.inst[3] = "// 0x0003:JMPT  r0x180/64, r0x48/64",
		.inst_size = 4,
	},
	{
		.valid = 1,
		// cltq CDQE
		.bytes = {0x48, 0x98},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:SEX  r0x8/32, r0x8/64",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// jmpq 
		.bytes = {0xe9, 0x98, 0xfc, 0xff, 0xff},
		.bytes_size = 5,
		.inst[0] = "// 0x0000:JMP  i0xfffffffffffffc98/64, r0x48/64",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// rep movsq %ds:(%rsi),%es:(%rdi) 
		.bytes = {0xf3, 0x48, 0xa5},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:CMPf r0x10/64, i0x0/64",
		.inst[1] = "// 0x0001:IF   cond=4 JMP-REL=0x0",
		.inst[2] = "// 0x0002:SUB  i0x1/64, r0x10/64, r0x10/64",
		.inst[3] = "// 0x0003:LOAD  m[r0x38]/64, r0x38/64, r0x180/64",
		.inst[4] = "// 0x0004:STORE  r0x180/64, r0x40/64, m[r0x40]/64",
		.inst[5] = "// 0x0005:ADD  i0x8/64, r0x38/64, r0x38/64",
		.inst[6] = "// 0x0006:ADD  i0x8/64, r0x40/64, r0x40/64",
		.inst[7] = "// 0x0007:JMP  i0xfffffffffffffffd/64, r0x48/64",
		.inst_size = 8,
	},
	{
		.valid = 1,
		// test   %eax,%eax
		.bytes = {0x85, 0xc0},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:TESTf r0x8/32, r0x8/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// movss  -0x4(%rbp),%xmm0
		.bytes = {0xf3, 0x0f, 0x10, 0x45, 0xfc},
		.bytes_size = 5,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x4/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x160]/128, r0x160/64, r0x180/128",
		.inst[2] = "// 0x0002:MOV  r0x180/128, r0x100/128",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// shl    %cl,%edx
		.bytes = {0xd3, 0xe2},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:SHLf r0x18/32, r0x10/8, r0x18/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// mov    %r13d,%ecx
		.bytes = {0x44, 0x89, 0xe9},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:MOV  r0x78/32, r0x10/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// cmp    $0x1,%esi
		.bytes = {0x83, 0xfe, 0x01},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:CMPf r0x38/32, i0x1/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// cmpl   $0x1,0x3c8(%r12)
		.bytes = {0x41, 0x83, 0xbc, 0x24, 0xc8, 0x03, 0x00, 0x00, 0x01},
		.bytes_size = 9,
		.inst[0] = "// 0x0000:ADD  r0x70/64, i0x3c8/64, r0x160/64",
		.inst[1] = "// 0x0001:LOAD  m[r0x160]/32, r0x160/64, r0x180/32",
		.inst[2] = "// 0x0002:CMPf r0x180/32, i0x1/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// 0f be c0             	movsbl %al,%eax
		.bytes = {0x0f, 0xbe, 0xc0},
		.bytes_size = 3,
		.inst[0] = "// 0x0000:SEX  r0x8/8, r0x8/32",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// e8 78 56 34 12	callq
		.bytes = {0xe8, 0x78, 0x56, 0x34, 0x12},
		.bytes_size = 5,
		.inst[0] = "// 0x0000:CALL 0x12345678 ();",
		.inst_size = 1,
	},
	{
		.valid = 1,
		// 7e e5                	jle    7 <test47+0x7>
		.bytes = {0x7e, 0xe5},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:IF   cond=15 JMP-REL=0xffffffffffffffe5",
		.inst_size = 1,
	},
};

#define test_data_no sizeof(test_data) / sizeof(struct test_data_s)

void dbg_print(const char* func, int line, int module, int level, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	switch (module) {
	case DEBUG_MAIN:
		if (level <= debug_dis64) {
			fprintf(stderr, "DEBUG_MAIN,0x%x %s,%d: ", level, func, line);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_INPUT_BFD:
		if (level <= debug_input_bfd) {
			fprintf(stderr, "DEBUG_INPUT_BFD,0x%x %s,%d: ", level, func, line);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_INPUT_DIS:
		if (level <= debug_input_dis) {
			fprintf(stderr, "DEBUG_INPUT_DIS,0x%x %s,%d: ", level, func, line);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_EXE:
		if (level <= debug_exe) {
			fprintf(stderr, "DEBUG_EXE,0x%x %s,%d: ", level, func, line);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_ANALYSE:
		if (level <= debug_analyse) {
			fprintf(stderr, "DEBUG_ANALYSE,0x%x %s,%d: ", level, func, line);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_ANALYSE_PATHS:
		if (level <= debug_analyse_paths) {
			fprintf(stderr, "DEBUG_ANALYSE_PATHS,0x%x %s,%d: ", level, func, line);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_ANALYSE_PHI:
		if (level <= debug_analyse_phi) {
			fprintf(stderr, "DEBUG_ANALYSE_PHI,0x%x %s,%d: ", level, func, line);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_OUTPUT:
		if (level <= debug_output) {
			fprintf(stderr, "DEBUG_OUTPUT,0x%x %s,%d: ", level, func, line);
			vfprintf(stderr, format, ap);
		}
		break;
	default:
		printf("DEBUG Failed: Module 0x%x\n", module);
		exit(1);
		break;
	}
	va_end(ap);
}

#if 0
int disassemble(void *handle_void, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset) {
	int tmp;
	tmp = disassemble_amd64(handle_void, dis_instructions, base_address, offset);
	return tmp;
}
#endif

void setLogLevel()
{
	if (getenv("ENABLE_DEBUG_DIS64"))
		debug_dis64 = 1;
	if (getenv("ENABLE_DEBUG_INPUT_BFD"))
		debug_input_bfd = 1;
	if (getenv("ENABLE_DEBUG_INPUT_DIS"))
		debug_input_dis = 1;
	if (getenv("ENABLE_DEBUG_EXE"))
		debug_exe = 1;
	if (getenv("ENABLE_DEBUG_ANALYSE"))
		debug_analyse = 1;
	if (getenv("ENABLE_DEBUG_ANALYSE_PATHS"))
		debug_analyse_paths = 1;
	if (getenv("ENABLE_DEBUG_ANALYSE_PHI"))
		debug_analyse_phi = 1;
	if (getenv("ENABLE_DEBUG_OUTPUT"))
		debug_output = 1;
}

int main(int argc, char *argv[])
{
	int n,m,l;
	int octets = 0;
	int offset = 0;
	int tmp;
	struct self_s *self = NULL;
	LLVMDisasmContextRef DC;
	LLVMDecodeAsmContextRef DC2;
	LLVMDecodeAsmX86_64Ref DA;
	struct dis_instructions_s dis_instructions;
	uint8_t buffer1[1024];
	uint8_t *buffer;
	size_t buffer_size = 0;
	const char *opcode_name = NULL;
	void *inst;
	int *test_result;
	struct string_s string1;
	string1.len = 0;
	string1.max = 1023;
	string1.string[0] = 0;
	int result_count;

	setLogLevel();

	if (argc != 1) {
		debug_print(DEBUG_MAIN, 1, "Syntax error\n");
		debug_print(DEBUG_MAIN, 1, "Usage: test_id\n");
		exit(1);
	}

	debug_print(DEBUG_MAIN, 1, "Setup ok\n");
	debug_print(DEBUG_MAIN, 1, "size_of test_data = 0x%lx\n", sizeof(test_data));
	debug_print(DEBUG_MAIN, 1, "size_of struct test_data_s = 0x%lx\n", sizeof(struct test_data_s));
	debug_print(DEBUG_MAIN, 1, "number of test_data entries = 0x%lx\n", sizeof(test_data) / sizeof(struct test_data_s));
	debug_print(DEBUG_MAIN, 1, "test_data_no = 0x%lx\n", test_data_no);

//	LLVMInitializeAllTargetInfos();
//	LLVMInitializeAllTargetMCs();
//	LLVMInitializeAllAsmParsers();
//	LLVMInitializeAllDisassemblers();
	LLVMInitializeX86TargetInfo();
	LLVMInitializeX86TargetMC();
	LLVMInitializeX86AsmParser();
	LLVMInitializeX86Disassembler();

	
	DA = LLVMNewDecodeAsmX86_64();
	if (!DA) {
		printf("LLVMNewDecodeAsmX86_64() failed\n");
		exit(1);
	}
	tmp = LLVMSetupDecodeAsmX86_64(DA);
	if (tmp) {
		printf("LLVMSetupDecodeAsmX86_64() failed\n");
		exit(1);
	}
//	LLVMPrintTargets();
	DC = LLVMCreateDisasm("x86_64-pc-linux-gnu", NULL,
		0, NULL,
		NULL);
	printf("DC = %p\n", DC);
	if (!DC) {
		printf("LLVMCreateDisasm() failed\n");
		exit(1);
	}
//	inst = LLVMCreateMCInst();
//	printf("inst %p\n", inst);
	struct instruction_low_level_s *ll_inst = calloc(1, sizeof(struct instruction_low_level_s));

//	LLVMPrintTargets();
//	DC2 = LLVMCreateDecodeAsm("x86_64-pc-linux-gnu", inst,
//		0, NULL,
//		NULL);
//	if (!DC2) {
//		printf("LLVMCreateDecodeAsm() failed\n");
//		exit(1);
//	}
//	LLVMPrintTargets();
//const MCInstrInfo *MII = LLVMDisasmGetMII(DC2);
//	int num_opcodes = LLVMDecodeAsmGetNumOpcodes(DC2);
//	printf("num_opcodes = 0x%x\n", num_opcodes);

	//LLVMDecodeAsmPrintOpcodes(DC); 
//	LLVMDecodeAsmOpcodesSource(DC); 

	self = calloc(1, sizeof(struct self_s));
	test_result = calloc(test_data_no, sizeof(int));

	for (l = 0; l < test_data_no; l++) {
//	for (l = 3; l < 4; l++) {
		if (!test_data[l].valid) {
			debug_print(DEBUG_MAIN, 1, "Test input data absent\n");
		}
		printf("\nSTART test data 0x%x\n", l);

		buffer_size = test_data[l].bytes_size;
		buffer = &(test_data[l].bytes[0]);
#if 0
		tmp = bf_disassemble_init(handle_void, inst_size, inst);
		debug_print(DEBUG_MAIN, 1, "disassemble att  : ");
		bf_disassemble_set_options(handle_void, "att");
		bf_disassemble_callback_start(handle_void);
		octets = bf_disassemble(handle_void, offset);
		bf_disassemble_callback_end(handle_void);
		debug_print(DEBUG_MAIN, 1, "  octets=%d\n", octets);
		debug_print(DEBUG_MAIN, 1, "disassemble intel: ");
		bf_disassemble_set_options(handle_void, "intel");
		bf_disassemble_callback_start(handle_void);
		octets = bf_disassemble(handle_void, offset);
		bf_disassemble_callback_end(handle_void);
		debug_print(DEBUG_MAIN, 1, "  octets=%d\n", octets);
#endif
		octets = LLVMDisasmInstruction(DC, buffer,
			buffer_size, offset,
			(char *)buffer1, 1023);
		LLVMDisasmInstructionPrint(octets, buffer, buffer_size, buffer1);
		if (octets != test_data[l].bytes_size) {
			tmp = octets;
			octets = LLVMDisasmInstruction(DC, buffer + tmp,
				buffer_size - tmp, offset,
				(char *)buffer1, 1023);
			LLVMDisasmInstructionPrint(octets, buffer + tmp, buffer_size - tmp, buffer1);
		}

//		printf("LLVM DIS octets = 0x%x:", octets);
//		for (n = 0; n < octets; n++) {
//			printf("%02x ", buffer[n]);
//		}
//		printf(":%s\n", buffer1);
		opcode_name = NULL;
		ll_inst->opcode = 0;
		ll_inst->srcA.kind = KIND_EMPTY;
		ll_inst->srcB.kind = KIND_EMPTY;
		ll_inst->dstA.kind = KIND_EMPTY;
		tmp = LLVMInstructionDecodeAsmX86_64(DA, buffer,
			buffer_size, offset,
			ll_inst);
//		TSFlags = LLVMDecodeAsmGetTSFlags(DC2, opcode);
		printf("LLVM DIS2 test_result = 0x%x\n", tmp);
		if (tmp == 1) {
			printf("FAILED TEST 0x%x : ", l);
			test_result[l] = 1;
			for (n = 0; n < buffer_size; n++) {
				printf("%02x ", buffer[n]);
			}
			printf("\n");
		}
		if (!tmp) {
			printf("LLVM DIS2 opcode = 0x%x:%s prec = 0x%x\n\n", ll_inst->opcode, "not yet", ll_inst->predicate);
			tmp = LLVMPrintInstructionDecodeAsmX86_64(DA, ll_inst);
			tmp = convert_ll_inst_to_rtl(self, ll_inst, &dis_instructions);
			if (tmp) {
				printf("Unhandled instruction, not yet implemented convert\n");
				test_result[l] = 1;
			} else {
				for (m = 0; m < dis_instructions.instruction_number; m++) {
					string1.len = 0;
					string1.string[0] = 0;
					tmp = write_inst(self, &string1, &(dis_instructions.instruction[m]), m, NULL);
					tmp = printf("result:    len=%zd:%s\n", string1.len, string1.string);
					if (test_data[l].inst_size == dis_instructions.instruction_number) {
						tmp = printf("test data: len=%zd:%s\n", strlen(test_data[l].inst[m]), test_data[l].inst[m]);
						tmp = strncmp(string1.string, test_data[l].inst[m], string1.len);
						if (tmp) {
							printf("FAILED TEST 0x%x: tmp = 0x%x\n", l, tmp);
							test_result[l] = 1;
						}
					} else {
						printf("FAILED TEST 0x%x: wrong amount of instructions. Expect 0x%x, got 0x%x\n",
							l, test_data[l].inst_size, dis_instructions.instruction_number);
						test_result[l] = 2;
					}
				}
			}	
		}
		printf("END test data 0x%x\n", l);
	
	}

	result_count = 0;
	for (l = 0; l < test_data_no; l++) {
		if (test_result[l]) {
			printf("FAILED TEST 0x%x: result = 0x%x\n", l, test_result[l]);
			result_count++;
		}
	}
	if (!result_count) {
		printf("ALL TESTS PASSED!\n");
	}

	return 0;

}
