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

#define DEBUG_MAIN 1
#define DEBUG_INPUT_BFD 2
#define DEBUG_INPUT_DIS 3
#define DEBUG_OUTPUT 4
#define DEBUG_EXE 5
#define DEBUG_ANALYSE 6
#define DEBUG_ANALYSE_PATHS 7
#define DEBUG_ANALYSE_PHI 8

/* debug: 0 = no debug output. >= 1 is more debug output */
int debug_dis64 = 1;
int debug_input_bfd = 1;
int debug_input_dis = 1;
int debug_exe = 1;
int debug_analyse = 1;
int debug_analyse_paths = 1;
int debug_analyse_phi = 1;
int debug_output = 1;

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
		.inst[0] = "// 0x0000:ADD  r0x40/64, i0x123/64, r0x90/64",
		.inst[1] = "// 0x0001:MOV  r0x90/64, r0x8/32",
		.inst_size = 2,
	},
	{
		.valid = 1,
		// movzbl  -96(%rbp), %esi
		.bytes = {0x0f, 0xb6, 0x75, 0xa0},
		.bytes_size = 6,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x60/64, r0x90/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x90]/8, r0x98/8",
		.inst[2] = "// 0x0002:MOV  r0x98/8, r0x38/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// movzbl  1061(%rbx), %edx
		.bytes = {0x0f, 0xb6, 0x93, 0x25, 0x04, 0x00, 0x00},
		.bytes_size = 7,
		.inst[0] = "// 0x0000:ADD  r0x20/64, i0x425/64, r0x90/64",
		.inst[1] = "// 0x0001:LOAD  m[r0x90]/8, r0x98/8",
		.inst[2] = "// 0x0002:MOV  r0x98/8, r0x18/32",
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
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x68/64, r0x90/64",
		.inst[1] = "// 0x0001:MOV  i0xffffffa1/32, r0x98/32",
		.inst[2] = "// 0x0002:STORE  r0x98/32, r0x90/64, s[r0x90]/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// movb    $12, 1046(%r12)
		.bytes = {0x41, 0xc6, 0x84, 0x24, 0x16, 0x04, 0x00, 0x00, 0x0c},
		.bytes_size = 9,
		.inst[0] = "// 0x0000:ADD  r0x70/64, i0x416/64, r0x90/64",
		.inst[1] = "// 0x0001:MOV  i0xc/8, r0x98/8",
		.inst[2] = "// 0x0002:STORE  r0x98/8, r0x90/64, m[r0x90]/8",
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
		.inst[0] = "// 0x0000:SEX  r0x38/32, i0x0/0, r0x38/64",
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
		.inst[0] = "// 0x0000:ADD  r0x40/64, i0x60/64, r0x90/64",
		.inst[1] = "// 0x0001:LOAD  m[r0x90]/64, r0x98/64",
		.inst[2] = "// 0x0002:ADDf r0x38/64, r0x98/64, r0x38/64",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// mov    (%rsi),%eax
		.bytes = {0x8b, 0x06},
		.bytes_size = 2,
		.inst[0] = "// 0x0000:MOV  r0x38/64, r0x90/64",
		.inst[1] = "// 0x0001:LOAD  m[r0x90]/32, r0x98/32",
		.inst[2] = "// 0x0002:MOV  r0x98/32, r0x8/32",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// leaveq
		.bytes = {0xc9},
		.bytes_size = 1,
		.inst[0] = "// 0x0000:MOV  r0x30/64, r0x28/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x28]/64, r0x30/64",
		.inst[2] = "// 0x0002:ADD  r0x28/64, i0x8/64, r0x28/64",
		.inst_size = 3,
	},
	{
		.valid = 1,
		// retq
		.bytes = {0xc3},
		.bytes_size = 1,
		.inst[0] = "// 0x0000:LOAD  s[r0x28]/64, r0x90/64",
		.inst[1] = "// 0x0001:ADD  r0x28/64, i0x8/64, r0x28/64",
		.inst[2] = "// 0x0002:NOP ",
		.inst[3] = "// 0x0003:MOV  r0x90/64, r0x48/64",
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
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x8/64, r0x90/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x90]/32, r0x98/32",
		.inst[2] = "// 0x0002:SUBf r0x98/32, i0x1/32, r0x98/32",
		.inst[3] = "// 0x0003:STORE  r0x98/32, r0x90/64, s[r0x90]/32",
		.inst_size = 4,
	},
	{
		.valid = 1,
		// addl   $0x1,-0x4(%rbp)
		.bytes = {0x83, 0x45, 0xfc, 0x01},
		.bytes_size = 4,
		.inst[0] = "// 0x0000:SUB  r0x30/64, i0x4/64, r0x90/64",
		.inst[1] = "// 0x0001:LOAD  s[r0x90]/32, r0x98/32",
		.inst[2] = "// 0x0002:ADDf r0x98/32, i0x1/32, r0x98/32",
		.inst[3] = "// 0x0003:STORE  r0x98/32, r0x90/64, s[r0x90]/32",
		.inst_size = 4,
	},
};

#define test_data_no sizeof(test_data) / sizeof(struct test_data_s)

void debug_print(int module, int level, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	switch (module) {
	case DEBUG_MAIN:
		if (level <= debug_dis64) {
			fprintf(stderr, "DEBUG_MAIN,0x%x:", level);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_INPUT_BFD:
		if (level <= debug_input_bfd) {
			fprintf(stderr, "DEBUG_INPUT_BFD,0x%x:", level);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_INPUT_DIS:
		if (level <= debug_input_dis) {
			fprintf(stderr, "DEBUG_INPUT_DIS,0x%x:", level);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_EXE:
		if (level <= debug_exe) {
			fprintf(stderr, "DEBUG_EXE,0x%x:", level);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_ANALYSE:
		if (level <= debug_analyse) {
			fprintf(stderr, "DEBUG_ANALYSE,0x%x:", level);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_ANALYSE_PATHS:
		if (level <= debug_analyse_paths) {
			fprintf(stderr, "DEBUG_ANALYSE_PATHS,0x%x:", level);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_ANALYSE_PHI:
		if (level <= debug_analyse_phi) {
			fprintf(stderr, "DEBUG_ANALYSE_PHI,0x%x:", level);
			vfprintf(stderr, format, ap);
		}
		break;
	case DEBUG_OUTPUT:
		if (level <= debug_output) {
			fprintf(stderr, "DEBUG_OUTPUT,0x%x:", level);
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
	tmp = LLVMSetupDecodeAsmX86_64(DA);
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

	self = malloc(sizeof *self);
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
		printf("LLVM DIS2 test_result = 0x%x:", tmp);
		if (tmp == 1) {
			printf("TEST 0x%x FAILED AT: ", l);
			for (n = 0; n < buffer_size; n++) {
				printf("%02x ", buffer[n]);
			}
			printf("\n");
		}
		if (!tmp) {
			printf("LLVM DIS2 opcode = 0x%x:%s prec = 0x%x\n\n", ll_inst->opcode, "not yet", ll_inst->predicate);
			tmp = LLVMPrintInstructionDecodeAsmX86_64(DA, ll_inst);
			tmp = convert_ll_inst_to_rtl(ll_inst, &dis_instructions);
			if (tmp) {
				printf("Unhandled instruction, not yet implemented convert\n");
			}
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
					printf("FAILED TEST 0x%x: wrong amount of instructions\n", l);
					test_result[l] = 2;
				}

			}
		}
		printf("END test data 0x%x\n", l);
	
	}
	
	for (l = 0; l < test_data_no; l++) {
		if (test_result[l]) {
			printf("FAILED TEST 0x%x: result = 0x%x\n", l, test_result[l]);
		}
	}

	return 0;

}
