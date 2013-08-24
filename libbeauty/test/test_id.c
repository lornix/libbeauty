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

#include <rev.h>
#include <bfl.h>

#include <llvm-c-3.2/llvm-c/Disassembler.h>

#define EIP_START 0x40000000

struct dis_instructions_s dis_instructions;
uint8_t *inst;
size_t inst_size = 0;
uint8_t *data;
size_t data_size = 0;
uint8_t *rodata;
size_t rodata_size = 0;
void *handle_void;
char *dis_flags_table[] = { " ", "f" };
uint64_t inst_log = 1;	/* Pointer to the current free instruction log entry. */
struct self_s *self = NULL;

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
	int	opcode;
	int	operands_type;
	int	*operands;
};

#define ADDL 1
#define LEAL 2

struct test_data_s test_data[] = {
	{
		.valid = 1,
		.bytes = {0x01, 0xf8},
		.bytes_size = 2,
		.opcode = ADDL,
		.operands_type = 1,
		.operands = NULL
	},
	{
		.valid = 1,
		.bytes = {0x8d, 0x87, 0x23, 0x01, 0, 0},
		.bytes_size = 6,
		.opcode = LEAL,
		.operands_type = 1,
		.operands = NULL
	}
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

int disassemble(void *handle_void, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset) {
	int tmp;
	tmp = disassemble_amd64(handle_void, dis_instructions, base_address, offset);
	return tmp;
}


int main(int argc, char *argv[])
{
	int n;
	int octets = 0;
	int offset = 0;
	const char *file;
	LLVMDisasmContextRef DC;
	char buffer[1024];

	if (argc != 2) {
		debug_print(DEBUG_MAIN, 1, "Syntax error\n");
		debug_print(DEBUG_MAIN, 1, "Usage: dis64 filename\n");
		debug_print(DEBUG_MAIN, 1, "Where \"filename\" is the input .o file\n");
		exit(1);
	}
	file = argv[1];

	debug_print(DEBUG_MAIN, 1, "Setup ok\n");
	debug_print(DEBUG_MAIN, 1, "size_of test_data = 0x%lx\n", sizeof(test_data));
	debug_print(DEBUG_MAIN, 1, "size_of struct test_data_s = 0x%lx\n", sizeof(struct test_data_s));
	debug_print(DEBUG_MAIN, 1, "number of test_data entries = 0x%lx\n", sizeof(test_data) / sizeof(struct test_data_s));
	debug_print(DEBUG_MAIN, 1, "test_data_no = 0x%lx\n", test_data_no);

	self = malloc(sizeof *self);
	debug_print(DEBUG_MAIN, 1, "sizeof struct self_s = 0x%"PRIx64"\n", sizeof *self);
	/* Open file is only used to enable the disassemler */
//	handle_void = bf_test_open_file(file);
//	debug_print(DEBUG_MAIN, 1, "handle=%p\n", handle_void);
	DC = LLVMCreateDisasm("x86_64-pc-linux-gnu", NULL,
		0, NULL,
		NULL);

	for (n = 0; n < test_data_no; n++) {
		if (!test_data[n].valid) {
			debug_print(DEBUG_MAIN, 1, "Test input data absent\n");
		}

		inst_size = test_data[n].bytes_size;
		inst = &(test_data[n].bytes[0]);
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

		octets = LLVMDisasmInstruction(DC, inst,
			inst_size, offset,
			buffer, 1023);
		debug_print(DEBUG_MAIN, 1, "LLVM DIS octets = 0x%x:%s\n", octets, buffer);
	}

	return 0;

}
