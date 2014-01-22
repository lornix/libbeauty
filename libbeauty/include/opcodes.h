/*
 *  Copyright (C) 2004-2009 The libbeauty Team
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
 */
/* Intel ia32 instruction format: -
 Instruction-Prefixes (Up to four prefixes of 1-byte each. [optional] )
 Opcode (1-, 2-, or 3-byte opcode)
 ModR/M (1 byte [if required] )
 SIB (Scale-Index-Base:1 byte [if required] )
 Displacement (Address displacement of 1, 2, or 4 bytes or none)
 Immediate (Immediate data of 1, 2, or 4 bytes or none)

 Naming convention taked from Intel Instruction set manual, Appendix A. 25366713.pdf
*/

#ifndef __OPCODES__
#define __OPCODES__

/* enums for store_table */
enum {
	STORE_DIRECT,
	STORE_REG,
};

/* enums for indirect_table */
enum {
	IND_DIRECT,
	IND_MEM,
	IND_STACK,
	IND_IO,
};

#define NONE 0x00  /* Used for instructions that are not yet supported */
#define MOV 0x01
#define ADD 0x02
#define ADC 0x03
#define SUB 0x04
#define SBB 0x05
#define OR  0x06
#define XOR 0x07
#define rAND 0x08
#define NOT 0x09
#define TEST 0x0a
#define NEG 0x0b
#define CMP 0x0c
#define MUL 0x0d
#define IMUL 0x0e
#define DIV 0x0f
#define IDIV 0x10
#define JMP 0x11 /* Relative */
#define CALL 0x12 /* non-relative */ 
#define IF  0x13
#define ROL 0x14
#define ROR 0x15
#define RCL 0x16
#define RCR 0x17
#define SHL 0x18
#define SHR 0x19
#define SAL 0x1a
#define SAR 0x1b
#define IN  0x1c
#define OUT 0x1d
#define RET 0x1e /* Special instruction for helping to print the "return local_regNNNN;" */
#define SEX 0x1f /* Signed Extention */
#define JMPT 0x20 /* Jump Table */
#define CALLT 0x21 /* Call jump table */
#define PHI 0x22 /* A PHI point */
#define ICMP 0x23 /* ICMP. Similar to LLVM ICMP */
#define BC 0x24 /* Branch Conditional. Similar to LLVM ICMP */
#define LOAD 0x25 /* Load from memory/stack */
#define STORE 0x26 /* Store to memory/stack */
#define LEA 0x27 /* Used at the MC Inst low level */
#define CMOV 0x28 /* Used at the MC Inst low level */
#define DEC 0x29 /* Used at the MC Inst low level */
#define INC 0x2A /* Used at the MC Inst low level */
#define POP 0x2B /* Used at the MC Inst low level */
#define PUSH 0x2C /* Used at the MC Inst low level */
#define LEAVE 0x2D /* Used at the MC Inst low level */
#define NOP 0x2E /* The NOP instructions */
#define GEP1 0x2F /* Used when raising an ADD of pointers to LLVM IR */
#define CALLM 0x30 /* Call indirect */
#define SETCC 0x31 /* Set conditional */

#define FLAG_NONE 0
#define FLAG_OVERFLOW 1
#define NOT_OVERFLOW 2
#define BELOW 3
#define NOT_BELOW 4
#define EQUAL 5
#define NOT_EQUAL 6
#define BELOW_EQUAL 7
#define ABOVE 8
#define rSIGNED 9
#define NO_SIGNED 10
#define PARITY 11
#define NOT_PARITY 12
#define LESS 13
#define GREATER_EQUAL 14
#define LESS_EQUAL 15
#define GREATER 16

extern const char * opcode_table[];
/* FIXME: The values are currently set to 64bit, so can handle 64bit and 32bit, but not 128bit regs. */
#define REG_AX 0x08
#define REG_CX 0x10
#define REG_DX 0x18
#define REG_BX 0x20
#define REG_SP 0x28
#define REG_BP 0x30
#define REG_SI 0x38
#define REG_DI 0x40
#define REG_IP 0x48
#define REG_08 0x50
#define REG_09 0x58
#define REG_10 0x60
#define REG_11 0x68
#define REG_12 0x70
#define REG_13 0x78
#define REG_14 0x80
#define REG_15 0x88
#define REG_TMP1 0x90
#define REG_TMP2 0x98
#define REG_OVERFLOW 0xa0
#define REG_NOT_OVERFLOW 0xa1
#define REG_BELOW 0xa2
#define REG_NOT_BELOW 0xa3
#define REG_EQUAL 0xa4
#define REG_NOT_EQUAL 0xa5
#define REG_BELOW_EQUAL 0xa6
#define REG_ABOVE 0xa7
#define REG_SIGNED 0xa8
#define REG_NO_SIGNED 0xa9
#define REG_PARITY 0xaa
#define REG_NOT_PARITY 0xab
#define REG_LESS 0xac
#define REG_GREATER_EQUAL 0xad
#define REG_LESS_EQUAL 0xae
#define REG_GREATER 0xaf
#define REG_CS 0xb0
#define MAX_REG 0xb8

typedef struct reg_s reg_t;

struct reg_s {
  uint32_t offset;
  int32_t size;
} ;

extern reg_t reg_table[];

extern int immed_table[];

extern int shift2_table[];
extern int grp3_table[];

extern char *store_table[];
extern char *indirect_table[];

/*
ia32 registers will have their own memory space in the emulator.
All little endian.



Flags= 0x0,4 (offset, length in bytes) (not sure how to handle flags yet.)
eAX = 0x04,4
eCX = 0x08,4
eDX = 0x0c,4
eBX = 0x10,4
eSP = 0x14,4
eBP = 0x18,4
eSI = 0x1c,4
eDI = 0x20,4
eIP = 0x24,4
TMP1 = 0x28,4 (Used to convert an ia32 instruction into multiple RTL instructions.)
TMP2 = 0x2c,4 (Used to convert an ia32 instruction into multiple RTL instructions.)

AX = 0x04,2
CX = 0x08,2
DX = 0x0c,2
BX = 0x10,2
SP = 0x14,2
BP = 0x18,2
SI = 0x1c,2
DI = 0x20,2

AL = 0x04,1
CL = 0x08,1
DL = 0x0c,1
BL = 0x10,1

AH = 0x05,1
CH = 0x09,1
DH = 0x0d,1
BH = 0x11,1

*/

#endif /* __OPCODES__ */
