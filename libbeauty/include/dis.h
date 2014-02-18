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


#ifndef DIS_H
#define DIS_H

#include <stdio.h>
#include <inttypes.h>

#define EXTERNAL_ENTRY_POINTS_MAX 1000
#define RELOCATION_SIZE 1000
/* For the .text segment. I.e. Instructions. */
#define MEMORY_TEXT_SIZE 10000
#define MEMORY_STACK_SIZE 10000
#define MEMORY_REG_SIZE 100
/* For the .data segment. I.e. Static data */
#define MEMORY_DATA_SIZE 10000
#define MEMORY_USED_SIZE 10000
#define INST_LOG_ENTRY_SIZE 10000
#define ENTRY_POINTS_SIZE 1000

struct dis_instructions_s {
	int bytes_used;
	uint8_t bytes[16];
	int instruction_number;
	struct instruction_s instruction[10];
} ;

/* Little endian */
extern uint32_t getbyte(uint8_t *base_address, uint64_t offset);

extern uint32_t getdword(uint8_t *base_address, uint64_t offset);

extern int disassemble_amd64(void *handle, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset);
uint32_t print_reloc_table_entry(struct reloc_table_s *reloc_table_entry);

#endif /* DIS_H */
