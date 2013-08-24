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

 Naming convention taken from Intel Instruction set manual, Appendix A. 25366713.pdf
*/
#include <stdlib.h>
#include <rev.h>
#include "internal.h"

/* Little endian */
uint32_t getbyte(uint8_t *base_address, uint64_t offset) {
	uint32_t result;
	result=base_address[offset];
	debug_print(DEBUG_INPUT_DIS, 1, " 0x%x\n",result);
	return result;
}

uint32_t getword(uint8_t *base_address, uint64_t offset) {
	uint32_t result;
	result=getbyte(base_address, offset);
	offset++;
	result=result | getbyte(base_address, offset) << 8;
	offset++;
	return result;
}

uint32_t getdword(uint8_t *base_address, uint64_t offset) {
	uint32_t result;
	result=getbyte(base_address, offset);
	offset++;
	result=result | getbyte(base_address, offset) << 8;
	offset++;
	result=result | getbyte(base_address, offset) << 16;
	offset++;
	result=result | getbyte(base_address, offset) << 24;
	offset++;
	return result;
}

uint32_t print_reloc_table_entry(struct reloc_table_s *reloc_table_entry) {
	debug_print(DEBUG_INPUT_DIS, 1, "Reloc Type:0x%x\n", reloc_table_entry->type);
	debug_print(DEBUG_INPUT_DIS, 1, "Address:0x%"PRIx64"\n", reloc_table_entry->address);
	debug_print(DEBUG_INPUT_DIS, 1, "Size:0x%"PRIx64"\n", reloc_table_entry->size);
	debug_print(DEBUG_INPUT_DIS, 1, "Value:0x%"PRIx64"\n", reloc_table_entry->value);
	debug_print(DEBUG_INPUT_DIS, 1, "External Function Index:0x%"PRIx64"\n", reloc_table_entry->external_functions_index);
	debug_print(DEBUG_INPUT_DIS, 1, "Section index:0x%"PRIx64"\n", reloc_table_entry->section_index);
	debug_print(DEBUG_INPUT_DIS, 1, "Section name:%s\n", reloc_table_entry->section_name);
	debug_print(DEBUG_INPUT_DIS, 1, "Symbol name:%s\n", reloc_table_entry->symbol_name);
	return 0;
}

/* REX Volume2A Section 2.2.1.2 */
void split_ModRM(uint8_t byte, uint8_t rex, uint8_t *reg,  uint8_t *reg_mem, uint8_t *mod) {
	*reg = (byte >> 3) & 0x7; //bits 3-5
	*reg_mem = (byte & 0x7); //bits 0-2
	/* mod: 00, 01, 10 = various memory addressing modes. */
	/* mod: 11 = register */
	*mod = (byte >> 6); //bit 6-7
	if (rex & 0x4) {
		*reg = *reg | 0x8;
	}
	/* Only is REX.X == 0 */
	if ((rex & 0x3) == 1) {
		*reg_mem = *reg_mem | 0x8;
	}
	debug_print(DEBUG_INPUT_DIS, 1, "byte=%02x, reg=%02x, reg_mem=%02x, mod=%02x\n",
		byte,
		*reg,
		*reg_mem,
		*mod);
	}

/* REX Volume2A Section 2.2.1.2 */
void split_SIB(uint8_t byte, uint8_t rex, uint8_t *mul,  uint8_t *index, uint8_t *base) {
	*index = (byte >> 3) & 0x7; //bits 3-5
	*base = (byte & 0x7); //bits 0-2
	*mul = (byte >> 6); //bit 6-7
	if (rex & 0x2) {
		*index = *index | 0x8;
	}
	if (rex & 0x1) {
		*base = *base | 0x8;
	}

	// do the *2 etc. later
	//  *mul = 1 << *mul; // convert bits to *1, *2, *4, *8
	debug_print(DEBUG_INPUT_DIS, 1, "byte=%02x, mul=%02x, index=%02x, base=%02x\n",
		byte,
		*mul,
		*index,
		*base);
}

