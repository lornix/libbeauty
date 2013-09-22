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
#include <instruction_low_level.h>

int convert_operand(struct operand_low_level_s *ll_operand, struct operand_s *inst_operand) {
	switch(ll_operand->kind) {
	case KIND_REG:
		inst_operand->store = STORE_REG;
		inst_operand->indirect = IND_DIRECT;
		inst_operand->indirect_size = ll_operand->size;
		inst_operand->index = ll_operand->operand[0].value;
		inst_operand->relocated = 0;
		inst_operand->value_size = ll_operand->operand[0].size;
		break;
	case KIND_IMM:
		inst_operand->store = STORE_DIRECT;
		inst_operand->indirect = IND_DIRECT;
		inst_operand->indirect_size = ll_operand->size;
		inst_operand->index = ll_operand->operand[0].value;
		inst_operand->relocated = 0;
		inst_operand->value_size = ll_operand->operand[0].size;
//		tmp = bf_relocated_code(handle_void, base_address, offset + dis_instructions->bytes_used, 4, &reloc_table_entry);
//		if (!tmp) {
//			inst_operand->relocated = 1;
//			inst_operand->relocated_area = reloc_table_entry->relocated_area;
//			inst_operand->relocated_index = reloc_table_entry->value;
//		}
//		dis_instructions->bytes_used += 1;
		break;
	case KIND_SCALE:
		inst_operand->store = STORE_REG;
		inst_operand->indirect = IND_DIRECT;
		inst_operand->indirect_size = ll_operand->size;
		inst_operand->index = REG_TMP1;
		inst_operand->relocated = 0;
		inst_operand->value_size = ll_operand->size;
		break;
	default:
		break;
	}
	return 0;
}

int convert_ll_inst_to_rtl(struct instruction_low_level_s *ll_inst, struct dis_instructions_s *dis_instructions) {
	int tmp;
	struct instruction_s *instruction;
	int n;
	int indirect = 0;
	int kind;
	int srcA_ind = 0;
	int srcB_ind = 0;
	int dstA_ind = 0;
	int flags = 0;
	int result = 0;

	dis_instructions->instruction_number = 0;
	debug_print(DEBUG_INPUT_DIS, 1, "disassemble_amd64:start inst_number = 0x%x\n", dis_instructions->instruction_number);
	dis_instructions->instruction[dis_instructions->instruction_number].opcode = NOP; /* Un-supported OPCODE */
	dis_instructions->instruction[dis_instructions->instruction_number].flags = 0; /* No flags effected */
	if ((ll_inst->srcA.kind == KIND_IND_REG) || 	
		(ll_inst->srcA.kind == KIND_IND_IMM) || 	
		(ll_inst->srcA.kind == KIND_IND_SCALE))
		srcA_ind = 1;
	if ((ll_inst->srcB.kind == KIND_IND_REG) || 	
		(ll_inst->srcB.kind == KIND_IND_IMM) || 	
		(ll_inst->srcB.kind == KIND_IND_SCALE))
		srcB_ind = 1;
	if ((ll_inst->dstA.kind == KIND_IND_REG) || 	
		(ll_inst->dstA.kind == KIND_IND_IMM) || 	
		(ll_inst->dstA.kind == KIND_IND_SCALE))
		dstA_ind = 1;
	if (srcA_ind || srcB_ind || dstA_ind) 
		indirect = 1;

	switch (ll_inst->opcode) {
	case NOP:
	case MOV:
	case LEA: /* Used at the MC Inst low level */
	case JMPT: /* Jump Table */
	case CALLT: /* Call jump table */
	case JMP: /* Relative */
	case CALL: /* non-relative */ 
	case IF:
	case IN:
	case OUT:
	case ICMP: /* ICMP. Similar to LLVM ICMP */
	case BC: /* Branch Conditional. Similar to LLVM ICMP */
	case LOAD: /* Load from memory/stack */
	case STORE: /* Store to memory/stack */
	case SEX: /* Signed Extention */
	case PHI: /* A PHI point */
	case RET: /* Special instruction for helping to print the "return local_regNNNN;" */
		flags = 0;
		break;
	case ADD:
	case ADC:
	case SUB:
	case SBB:
	case OR:
	case XOR:
	case rAND:
	case NOT:
	case TEST:
	case NEG:
	case CMP:
	case MUL:
	case IMUL:
	case DIV:
	case IDIV:
	case ROL:
	case ROR:
	case RCL:
	case RCR:
	case SHL:
	case SHR:
	case SAL:
	case SAR:
		/* Affects flags */
		flags = 1;
		break;
	}
	/* FIXME: Need to handle special instructions as well */
	if (!indirect) {
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		if ((ll_inst->srcA.kind == KIND_SCALE) &&
			(ll_inst->srcB.kind == KIND_SCALE)) {
			// FAILURE EXIT
			printf("FAILED: Too many KIND_IND_SCALE\n");
			exit(1);
		}
		if (ll_inst->dstA.kind == KIND_SCALE) {
			// FAILURE EXIT
			printf("FAILED: dstA KIND_IND_SCALE\n");
			exit(1);
		}
		if (ll_inst->srcA.kind == KIND_SCALE) {
			// Deal with scale, put result in REG_TMP1
		}
		if (ll_inst->srcB.kind == KIND_SCALE) {
			// Deal with scale, put result in REG_TMP1
		}
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = ll_inst->opcode;
		instruction->flags = flags;
		convert_operand(&(ll_inst->srcA),&(instruction->srcA));
		convert_operand(&(ll_inst->srcB),&(instruction->srcB));
		convert_operand(&(ll_inst->dstA),&(instruction->dstA));
		dis_instructions->instruction_number++;
	} else {
		dis_instructions->instruction_number = 0; /* Tag unimplemented dis_instructions. */
	}

	debug_print(DEBUG_INPUT_DIS, 1, "disassemble_amd64:end inst_number = 0x%x\n", dis_instructions->instruction_number);
	for (n = 0; n < dis_instructions->instruction_number; n++) {
		instruction = &dis_instructions->instruction[n];
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: flags = 0x%x\n", n, instruction->flags);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.store = 0x%x\n", n, instruction->srcA.store);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.indirect = 0x%x\n", n, instruction->srcA.indirect);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.indirect_size = 0x%x\n", n, instruction->srcA.indirect_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.index = 0x%"PRIx64"\n", n, instruction->srcA.index);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.relocated = 0x%x\n", n, instruction->srcA.relocated);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcA.value_size = 0x%x\n", n, instruction->srcA.value_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.store = 0x%x\n", n, instruction->srcB.store);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.indirect = 0x%x\n", n, instruction->srcB.indirect);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.indirect_size = 0x%x\n", n, instruction->srcB.indirect_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.index = 0x%"PRIx64"\n", n, instruction->srcB.index);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.relocated = 0x%x\n", n, instruction->srcB.relocated);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: srcB.value_size = 0x%x\n", n, instruction->srcB.value_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.store = 0x%x\n", n, instruction->dstA.store);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.indirect = 0x%x\n", n, instruction->dstA.indirect);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.indirect_size = 0x%x\n", n, instruction->dstA.indirect_size);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.store = 0x%x\n", n, instruction->dstA.store);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.index = 0x%"PRIx64"\n", n, instruction->dstA.index);
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: dstA.value_size = 0x%x\n", n, instruction->dstA.value_size);
	}
	return result;
}
