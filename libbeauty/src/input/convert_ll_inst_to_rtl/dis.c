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


const char * dis_opcode_table[] = {
	"NOP",   // 0x00
	"MOV",   // 0x01
	"ADD",   // 0x02
	"ADC",   // 0x03
	"SUB",   // 0x04
	"SBB",   // 0x05
	"OR ",   // 0x06
	"XOR",   // 0x07
	"AND",   // 0x08
	"NOT",   // 0x09
	"TEST",  // 0x0A
	"NEG",   // 0x0B
	"CMP",   // 0x0C
	"MUL",   // 0x0D
	"IMUL",  // 0x0E
	"DIV",   // 0x0F
	"IDIV",  // 0x10
	"JMP",   // 0x11
	"CALL",  // 0x12
	"IF ",   // 0x13
	"ROL",   // 0x14  /* ROL,ROR etc. might be reduced to simpler equivalents. */
	"ROR",   // 0x15
	"RCL",   // 0x16
	"RCR",   // 0x17
	"SHL",   // 0x18
	"SHR",   // 0x19
	"SAL",   // 0x1A
	"SAR",   // 0x1B
	"IN ",   // 0x1C
	"OUT",   // 0x1D
	"RET",   // 0x1E
	"SEX",   // 0x1F   /* Signed extension */
	"JMPT",	 // 0x20
	"CALLT",  // 0x21
	"PHI",  // 0x22
	"ICMP",  // 0x23
	"BC",  // 0x24
	"LOAD",  // 0x25
	"STORE",  // 0x26
	"LEA",  // 0x27
	"CMOV",  // 0x28
	"DEC",  // 0x29
	"INC",  // 0x2a
	"POP",  // 0x2b
	"PUSH",  // 0x2c
	""
};




int convert_operand(struct operand_low_level_s *ll_operand, int operand_number, struct operand_s *inst_operand) {
	switch(ll_operand->kind) {
	case KIND_EMPTY:
		inst_operand->store = 0;
		inst_operand->indirect = 0;
		inst_operand->indirect_size = 0;
		inst_operand->index = 0;
		inst_operand->relocated = 0;
		inst_operand->value_size = 0;
		break;
	case KIND_REG:
		inst_operand->store = STORE_REG;
		inst_operand->indirect = IND_DIRECT;
		inst_operand->indirect_size = ll_operand->size;
		inst_operand->index = ll_operand->operand[operand_number].value;
		inst_operand->relocated = 0;
		inst_operand->value_size = ll_operand->operand[operand_number].size;
		break;
	case KIND_IMM:
		inst_operand->store = STORE_DIRECT;
		inst_operand->indirect = IND_DIRECT;
		inst_operand->indirect_size = ll_operand->size;
		inst_operand->index = ll_operand->operand[operand_number].value;
		inst_operand->relocated = 0;
		inst_operand->value_size = ll_operand->operand[operand_number].size;
//		tmp = bf_relocated_code(handle_void, base_address, offset + dis_instructions->bytes_used, 4, &reloc_table_entry);
//		if (!tmp) {
//			inst_operand->relocated = 1;
//			inst_operand->relocated_area = reloc_table_entry->relocated_area;
//			inst_operand->relocated_index = reloc_table_entry->value;
//		}
//		dis_instructions->bytes_used += 1;
		break;
	case KIND_SCALE:
		switch (operand_number) {
		case 0:
		case 2:
		case 4:
			/* IMM */
			inst_operand->store = STORE_DIRECT;
			inst_operand->indirect = IND_DIRECT;
			inst_operand->indirect_size = ll_operand->size;
			inst_operand->index = ll_operand->operand[operand_number].value;
			inst_operand->relocated = 0;
			inst_operand->value_size = ll_operand->operand[operand_number].size;
			break;
		case 1:
		case 3:
			/* REG */
			inst_operand->store = STORE_REG;
			inst_operand->indirect = IND_DIRECT;
			inst_operand->indirect_size = ll_operand->size;
			inst_operand->index = ll_operand->operand[operand_number].value;
			inst_operand->relocated = 0;
			inst_operand->value_size = ll_operand->operand[operand_number].size;
			break;
		default:
			// FAILURE EXIT
			printf("FAILED: KIND_SCALE operand_number out of range\n");
			exit(1);
			break;
		}
		break;
	default:
		break;
	}
	return 0;
}

struct operand_low_level_s operand_empty = {
	.kind = KIND_EMPTY,
};

struct operand_low_level_s operand_reg_tmp1 = {
	.kind = KIND_REG,
	.size = 64,
	.operand = {{.value = REG_TMP1,.size = 64, .offset = 0}},
//	.operand.operand[0].size = 64,
//	.operand.operand[0].offset = 0,
};

struct operand_low_level_s operand_reg_tmp2 = {
	.kind = KIND_REG,
	.size = 64,
	.operand = {{.value = REG_TMP2,.size = 64, .offset = 0}},
};


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
	int final_opcode = 0;
	struct operand_low_level_s *previous_operand;
	struct operand_low_level_s operand_imm;
	struct operand_low_level_s *srcA_operand;

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
	final_opcode = ll_inst->opcode;
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
		struct operand_low_level_s operand_tmp;
		previous_operand = &operand_empty;
		srcA_operand = &(ll_inst->srcA);
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
			// Most likely opcode LEA. Deal with scale, put result in REG_TMP1
			if (ll_inst->srcA.operand[2].value == 0) {
				previous_operand = &operand_empty;
			} else if ((ll_inst->srcA.operand[2].value != 0) && (ll_inst->srcA.operand[1].value == 1)) {
				operand_tmp.kind = KIND_REG;
				operand_tmp.size = 64;
				operand_tmp.operand[0].value = ll_inst->srcA.operand[2].value;
				operand_tmp.operand[0].size = ll_inst->srcA.operand[2].size;
				operand_tmp.operand[0].offset = ll_inst->srcA.operand[2].offset;
				previous_operand = &operand_tmp;
			} else if ((ll_inst->srcA.operand[2].value != 0) && (ll_inst->srcA.operand[1].value > 1)) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = MUL;
				instruction->flags = 0;
				convert_operand(&(ll_inst->srcA), 2, &(instruction->srcA));
				convert_operand(&(ll_inst->srcA), 1, &(instruction->srcB));
				convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
			}
			if ((ll_inst->srcA.operand[3].value > 0) && (previous_operand == &operand_empty)) {
				operand_imm.kind = KIND_IMM;
				operand_imm.size = 64;
				operand_imm.operand[0].value = ll_inst->srcA.operand[3].value;
				operand_imm.operand[0].size = ll_inst->srcA.operand[3].size;
				operand_imm.operand[0].offset = ll_inst->srcA.operand[3].offset;
				previous_operand = &operand_imm;
			} else if ((ll_inst->srcA.operand[3].value > 0) && (previous_operand != &operand_empty)) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = ADD;
				instruction->flags = 0;
				convert_operand(previous_operand, 0, &(instruction->srcA));
				convert_operand(&(ll_inst->srcA), 3, &(instruction->srcB));
				convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
			}
			if (previous_operand == &operand_empty) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = MOV;
				instruction->flags = 0;
				convert_operand(&(ll_inst->srcA), 0, &(instruction->srcA));
				convert_operand(&operand_empty, 0, &(instruction->srcB));
				convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
				srcA_operand = &operand_reg_tmp1;
			} else {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = ADD;
				instruction->flags = 0;
				convert_operand(&(ll_inst->srcA), 0, &(instruction->srcA));
				convert_operand(previous_operand, 0, &(instruction->srcB));
				convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
				srcA_operand = &operand_reg_tmp1;
			}
			final_opcode = MOV;
		}
		if (ll_inst->srcB.kind == KIND_SCALE) {
			// Deal with scale, put result in REG_TMP1
			printf("FAILED: srcB KIND_IND_SCALE\n");
			exit(1);
		}
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = final_opcode;ll_inst->opcode;
		instruction->flags = flags;
		convert_operand(srcA_operand, 0, &(instruction->srcA));
		convert_operand(&(ll_inst->srcB), 0, &(instruction->srcB));
		convert_operand(&(ll_inst->dstA), 0, &(instruction->dstA));
		dis_instructions->instruction_number++;
	} else {
		/* Handle the indirect case */
		dis_instructions->instruction_number = 0; /* Tag unimplemented dis_instructions. */
	}

	debug_print(DEBUG_INPUT_DIS, 1, "disassemble_amd64:end inst_number = 0x%x\n", dis_instructions->instruction_number);
	for (n = 0; n < dis_instructions->instruction_number; n++) {
		instruction = &dis_instructions->instruction[n];
		debug_print(DEBUG_INPUT_DIS, 1, "0x%x: opcode = 0x%x:%s\n",
			n, instruction->opcode, dis_opcode_table[instruction->opcode]);
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
