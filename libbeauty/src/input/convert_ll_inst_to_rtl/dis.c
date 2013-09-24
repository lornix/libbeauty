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
	printf("convert_operand: kind = 0x%x\n", ll_operand->kind);
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
	case KIND_IND_SCALE:
		switch (operand_number) {
		case 0:
		case 2:
		case 4:
			/* REG */
			inst_operand->store = STORE_REG;
			inst_operand->indirect = IND_DIRECT;
			inst_operand->indirect_size = ll_operand->size;
			inst_operand->index = ll_operand->operand[operand_number].value;
			inst_operand->relocated = 0;
			inst_operand->value_size = ll_operand->operand[operand_number].size;
			break;
		case 1:
		case 3:
			/* IMM */
			inst_operand->store = STORE_DIRECT;
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
		// FAILURE EXIT
		printf("FAILED: KIND not recognised\n");
		exit(1);
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
	.operand = {{.value = REG_TMP1, .size = 64, .offset = 0}},
//	.operand.operand[0].size = 64,
//	.operand.operand[0].offset = 0,
};

struct operand_low_level_s operand_reg_tmp2 = {
	.kind = KIND_REG,
	.size = 64,
	.operand = {{.value = REG_TMP2, .size = 64, .offset = 0}},
};


int convert_base(struct instruction_low_level_s *ll_inst, int flags, struct dis_instructions_s *dis_instructions) {
	int tmp;
	struct instruction_s *instruction;
	int n;
	int indirect = 0;
	int srcA_ind = 0;
	int srcB_ind = 0;
	int dstA_ind = 0;
	int result = 0;
	int final_opcode = 0;
	struct operand_low_level_s *previous_operand;
	struct operand_low_level_s operand_imm;
	struct operand_low_level_s *srcA_operand;
	struct operand_low_level_s *srcB_operand;
	struct operand_low_level_s *dstA_operand;
	struct operand_low_level_s *scale_operand;
	struct operand_low_level_s operand_tmp;

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

	previous_operand = &operand_empty;
	srcA_operand = &(ll_inst->srcA);
	srcB_operand = &(ll_inst->srcB);
	dstA_operand = &(ll_inst->dstA);
	previous_operand = &operand_empty;
	/* FIXME: Need to handle special instructions as well */
	if (!indirect) {
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		if ((srcA_operand->kind == KIND_SCALE) &&
			(srcB_operand->kind == KIND_SCALE)) {
			// FAILURE EXIT
			printf("FAILED: Too many KIND_IND_SCALE\n");
			exit(1);
		}
		if (dstA_operand->kind == KIND_SCALE) {
			// FAILURE EXIT
			printf("FAILED: dstA KIND_IND_SCALE\n");
			exit(1);
		}
		if (srcA_operand->kind == KIND_SCALE) {
			scale_operand = srcA_operand;
			// Most likely opcode LEA. Deal with scale, put result in REG_TMP1
			if (scale_operand->operand[2].value == 0) {
				previous_operand = &operand_empty;
			} else if ((scale_operand->operand[2].value != 0) && (scale_operand->operand[1].value == 1)) {
				operand_tmp.kind = KIND_REG;
				operand_tmp.size = 64;
				operand_tmp.operand[0].value = scale_operand->operand[2].value;
				operand_tmp.operand[0].size = scale_operand->operand[2].size;
				operand_tmp.operand[0].offset = scale_operand->operand[2].offset;
				previous_operand = &operand_tmp;
			} else if ((scale_operand->operand[2].value != 0) && (scale_operand->operand[1].value > 1)) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = MUL;
				instruction->flags = 0;
				convert_operand(scale_operand, 2, &(instruction->srcA));
				convert_operand(scale_operand, 1, &(instruction->srcB));
				convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
			}
			if ((scale_operand->operand[3].value > 0) && (previous_operand == &operand_empty)) {
				operand_imm.kind = KIND_IMM;
				operand_imm.size = 64;
				operand_imm.operand[0].value = scale_operand->operand[3].value;
				operand_imm.operand[0].size = scale_operand->operand[3].size;
				operand_imm.operand[0].offset = scale_operand->operand[3].offset;
				previous_operand = &operand_imm;
			} else if ((scale_operand->operand[3].value > 0) && (previous_operand != &operand_empty)) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = ADD;
				instruction->flags = 0;
				convert_operand(previous_operand, 0, &(instruction->srcA));
				convert_operand(scale_operand, 3, &(instruction->srcB));
				convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
			}
			if (previous_operand == &operand_empty) {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = MOV;
				instruction->flags = 0;
				convert_operand(scale_operand, 0, &(instruction->srcA));
				convert_operand(&operand_empty, 0, &(instruction->srcB));
				convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
				dis_instructions->instruction_number++;
				previous_operand = &operand_reg_tmp1;
				srcA_operand = &operand_reg_tmp1;
			} else {
				instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
				instruction->opcode = ADD;
				instruction->flags = 0;
				convert_operand(scale_operand, 0, &(instruction->srcA));
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
		instruction->opcode = final_opcode;
		instruction->flags = flags;
		convert_operand(srcA_operand, 0, &(instruction->srcA));
		convert_operand(srcB_operand, 0, &(instruction->srcB));
		convert_operand(dstA_operand, 0, &(instruction->dstA));
		dis_instructions->instruction_number++;
	} else {
		/* Handle the indirect case */
		if (dstA_operand->kind == KIND_IND_SCALE) {
			scale_operand = dstA_operand;
			/* Let srcA and srcB override this */
		}
		if (srcA_operand->kind == KIND_IND_SCALE) {
			scale_operand = srcA_operand;
		}
		if (srcB_operand->kind == KIND_IND_SCALE) {
			scale_operand = srcB_operand;
		}

		if (scale_operand->operand[2].value == 0) {
			previous_operand = &operand_empty;
		} else if ((scale_operand->operand[2].value != 0) && (scale_operand->operand[1].value == 1)) {
			operand_tmp.kind = KIND_REG;
			operand_tmp.size = 64;
			operand_tmp.operand[0].value = scale_operand->operand[2].value;
			operand_tmp.operand[0].size = scale_operand->operand[2].size;
			operand_tmp.operand[0].offset = scale_operand->operand[2].offset;
			previous_operand = &operand_tmp;
		} else if ((scale_operand->operand[2].value != 0) && (scale_operand->operand[1].value > 1)) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = MUL;
			instruction->flags = 0;
			convert_operand(scale_operand, 2, &(instruction->srcA));
			convert_operand(scale_operand, 1, &(instruction->srcB));
			convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp1;
		}
		if ((scale_operand->operand[3].value > 0) && (previous_operand == &operand_empty)) {
			operand_imm.kind = KIND_IMM;
			operand_imm.size = 64;
			operand_imm.operand[0].value = scale_operand->operand[3].value;
			operand_imm.operand[0].size = scale_operand->operand[3].size;
			operand_imm.operand[0].offset = scale_operand->operand[3].offset;
			previous_operand = &operand_imm;
		} else if ((scale_operand->operand[3].value > 0) && (previous_operand != &operand_empty)) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = ADD;
			instruction->flags = 0;
			convert_operand(previous_operand, 0, &(instruction->srcA));
			convert_operand(scale_operand, 3, &(instruction->srcB));
			convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp1;
		}
		if (previous_operand == &operand_empty) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = MOV;
			instruction->flags = 0;
			convert_operand(scale_operand, 0, &(instruction->srcA));
			convert_operand(&operand_empty, 0, &(instruction->srcB));
			convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp1;
		} else {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = ADD;
			instruction->flags = 0;
			convert_operand(scale_operand, 0, &(instruction->srcA));
			convert_operand(previous_operand, 0, &(instruction->srcB));
			convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
			previous_operand = &operand_reg_tmp1;
		}
		if ((srcA_operand->kind == KIND_IND_SCALE) ||
			(srcB_operand->kind == KIND_IND_SCALE)) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = LOAD;
			instruction->flags = 0;
			convert_operand(previous_operand, 0, &(instruction->srcA));
			instruction->srcA.indirect = IND_MEM;
			convert_operand(&operand_empty, 0, &(instruction->srcB));
			convert_operand(&operand_reg_tmp2, 0, &(instruction->dstA));
			dis_instructions->instruction_number++;
		}
		previous_operand = &operand_reg_tmp2;
		
		if (ll_inst->srcA.kind == KIND_IND_SCALE) {
			srcA_operand = previous_operand;
		}
		if (ll_inst->srcB.kind == KIND_IND_SCALE) {
			srcB_operand = previous_operand;
		}
		instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
		instruction->opcode = ll_inst->opcode;
		instruction->flags = flags;
		convert_operand(srcA_operand, 0, &(instruction->srcA));
		convert_operand(srcB_operand, 0, &(instruction->srcB));
		if (ll_inst->dstA.kind == KIND_IND_SCALE) {
			convert_operand(previous_operand, 0, &(instruction->dstA));
		} else {
			convert_operand(dstA_operand, 0, &(instruction->dstA));
		}
		dis_instructions->instruction_number++;
		if (ll_inst->dstA.kind == KIND_IND_SCALE) {
			instruction = &dis_instructions->instruction[dis_instructions->instruction_number];	
			instruction->opcode = STORE;
			instruction->flags = 0;
			convert_operand(previous_operand, 0, &(instruction->srcA));
			convert_operand(&operand_empty, 0, &(instruction->srcB));
			convert_operand(&operand_reg_tmp1, 0, &(instruction->dstA));
			instruction->dstA.indirect = IND_MEM;
			dis_instructions->instruction_number++;
		}
	}
	result = 0;
	return result;
}

int convert_ll_inst_to_rtl(struct instruction_low_level_s *ll_inst, struct dis_instructions_s *dis_instructions) {
	int tmp;
	//int n;
	int result = 1;
	dis_instructions->instruction_number = 0;

	switch (ll_inst->opcode) {
	case NOP:
		/* Do nothing */
		result = 0;
		break;
	case MOV:
		tmp  = convert_base(ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case LEA: /* Used at the MC Inst low level */
		tmp  = convert_base(ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case JMPT: /* Jump Table */
		break;
	case CALLT: /* Call jump table */
		break;
	case JMP: /* Relative */
		break;
	case CALL: /* non-relative */ 
		break;
	case IF:
		break;
	case IN:
		break;
	case OUT:
		break;
	case ICMP: /* ICMP. Similar to LLVM ICMP */
		break;
	case BC: /* Branch Conditional. Similar to LLVM ICMP */
		break;
	case LOAD: /* Load from memory/stack */
		tmp  = convert_base(ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case STORE: /* Store to memory/stack */
		tmp  = convert_base(ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case SEX: /* Signed Extention */
		tmp  = convert_base(ll_inst, 0, dis_instructions);
		result = tmp;
		break;
	case PHI: /* A PHI point */
		break;
	case RET: /* Special instruction for helping to print the "result local_regNNNN;" */
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case ADD:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case ADC:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SUB:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SBB:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case OR:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case XOR:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case rAND:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case NOT:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case TEST:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case NEG:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case CMP:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case MUL:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case IMUL:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case DIV:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case IDIV:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case ROL:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case ROR:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case RCL:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case RCR:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SHL:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SHR:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SAL:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	case SAR:
		tmp  = convert_base(ll_inst, 1, dis_instructions);
		result = tmp;
		break;
	default:
		debug_print(DEBUG_INPUT_DIS, 1, "convert: Unrecognised opcode %x\n", ll_inst->opcode);
		result = 0;
		break;
	}
	debug_print(DEBUG_INPUT_DIS, 1, "disassemble_amd64:end inst_number = 0x%x\n", dis_instructions->instruction_number);
#if 0
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
#endif
	return result;
}
