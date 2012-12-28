/*
 *  Copyright (C) 2012  The libbeauty Team
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
 * 06-05-2012 Initial work.
 *   Copyright (C) 2012 James Courtier-Dutton James@superbug.co.uk
 */

#include <stdio.h>
#include <rev.h>

extern int reg_params_order[];

const char *condition_table[] = {
	"OVERFLOW_0", /* Signed */
	"NOT_OVERFLOW_1", /* Signed */
	"BELOW_2",	/* Unsigned */
	"NOT_BELOW_3",	/* Unsigned */
	"EQUAL_4",	/* Signed or Unsigned */
	"NOT_EQUAL_5",	/* Signed or Unsigned */
	"BELOW_EQUAL_6",	/* Unsigned */
	"ABOVE_7",	/* Unsigned */
	"SIGNED_8",	/* Signed */
	"NO_SIGNED_9",	/* Signed */
	"PARITY_10",	/* Signed or Unsigned */
	"NOT_PARITY_11",/* Signed or Unsigned */
	"LESS_12",	/* Signed */
	"GREATER_EQUAL_13", /* Signed */
	"LESS_EQUAL_14",    /* Signed */
	"GREATER_15"	/* Signed */
};

int output_label(struct label_s *label, FILE *fd) {
	int tmp;

	switch (label->scope) {
	case 3:
		printf("%"PRIx64";\n", label->value);
		/* FIXME: Handle the case of an immediate value being &data */
		/* but it is very difficult to know if the value is a pointer (&data) */
		/* or an offset (data[x]) */
		/* need to use the relocation table to find out */
		/* no relocation table entry == offset */
		/* relocation table entry == pointer */
		/* this info should be gathered at disassembly point */
		switch (label->type) {
		case 1:
			tmp = fprintf(fd, "data%04"PRIx64,
				label->value);
			break;
		case 2:
			tmp = fprintf(fd, "&data%04"PRIx64,
				label->value);
			break;
		case 3:
			tmp = fprintf(fd, "0x%"PRIx64,
				label->value);
			break;
		default:
			printf("output_label error\n");
			return 1;
			break;
		}
		break;
	case 2:
		switch (label->type) {
		case 2:
			printf("param_stack%04"PRIx64,
				label->value);
			tmp = fprintf(fd, "param_stack%04"PRIx64,
				label->value);
			break;
		case 1:
			printf("param_reg%04"PRIx64,
				label->value);
			tmp = fprintf(fd, "param_reg%04"PRIx64,
				label->value);
			break;
		default:
			printf("output_label error\n");
			return 1;
			break;
		}
		break;
	case 1:
		switch (label->type) {
		case 2:
			printf("local_stack%04"PRIx64,
				label->value);
			tmp = fprintf(fd, "local_stack%04"PRIx64,
				label->value);
			break;
		case 1:
			printf("local_reg%04"PRIx64,
				label->value);
			tmp = fprintf(fd, "local_reg%04"PRIx64,
				label->value);
			break;
		default:
			printf("output_label error type=%"PRIx64"\n", label->type);
			return 1;
			break;
		}
		break;
	case 4:
		/* FIXME: introduce indirect_value_id and indirect_value_scope */
		/* in order to resolve somewhere */
		/* It will always be a register, and therefore can re-use the */
		/* value_id to identify it. */
		/* It will always be a local and not a param */
		/* FIXME: local_reg should be handled in case 1.1 above and
		 *        not be a separate label
		 */
		printf("xxxlocal_reg%04"PRIx64";\n", label->value);
		tmp = fprintf(fd, "xxxlocal_reg%04"PRIx64,
			label->value);
		break;
	default:
		printf("unknown label scope: %04"PRIx64";\n", label->scope);
		tmp = fprintf(fd, "unknown%04"PRIx64,
			label->scope);
		break;
	}
	return 0;
}

int output_label_redirect(int offset, struct label_s *labels, struct label_redirect_s *label_redirect, FILE *fd) {
	int tmp;
	struct label_s *label;

	tmp = label_redirect[offset].redirect;
	label = &labels[tmp];
	tmp = output_label(label, fd);
	return 0;
}

int output_variable(int store, int indirect, uint64_t index, uint64_t relocated, uint64_t value_scope, uint64_t value_id, uint64_t indirect_offset_value, uint64_t indirect_value_id, FILE *fd) {
	int tmp;
	/* FIXME: May handle by using first switch as switch (indirect) */
	switch (store) {
	case STORE_DIRECT:
		printf("%"PRIx64";\n", index);
		/* FIXME: Handle the case of an immediate value being &data */
		/* but it is very difficult to know if the value is a pointer (&data) */
		/* or an offset (data[x]) */
		/* need to use the relocation table to find out */
		/* no relocation table entry == offset */
		/* relocation table entry == pointer */
		/* this info should be gathered at disassembly point */
		if (indirect == IND_MEM) {
			tmp = fprintf(fd, "data%04"PRIx64,
				index);
		} else if (relocated) {
			tmp = fprintf(fd, "&data%04"PRIx64,
				index);
		} else {
			tmp = fprintf(fd, "0x%"PRIx64,
				index);
		}
		break;
	case STORE_REG:
		switch (value_scope) {
		case 1:
			/* FIXME: Should this be param or instead param_reg, param_stack */
			if (IND_STACK == indirect) {
				printf("param_stack%04"PRIx64",%04"PRIx64",%04d",
					index, indirect_offset_value, indirect);
				tmp = fprintf(fd, "param_stack%04"PRIx64",%04"PRIx64",%04d",
					index, indirect_offset_value, indirect);
			} else if (0 == indirect) {
				printf("param_reg%04"PRIx64,
					index);
				tmp = fprintf(fd, "param_reg%04"PRIx64,
					index);
			}
			break;
		case 2:
			/* FIXME: Should this be local or instead local_reg, local_stack */
			if (IND_STACK == indirect) {
				printf("local_stack%04"PRIx64,
					value_id);
				tmp = fprintf(fd, "local_stack%04"PRIx64,
					value_id);
			} else if (0 == indirect) {
				printf("local_reg%04"PRIx64,
					value_id);
				tmp = fprintf(fd, "local_reg%04"PRIx64,
					value_id);
			}
			break;
		case 3: /* Data */
			/* FIXME: introduce indirect_value_id and indirect_value_scope */
			/* in order to resolve somewhere */
			/* It will always be a register, and therefore can re-use the */
			/* value_id to identify it. */
			/* It will always be a local and not a param */
			printf("xxxlocal_mem%04"PRIx64";\n", (indirect_value_id));
			tmp = fprintf(fd, "xxxlocal_mem%04"PRIx64,
				indirect_value_id);
			break;
		default:
			printf("unknown value scope: %04"PRIx64";\n", (value_scope));
			tmp = fprintf(fd, "unknown%04"PRIx64,
				value_scope);
			break;
		}
		break;
	default:
		printf("Unhandled store1\n");
		break;
	}
	return 0;
}

int if_expression( int condition, struct inst_log_entry_s *inst_log1_flagged,
	struct label_redirect_s *label_redirect, struct label_s *labels, FILE *fd)
{
	int opcode;
	int err = 0;
	int tmp;
	//int store;
	//int indirect;
	//uint64_t index;
	//uint64_t relocated;
	//uint64_t value_scope;
	uint64_t value_id;
	//uint64_t indirect_offset_value;
	//uint64_t indirect_value_id;
	struct label_s *label;
	const char *condition_string;

	opcode = inst_log1_flagged->instruction.opcode;
	printf("\t if opcode=0x%x, ",inst_log1_flagged->instruction.opcode);

	switch (opcode) {
	case CMP:
		switch (condition) {
		case LESS_EQUAL:
		case BELOW_EQUAL:   /* Unsigned */
			condition_string = " <= ";
			break;
		case GREATER_EQUAL: /* Signed */
		case NOT_BELOW:   /* Unsigned */
			condition_string = " >= ";
			break;
		case GREATER:
		case ABOVE:
			condition_string = " > ";
			break;
		case BELOW:
		case LESS:
			condition_string = " < ";
			break;
		case NOT_EQUAL:
			condition_string = " != ";
			break;
		case EQUAL:
			condition_string = " == ";
			break;
		default:
			printf("if_expression: non-yet-handled: 0x%x\n", condition);
			err = 1;
			break;
		}
		if (err) break;
		tmp = fprintf(fd, "(");
		if (IND_MEM == inst_log1_flagged->instruction.dstA.indirect) {
			tmp = fprintf(fd, "*");
			value_id = inst_log1_flagged->value2.indirect_value_id;
		} else {
			value_id = inst_log1_flagged->value2.value_id;
		}
		if (STORE_DIRECT == inst_log1_flagged->instruction.dstA.store) {
			tmp = fprintf(fd, "0x%"PRIx64, inst_log1_flagged->instruction.dstA.index);
		} else {
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
		}
		tmp = fprintf(fd, "%s", condition_string);
		if (IND_MEM == inst_log1_flagged->instruction.srcA.indirect) {
			tmp = fprintf(fd, "*");
			value_id = inst_log1_flagged->value1.indirect_value_id;
		} else {
			value_id = inst_log1_flagged->value1.value_id;
		}
		tmp = label_redirect[value_id].redirect;
		label = &labels[tmp];
		//tmp = fprintf(fd, "0x%x:", tmp);
		tmp = output_label(label, fd);
		tmp = fprintf(fd, ") ");
		break;
	case SUB:
	case ADD:
		switch (condition) {
		case EQUAL:
			condition_string = " == 0";
			break;
		case NOT_EQUAL:
			condition_string = " != 0";
			break;
		default:
			printf("if_expression: non-yet-handled: 0x%x\n", condition);
			err = 1;
			break;
		}

		if ((!err) && (IND_DIRECT == inst_log1_flagged->instruction.srcA.indirect) &&
			(IND_DIRECT == inst_log1_flagged->instruction.dstA.indirect) &&
			(0 == inst_log1_flagged->value3.offset_value)) {
			tmp = fprintf(fd, "((");
			if (1 == inst_log1_flagged->instruction.dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1_flagged->value2.indirect_value_id;
			} else {
				value_id = inst_log1_flagged->value2.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			tmp = fprintf(fd, "%s) ", condition_string);
		}
		break;

	case TEST:
		switch (condition) {
		case EQUAL:
			condition_string = " == 0";
			break;
		case NOT_EQUAL:
			condition_string = " != 0";
			break;
		case LESS_EQUAL:
			condition_string = " <= 0";
			break;
		default:
			printf("if_expression: non-yet-handled: 0x%x\n", condition);
			err = 1;
			break;
		}

		if ((!err) && (IND_DIRECT == inst_log1_flagged->instruction.srcA.indirect) &&
			(IND_DIRECT == inst_log1_flagged->instruction.dstA.indirect) &&
			(0 == inst_log1_flagged->value3.offset_value)) {
			tmp = fprintf(fd, "((");
			if (1 == inst_log1_flagged->instruction.dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1_flagged->value2.indirect_value_id;
			} else {
				value_id = inst_log1_flagged->value2.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			tmp = fprintf(fd, " AND ");
			if (1 == inst_log1_flagged->instruction.srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1_flagged->value1.indirect_value_id;
			} else {
				value_id = inst_log1_flagged->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			tmp = fprintf(fd, ")%s) ", condition_string);
		}
		break;

	case rAND:
		switch (condition) {
		case EQUAL:
			condition_string = " == 0";
			break;
		case NOT_EQUAL:
			condition_string = " != 0";
			break;
		default:
			printf("if_expression: non-yet-handled: 0x%x\n", condition);
			err = 1;
			break;
		}

		if ((!err) && (IND_DIRECT == inst_log1_flagged->instruction.srcA.indirect) &&
			(IND_DIRECT == inst_log1_flagged->instruction.dstA.indirect) &&
			(0 == inst_log1_flagged->value3.offset_value)) {
			tmp = fprintf(fd, "((");
			if (1 == inst_log1_flagged->instruction.dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1_flagged->value2.indirect_value_id;
			} else {
				value_id = inst_log1_flagged->value2.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			tmp = fprintf(fd, " AND ");
			if (1 == inst_log1_flagged->instruction.srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1_flagged->value1.indirect_value_id;
			} else {
				value_id = inst_log1_flagged->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			tmp = fprintf(fd, ")%s) ", condition_string);
		}
		break;

	default:
		printf("if_expression: Previous flags instruction not handled: opcode = 0x%x, cond = 0x%x\n", opcode, condition);
		err = 1;
		break;
	}
	return err;
}

/* If relocated_data returns 1, it means that there was a
 * relocation table entry for this data location.
 * This most likely means that this is a pointer.
 * FIXME: What to do if the relocation is to the code segment? Pointer to function?
 */
uint32_t relocated_data(struct rev_eng *handle, uint64_t offset, uint64_t size)
{
	int n;
	for (n = 0; n < handle->reloc_table_data_sz; n++) {
		if (handle->reloc_table_data[n].address == offset) {
			return 1;
		}
	}
	return 0;
}


uint32_t output_function_name(FILE *fd,
		struct external_entry_point_s *external_entry_point)
{
	int tmp;

	printf("int %s()\n{\n", external_entry_point->name);
	printf("value = %"PRIx64"\n", external_entry_point->value);
	tmp = fprintf(fd, "int %s(", external_entry_point->name);
	return 0;
}

int output_inst_in_c(struct self_s *self, struct process_state_s *process_state,
			 FILE *fd, int inst_number, struct label_redirect_s *label_redirect, struct label_s *labels, const char *cr)
{
	int tmp, l, n2;
	int tmp_state;
	int err;
	int found;
	uint64_t value_id;
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1 = NULL;
	struct inst_log_entry_s *inst_log1_prev;
	struct inst_log_entry_s *inst_log1_flags;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct label_s *label;

	inst_log1 =  &inst_log_entry[inst_number];
	if (!inst_log1) {
		printf("output_function_body:Invalid inst_log1[0x%x]\n", inst_number);
		return 1;
	}
	inst_log1_prev =  &inst_log_entry[inst_log1->prev[0]];
	if (!inst_log1_prev) {
		printf("output_function_body:Invalid inst_log1_prev[0x%x]\n", inst_number);
		return 1;
	}
	instruction =  &inst_log1->instruction;
	//instruction_prev =  &inst_log1_prev->instruction;

	write_inst(self, fd, instruction, inst_number, labels);
	tmp = fprintf(fd, "%s", cr);

	tmp = fprintf(fd, "// ");
	if (inst_log1->prev_size > 0) {
		tmp = fprintf(fd, "prev_size=0x%x: ",
			inst_log1->prev_size);
		for (l = 0; l < inst_log1->prev_size; l++) {
			tmp = fprintf(fd, "prev=0x%x, ",
			inst_log1->prev[l]);
		}
	}
	if (inst_log1->next_size > 0) {
		tmp = fprintf(fd, "next_size=0x%x: ",
			inst_log1->next_size);
		for (l = 0; l < inst_log1->next_size; l++) {
			tmp = fprintf(fd, "next=0x%x, ",
			inst_log1->next[l]);
		}
	}
	tmp = fprintf(fd, "\n");
	/* Output labels when this is a join point */
	/* or when the previous instruction was some sort of jump */
	if ((inst_log1->prev_size) > 1) {
		printf("label%04"PRIx32":\n", inst_number);
		tmp = fprintf(fd, "label%04"PRIx32":\n", inst_number);
	} else {
		if ((inst_log1->prev[0] != (inst_number - 1)) &&
			(inst_log1->prev[0] != 0)) {
			printf("label%04"PRIx32":\n", inst_number);
			tmp = fprintf(fd, "label%04"PRIx32":\n", inst_number);
		}
	}
	printf("\n");
	/* Test to see if we have an instruction to output */
	printf("Inst 0x%04x: %d: value_type = %d, %d, %d\n", inst_number,
		instruction->opcode,
		inst_log1->value1.value_type,
		inst_log1->value2.value_type,
		inst_log1->value3.value_type);
	/* FIXME: JCD: This fails for some call instructions */
	if ((0 == inst_log1->value3.value_type) ||
		(1 == inst_log1->value3.value_type) ||
		(2 == inst_log1->value3.value_type) ||
		(3 == inst_log1->value3.value_type) ||
		(4 == inst_log1->value3.value_type) ||
		(6 == inst_log1->value3.value_type) ||
		(5 == inst_log1->value3.value_type)) {
		switch (instruction->opcode) {
		case MOV:
		case SEX:
			if (inst_log1->value1.value_type == 6) {
				printf("ERROR1 %d\n", instruction->opcode);
				//break;
			}
			if (inst_log1->value1.value_type == 5) {
				printf("ERROR2\n");
				//break;
			}
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			/* FIXME: Check limits */
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " = ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";%s",cr);

			break;
		case NEG:
			if (inst_log1->value1.value_type == 6) {
				printf("ERROR1\n");
				//break;
			}
			if (inst_log1->value1.value_type == 5) {
				printf("ERROR2\n");
				//break;
			}
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			/* FIXME: Check limits */
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " = -");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");

			break;

		case ADD:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " += ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case MUL:
		case IMUL:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " *= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case SUB:
		case SBB:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "//\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " \\-= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";%s", cr);
			break;
		case rAND:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " &= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case OR:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " |= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case XOR:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " ^= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case NOT:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " = !");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case SHL: //TODO: UNSIGNED
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " <<= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case SHR: //TODO: UNSIGNED
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " >>= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case SAL: //TODO: SIGNED
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " <<= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case SAR: //TODO: SIGNED
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " >>= ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case JMP:
			printf("JMP reached XXXX\n");
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			tmp = fprintf(fd, "\t");

//			if (instruction->srcA.relocated) {
//				printf("JMP goto rel%08"PRIx64";\n", instruction->srcA.index);
//				tmp = fprintf(fd, "JMP goto rel%08"PRIx64";\n",
//					instruction->srcA.index);
//			} else {
				printf("JMP2 goto label%04"PRIx32";\n",
					inst_log1->next[0]);
				tmp = fprintf(fd, "JMP2 goto label%04"PRIx32";\n",
					inst_log1->next[0]);
//			}
			break;
		case JMPT:
			printf("JMPT reached XXXX\n");
			if (inst_log1->value1.value_type == 6) {
				printf("ERROR1 %d\n", instruction->opcode);
				//break;
			}
			if (inst_log1->value1.value_type == 5) {
				printf("ERROR2\n");
				//break;
			}
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			/* FIXME: Check limits */
			if (1 == instruction->dstA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value3.value_id);
			tmp = fprintf(fd, " = ");
			printf("\nstore=%d\n", instruction->srcA.store);
			if (1 == instruction->srcA.indirect) {
				tmp = fprintf(fd, "*");
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			tmp = label_redirect[value_id].redirect;
			label = &labels[tmp];
			//tmp = fprintf(fd, "0x%x:", tmp);
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		case CALL:
			/* FIXME: This does nothing at the moment. */
			if (print_inst(self, instruction, inst_number, labels)) {
				tmp = fprintf(fd, "exiting1\n");
				return 1;
			}
			/* Search for EAX */
			printf("call index = 0x%"PRIx64"\n", instruction->srcA.index);
			tmp = instruction->srcA.index;
			if ((tmp >= 0) && (tmp < EXTERNAL_ENTRY_POINTS_MAX)) {
				printf("params size = 0x%x\n",
					external_entry_points[instruction->srcA.index].params_size);
			}
			printf("\t");
			tmp = fprintf(fd, "\t");
			tmp = label_redirect[inst_log1->value3.value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			printf(" = ");
			tmp = fprintf(fd, " = ");
			if (IND_DIRECT == instruction->srcA.indirect) {
				/* A direct call */
				/* FIXME: Get the output right */
				if (1 == instruction->srcA.relocated) {
					struct extension_call_s *call;
					call = inst_log1->extension;
					//tmp = fprintf(fd, "%s(%d:", 
					//	external_entry_points[instruction->srcA.index].name,
					//	external_entry_points[instruction->srcA.index].params_size);
					tmp = fprintf(fd, "%s(", 
						external_entry_points[instruction->srcA.index].name);
					tmp_state = 0;
					for (n2 = 0; n2 < call->params_size; n2++) {
						struct label_s *label;
						tmp = label_redirect[call->params[n2]].redirect;
						label = &labels[tmp];
						//printf("reg_params_order = 0x%x, label->value = 0x%"PRIx64"\n", reg_params_order[m], label->value);
						//if ((label->scope == 2) &&
						//	(label->type == 1)) {
						if (tmp_state > 0) {
							fprintf(fd, ", ");
						}
						//fprintf(fd, "int%"PRId64"_t ",
						//	label->size_bits);
						tmp = output_label(label, fd);
						tmp_state++;
					//	}
					}
#if 0
					for (n2 = 0; n2 < external_entry_points[l].params_size; n2++) {
						struct label_s *label;
						label = &labels[external_entry_points[l].params[n2]];
						if ((label->scope == 2) &&
							(label->type == 1)) {
							continue;
						}
						if (tmp_state > 0) {
							fprintf(fd, ", ");
						}
						fprintf(fd, "int%"PRId64"_t ",
						label->size_bits);
						tmp = output_label(label, fd);
						tmp_state++;
					}
#endif
					tmp = fprintf(fd, ");\n");
				} else {
					tmp = fprintf(fd, "CALL1()\n");
				}
#if 0
				/* FIXME: JCD test disabled */
				call = inst_log1->extension;
				if (call) {
					for (l = 0; l < call->params_size; l++) {
						if (l > 0) {
							fprintf(fd, ", ");
						}
						label = &labels[call->params[l]];
						tmp = output_label(label, fd);
					}
				}
#endif
				//tmp = fprintf(fd, ");\n");
				//printf("%s();\n",
				//	external_entry_points[instruction->srcA.index].name);
			} else {
				/* A indirect call via a function pointer or call table. */
				tmp = fprintf(fd, "(*");
				tmp = label_redirect[inst_log1->value1.indirect_value_id].redirect;
				label = &labels[tmp];
				tmp = output_label(label, fd);
				tmp = fprintf(fd, ") ()\n");
			}
//			tmp = fprintf(fd, "/* call(); */\n");
//			printf("/* call(); */\n");
			break;

		case CMP:
			/* Don't do anything for this instruction. */
			/* only does anything if combined with a branch instruction */
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			tmp = fprintf(fd, "\t");
			tmp = fprintf(fd, "/* cmp; */\n");
			printf("/* cmp; */\n");
			break;

		case TEST:
			/* Don't do anything for this instruction. */
			/* only does anything if combined with a branch instruction */
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			tmp = fprintf(fd, "\t");
			tmp = fprintf(fd, "/* test; */\n");
			printf("/* test; */\n");
			break;

		case IF:
			/* FIXME: Never gets here, why? */
			/* Don't do anything for this instruction. */
			/* only does anything if combined with a branch instruction */
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			printf("if ");
			tmp = fprintf(fd, "if ");
			found = 0;
			tmp = 30; /* Limit the scan backwards */
			l = inst_log1->prev[0];
			do {
				inst_log1_flags =  &inst_log_entry[l];
				printf("Previous opcode 0x%x\n", inst_log1_flags->instruction.opcode);
				printf("Previous flags 0x%x\n", inst_log1_flags->instruction.flags);
				if (1 == inst_log1_flags->instruction.flags) {
					found = 1;
				}
				printf("Previous flags instruction size 0x%x\n", inst_log1_flags->prev_size);
				if (inst_log1_flags->prev > 0) {
					l = inst_log1_flags->prev[0];
				} else {
					l = 0;
				}
				tmp--;
			} while ((0 == found) && (0 < tmp) && (0 != l));
			if (found == 0) {
				printf("Previous flags instruction not found. found=%d, tmp=%d, l=%d\n", found, tmp, l);
				return 1;
			} else {
				printf("Previous flags instruction found. found=%d, tmp=%d, l=%d\n", found, tmp, l);
			}

			err = if_expression( instruction->srcA.index, inst_log1_flags, label_redirect, labels, fd);
			printf("\t prev flags=%d, ",inst_log1_flags->instruction.flags);
			printf("\t prev opcode=0x%x, ",inst_log1_flags->instruction.opcode);
			printf("\t 0x%"PRIx64":%s", instruction->srcA.index, condition_table[instruction->srcA.index]);
			printf("\t LHS=%d, ",inst_log1->prev[0]);
			printf("IF goto label%04"PRIx32";\n", inst_log1->next[1]);
			if (err) {
				printf("IF CONDITION unknown\n");
				return 1;
			}
			tmp = fprintf(fd, "IF goto ");
//			for (l = 0; l < inst_log1->next_size; l++) {
//				tmp = fprintf(fd, ", label%04"PRIx32"", inst_log1->next[l]);
//			}
			tmp = fprintf(fd, "label%04"PRIx32";", inst_log1->next[1]);
			tmp = fprintf(fd, "\n");
			tmp = fprintf(fd, "\telse goto label%04"PRIx32";\n", inst_log1->next[0]);

			break;

		case NOP:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			break;
		case RET:
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			printf("\t");
			tmp = fprintf(fd, "\t");
			printf("return\n");
			tmp = fprintf(fd, "return ");
			tmp = label_redirect[inst_log1->value1.value_id].redirect;
			label = &labels[tmp];
			tmp = output_label(label, fd);
			//tmp = fprintf(fd, " /*(0x%"PRIx64")*/", inst_log1->value1.value_id);
			tmp = fprintf(fd, ";\n");
			break;
		default:
			printf("Unhandled output instruction1 opcode=0x%x\n", instruction->opcode);
			tmp = fprintf(fd, "Unhandled output instruction\n");
			if (print_inst(self, instruction, inst_number, labels))
				return 1;
			return 1;
			break;
		}
		if (0 < inst_log1->next_size && inst_log1->next[0] != (inst_number + 1)) {
			printf("\tTMP3 goto label%04"PRIx32";\n", inst_log1->next[0]);
			tmp = fprintf(fd, "\tTMP3 goto label%04"PRIx32";\n", inst_log1->next[0]);
		}
	}
	return 0;
}

int output_function_body(struct self_s *self, struct process_state_s *process_state,
			 FILE *fd, int start, int end, struct label_redirect_s *label_redirect, struct label_s *labels)
{
	int tmp, l, n, n2;
	int tmp_state;
	int err;
	int found;
	uint64_t value_id;
	struct instruction_s *instruction;
	//struct instruction_s *instruction_prev;
	struct inst_log_entry_s *inst_log1 = NULL;
	struct inst_log_entry_s *inst_log1_prev;
	struct inst_log_entry_s *inst_log1_flags;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	//struct memory_s *value;
	struct label_s *label;
	//struct extension_call_s *call;

	if (!start || !end) {
		printf("output_function_body:Invalid start or end\n");
		return 1;
	}
	printf("output_function_body:start=0x%x, end=0x%x\n", start, end);

	for (n = start; n <= end; n++) {
		tmp = output_inst_in_c(self, process_state, fd, n, label_redirect, labels, "\\n");
	}
#if 0
	if (0 < inst_log1->next_size && inst_log1->next[0]) {
		printf("\tTMP1 goto label%04"PRIx32";\n", inst_log1->next[0]);
		tmp = fprintf(fd, "\tTMP1 goto label%04"PRIx32";\n", inst_log1->next[0]);
	}
#endif
	tmp = fprintf(fd, "}\n\n");
	return 0;
}

