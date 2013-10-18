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
#include <string.h>

char *dis_flags_table[] = { " ", "f" };

/* RDI, RSI, RDX, RCX, R08, R09  */
int reg_params_order[] = {
        0x40, /* RDI */
        0x38, /* RSI */
        0x18, /* RDX */
        0x10, /* RCX */
        REG_08, /* R08 */
        REG_09 /* R09 */
};

const char * opcode_table[] = {
	"NONE",   // 0x00
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
	"INC",  // 0x2A
	"POP",  // 0x2B
	"PUSH",  // 0x2C
	"LEAVE",  // 0x2D
	"NOP",  // 0x2E
};

char *store_table[] = { "i", "r", "m", "s" };
char *indirect_table[] = { "", "m", "s", "p" };

int string_cat(struct string_s *string, char *src, int src_length) {
	int result = 1;
	if ((string->len + src_length) < string->max) {
		memcpy(&(string->string[string->len]), src, src_length);
		string->len += src_length;
		string->string[string->len] = 0;
		result = 0;
	} else {
		printf("string_cat: FAILED. string len = 0x%x, src_length = 0x%x\n", string->len, src_length);
	}
	return result;
}


int write_inst(struct self_s *self, struct string_s *string, struct instruction_s *instruction, int instruction_number, struct label_s *labels)
{
	int ret = 1; /* Default to failed */
	int tmp;
	int tmp_state = 0;
	int n, l;
	char buffer[1024];
	struct external_entry_point_s *external_entry_points = self->external_entry_points;

	printf("string len = 0x%x, max = 0x%x\n", string->len, string->max);

	debug_print(DEBUG_OUTPUT, 1, "opcode = 0x%x\n", instruction->opcode);
	debug_print(DEBUG_OUTPUT, 1, "opcode = 0x%x\n", instruction->flags);
	tmp = snprintf(buffer, 1023, "// 0x%04x:%s%s",
		instruction_number,
		opcode_table[instruction->opcode],
		dis_flags_table[instruction->flags]);
	tmp = string_cat(string, buffer, strlen(buffer));

	switch (instruction->opcode) {
	case MOV:
	case LOAD:
		if (instruction->srcA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d,",
				indirect_table[instruction->srcA.indirect],
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d,",
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		if (instruction->dstA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d",
				indirect_table[instruction->dstA.indirect],
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d",
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		ret = 0;
		break;
	case STORE:
	case ADD:
	case SUB:
	case SBB:
	case MUL:
	case IMUL:
	case rAND:
	case OR:
	case XOR:
	case SHL:
	case SHR:
	case SAL:
	case SAR:
	case CMP:
	case NOT:
	case NEG:
	case SEX:
	case TEST:
	/* FIXME: Add DIV */
	//case DIV:
		if (instruction->srcA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d,",
				indirect_table[instruction->srcA.indirect],
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d,",
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		if (instruction->srcB.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d,",
				indirect_table[instruction->srcB.indirect],
				store_table[instruction->srcB.store],
				instruction->srcB.index,
				instruction->srcB.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d,",
				store_table[instruction->srcB.store],
				instruction->srcB.index,
				instruction->srcB.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		if (instruction->dstA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d",
				indirect_table[instruction->dstA.indirect],
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d",
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		ret = 0;
		break;
	case ICMP:
		tmp = snprintf(buffer, 1023, " COND 0x%x,",
			instruction->predicate);
		if (instruction->srcA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d,",
				indirect_table[instruction->srcA.indirect],
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d,",
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		if (instruction->srcB.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d,",
				indirect_table[instruction->srcB.indirect],
				store_table[instruction->srcB.store],
				instruction->srcB.index,
				instruction->srcB.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d,",
				store_table[instruction->srcB.store],
				instruction->srcB.index,
				instruction->srcB.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		if (instruction->dstA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d",
				indirect_table[instruction->dstA.indirect],
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d",
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		ret = 0;
		break;
	case JMP:
		if (instruction->srcA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d,",
				indirect_table[instruction->srcA.indirect],
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d,",
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		if (instruction->dstA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d",
				indirect_table[instruction->dstA.indirect],
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d",
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		ret = 0;
		break;
	case BC:
		if (instruction->srcA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d,",
				indirect_table[instruction->srcA.indirect],
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d,",
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		ret = 0;
		break;
	case JMPT:
		if (instruction->srcA.indirect) {
			debug_print(DEBUG_OUTPUT, 1, "JMPT 0x%x 0x%x 0x%x\n", instruction->srcA.indirect, instruction->srcA.store, instruction->srcA.value_size);
			if (instruction->srcA.indirect > 4) {
				instruction->srcA.indirect = 0;
			}
			if (instruction->srcA.indirect < 0) {
				instruction->srcA.indirect = 0;
			}
			if (instruction->srcA.store > 4) {
				instruction->srcA.store = 0;
			}
			if (instruction->srcA.store < 0) {
				instruction->srcA.store = 0;
			}
			debug_print(DEBUG_OUTPUT, 1, "JMPT 0x%x 0x%x 0x%x\n", instruction->srcA.indirect, instruction->srcA.store, instruction->srcA.value_size);
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d,",
				indirect_table[instruction->srcA.indirect],
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d,",
				store_table[instruction->srcA.store],
				instruction->srcA.index,
				instruction->srcA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		if (instruction->dstA.indirect) {
			tmp = snprintf(buffer, 1023, " %s[%s0x%"PRIx64"]/%d",
				indirect_table[instruction->dstA.indirect],
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " %s0x%"PRIx64"/%d",
				store_table[instruction->dstA.store],
				instruction->dstA.index,
				instruction->dstA.value_size);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		ret = 0;
		break;
	case IF:
		tmp = snprintf(buffer, 1023, " cond=%"PRIu64"", instruction->srcA.index);
		tmp = snprintf(buffer, 1023, " JMP-REL=0x%"PRIx64"", instruction->dstA.index);
		ret = 0;
		break;
	case CALL:
		if (instruction->srcA.relocated == 2) {
			for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
				if ((external_entry_points[n].valid != 0) &&
					(external_entry_points[n].type == 1) &&
					(external_entry_points[n].value == instruction->srcA.index)) {
					instruction->srcA.index = n;
					instruction->srcA.relocated = 1;
					break;
				}
			}
		}
		if ((instruction->srcA.indirect == IND_DIRECT) &&
			(instruction->srcA.relocated == 1)) {
			tmp = snprintf(buffer, 1023, " CALL2 0x%"PRIx64":%s(",
				instruction->srcA.index,
				external_entry_points[instruction->srcA.index].name);
			tmp = string_cat(string, buffer, strlen(buffer));
			tmp_state = 0;
			l = instruction->srcA.index;
			for (n = 0; n < external_entry_points[l].params_size; n++) {
				struct label_s *label;
				label = &labels[external_entry_points[l].params[n]];
				debug_print(DEBUG_OUTPUT, 1, "reg_params_order = 0x%x, label->value = 0x%"PRIx64"\n", reg_params_order[n], label->value);
				if ((label->scope == 2) &&
					(label->type == 1)) {
					if (tmp_state > 0) {
						snprintf(buffer, 1023, ", ");
					}
					snprintf(buffer, 1023, "int%"PRId64"_t ",
						label->size_bits);
					tmp = label_to_string(label, buffer, 1023);
					tmp = snprintf(buffer, 1023, "%s", buffer);
					tmp_state++;
				}
			}
			for (n = 0; n < external_entry_points[l].params_size; n++) {
				struct label_s *label;
				label = &labels[external_entry_points[l].params[n]];
				if ((label->scope == 2) &&
					(label->type == 1)) {
					continue;
				}
				if (tmp_state > 0) {
					snprintf(buffer, 1023, ", ");
				}
				snprintf(buffer, 1023, "int%"PRId64"_t ",
					label->size_bits);
				tmp = string_cat(string, buffer, strlen(buffer));
				tmp = label_to_string(label, buffer, 1023);
				tmp = snprintf(buffer, 1023, "%s", buffer);
				tmp_state++;
			}
			tmp = snprintf(buffer, 1023, ");");
		} else if (instruction->srcA.indirect == IND_MEM) {
			tmp = snprintf(buffer, 1023, "(*r0x%"PRIx64") ();", 
				instruction->srcA.index);
			tmp = string_cat(string, buffer, strlen(buffer));
		} else {
			tmp = snprintf(buffer, 1023, " CALL FAILED index=0x%"PRIx64"",
				instruction->srcA.index);
			tmp = string_cat(string, buffer, strlen(buffer));
		}
		ret = 0;
		break;
	case NOP:
		//tmp = snprintf(buffer, 1023, "");
		ret = 0;
		break;
	case RET:
		//tmp = snprintf(buffer, 1023, "");
		ret = 0;
		break;
	default:
		debug_print(DEBUG_OUTPUT, 1, "Print inst fails. Opcode = 0x%x\n", instruction->opcode);
		exit(1);
	}
	return ret;
}

int print_inst(struct self_s *self, struct instruction_s *instruction, int instruction_number, struct label_s *labels)
{
	int ret;
	int tmp;
	struct string_s string1;
	string1.len = 0;
	string1.max = 1023;
	string1.string[0] = 0;
	
	ret = write_inst(self, &string1, instruction, instruction_number, labels);
	tmp = fprintf(stderr, "%s", string1.string);
	tmp = fprintf(stderr, "\n");
	return ret;
}

int print_inst_short(struct self_s *self, struct instruction_s *instruction) {
	debug_print(DEBUG_OUTPUT, 1, "Execute Instruction %d:%s%s\n",
		instruction->opcode,
		opcode_table[instruction->opcode],
		dis_flags_table[instruction->flags]);
	return 0;
}
