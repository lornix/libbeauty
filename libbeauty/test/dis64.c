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
 * 11-9-2004 Initial work.
 *   Copyright (C) 2004 James Courtier-Dutton James@superbug.co.uk
 * 10-11-2007 Updates.
 *   Copyright (C) 2007 James Courtier-Dutton James@superbug.co.uk
 * 29-03-2009 Updates.
 *   Copyright (C) 2009 James Courtier-Dutton James@superbug.co.uk
 * 05-05-2013 Updates.
 *   Copyright (C) 2004-2013 James Courtier-Dutton James@superbug.co.uk
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

#define AST_SIZE 300
/* Params order:
 * int test30(int64_t param_reg0040, int64_t param_reg0038, int64_t param_reg0018, int64_t param_reg0010, int64_t param_reg0050, int64_t param_reg0058, int64_t param_stack0008, int64_t param_stack0010)
 */

/* Used to store details of each instruction.
 * Linked by prev/next pointers
 * so that a single list can store all program flow.
 */
// struct inst_log_entry_s inst_log_entry[INST_LOG_ENTRY_SIZE];
// int search_back_seen[INST_LOG_ENTRY_SIZE];

/* Used to keep record of where we have been before.
 * Used to identify program flow, branches, and joins.
 */
int memory_used[MEMORY_USED_SIZE];
/* Used to keep a non bfd version of the relocation entries */
int memory_relocation[MEMORY_USED_SIZE];

int disassemble(void *handle_void, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset) {
	int tmp;
	tmp = disassemble_amd64(handle_void, dis_instructions, base_address, offset);
	return tmp;
}


int print_dis_instructions(struct self_s *self)
{
	int n;
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;

	debug_print(DEBUG_MAIN, 1, "print_dis_instructions:\n");
	for (n = 1; n < inst_log; n++) {
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		if (print_inst(self, instruction, n, NULL))
			return 1;
		debug_print(DEBUG_MAIN, 1, "start_address:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.start_address,
			inst_log1->value2.start_address,
			inst_log1->value3.start_address);
		debug_print(DEBUG_MAIN, 1, "init:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.init_value,
			inst_log1->value2.init_value,
			inst_log1->value3.init_value);
		debug_print(DEBUG_MAIN, 1, "offset:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.offset_value,
			inst_log1->value2.offset_value,
			inst_log1->value3.offset_value);
		debug_print(DEBUG_MAIN, 1, "indirect init:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.indirect_init_value,
			inst_log1->value2.indirect_init_value,
			inst_log1->value3.indirect_init_value);
		debug_print(DEBUG_MAIN, 1, "indirect offset:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.indirect_offset_value,
			inst_log1->value2.indirect_offset_value,
			inst_log1->value3.indirect_offset_value);
		debug_print(DEBUG_MAIN, 1, "indirect value_id:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.indirect_value_id,
			inst_log1->value2.indirect_value_id,
			inst_log1->value3.indirect_value_id);
		debug_print(DEBUG_MAIN, 1, "value_type:0x%x, 0x%x -> 0x%x\n",
			inst_log1->value1.value_type,
			inst_log1->value2.value_type,
			inst_log1->value3.value_type);
		debug_print(DEBUG_MAIN, 1, "value_scope:0x%x, 0x%x -> 0x%x\n",
			inst_log1->value1.value_scope,
			inst_log1->value2.value_scope,
			inst_log1->value3.value_scope);
		debug_print(DEBUG_MAIN, 1, "value_id:0x%"PRIx64", 0x%"PRIx64" -> 0x%"PRIx64"\n",
			inst_log1->value1.value_id,
			inst_log1->value2.value_id,
			inst_log1->value3.value_id);
		if (inst_log1->prev_size > 0) {
			int n;
			for (n = 0; n < inst_log1->prev_size; n++) {
				debug_print(DEBUG_MAIN, 1, "inst_prev:%d:0x%04x\n",
					n,
					inst_log1->prev[n]);
			}
		}
		if (inst_log1->next_size > 0) {
			int n;
			for (n = 0; n < inst_log1->next_size; n++) {
				debug_print(DEBUG_MAIN, 1, "inst_next:%d:0x%04x\n",
					n,
					inst_log1->next[n]);
			}
		}
	}
	return 0;
}

int ram_init(struct memory_s *memory_data)
{
	return 0;
}

int reg_init(struct memory_s *memory_reg)
{
	/* esp */
	memory_reg[0].start_address = REG_SP;
	/* 4 bytes */
	memory_reg[0].length = 8;
	/* 1 - Known */
	memory_reg[0].init_value_type = 1;
	/* Initial value when first accessed */
	memory_reg[0].init_value = 0x10000;
	/* No offset yet */
	memory_reg[0].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_reg[0].value_type = 6;
	memory_reg[0].value_unsigned = 0;
	memory_reg[0].value_signed = 0;
	memory_reg[0].value_instruction = 0;
	memory_reg[0].value_pointer = 1;
	memory_reg[0].value_normal = 0;
	/* Index into the various structure tables */
	memory_reg[0].value_struct = 0;
	/* last_accessed_from_instruction_at_memory_location */
	memory_reg[0].ref_memory = 0;
	memory_reg[0].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_reg[0].value_scope = 2;
	/* Each time a new value is assigned, this value_id increases */
	memory_reg[0].value_id = 1;
	/* valid: 0 - Entry Not used yet, 1 - Entry Used */
	memory_reg[0].valid = 1;

	/* ebp */
	memory_reg[1].start_address = REG_BP;
	/* 4 bytes */
	memory_reg[1].length = 8;
	/* 1 - Known */
	memory_reg[1].init_value_type = 1;
	/* Initial value when first accessed */
	memory_reg[1].init_value = 0x20000;
	/* No offset yet */
	memory_reg[1].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_reg[1].value_type = 6;
	memory_reg[1].value_unsigned = 0;
	memory_reg[1].value_signed = 0;
	memory_reg[1].value_instruction = 0;
	memory_reg[1].value_pointer = 1;
	memory_reg[1].value_normal = 0;
	/* Index into the various structure tables */
	memory_reg[1].value_struct = 0;
	memory_reg[1].ref_memory = 0;
	memory_reg[1].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_reg[1].value_scope = 2;
	/* Each time a new value is assigned, this value_id increases */
	memory_reg[1].value_id = 2;
	/* valid: 0 - entry Not used yet, 1 - entry Used */
	memory_reg[1].valid = 1;

	/* eip */
	memory_reg[2].start_address = REG_IP;
	/* 4 bytes */
	memory_reg[2].length = 8;
	/* 1 - Known */
	memory_reg[2].init_value_type = 1;
	/* Initial value when first accessed */
	memory_reg[2].init_value = EIP_START;
	/* No offset yet */
	memory_reg[2].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_reg[2].value_type = 5;
	memory_reg[2].value_type = 6;
	memory_reg[2].value_unsigned = 0;
	memory_reg[2].value_signed = 0;
	memory_reg[2].value_instruction = 0;
	memory_reg[2].value_pointer = 1;
	memory_reg[2].value_normal = 0;
	/* Index into the various structure tables */
	memory_reg[2].value_struct = 0;
	memory_reg[2].ref_memory = 0;
	memory_reg[2].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_reg[2].value_scope = 3;
	/* Each time a new value is assigned, this value_id increases */
	memory_reg[2].value_id = 0;
	/* valid: 0 - entry Not used yet, 1 - entry Used */
	memory_reg[2].valid = 1;
	return 0;
}

int stack_init(struct memory_s *memory_stack)
{
	int n = 0;
	/* eip on the stack */
	memory_stack[n].start_address = 0x10000;
	/* 4 bytes */
	memory_stack[n].length = 8;
	/* 1 - Known */
	memory_stack[n].init_value_type = 1;
	/* Initial value when first accessed */
	memory_stack[n].init_value = 0x0;
	/* No offset yet */
	memory_stack[n].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_stack[n].value_type = 5;
	memory_stack[n].value_unsigned = 0;
	memory_stack[n].value_signed = 0;
	memory_stack[n].value_instruction = 0;
	memory_stack[n].value_pointer = 1;
	memory_stack[n].value_normal = 0;
	/* Index into the various structure tables */
	memory_stack[n].value_struct = 0;
	memory_stack[n].ref_memory = 0;
	memory_stack[n].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_stack[n].value_scope = 2;
	/* Each time a new value is assigned, this value_id increases */
	memory_stack[n].value_id = 3;
	/* valid: 0 - Not used yet, 1 - Used */
	memory_stack[n].valid = 1;
	n++;

#if 0
	/* Param1 */
	memory_stack[n].start_address = 0x10004;
	/* 4 bytes */
	memory_stack[n].length = 4;
	/* 1 - Known */
	memory_stack[n].init_value_type = 1;
	/* Initial value when first accessed */
	memory_stack[n].init_value = 0x321;
	/* No offset yet */
	memory_stack[n].offset_value = 0;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	memory_stack[n].value_type = 2;
	memory_stack[n].ref_memory = 0;
	memory_stack[n].ref_log = 0;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Mem */
	memory_stack[n].value_scope = 0;
	/* Each time a new value is assigned, this value_id increases */
	memory_stack[n].value_id = 0;
	/* valid: 0 - Not used yet, 1 - Used */
	memory_stack[n].valid = 1;
	n++;
#endif
	for (;n < MEMORY_STACK_SIZE; n++) {
		memory_stack[n].valid = 0;
	}
	return 0;
}

int print_mem(struct memory_s *memory, int location) {
	debug_print(DEBUG_MAIN, 1, "start_address:0x%"PRIx64"\n",
		memory[location].start_address);
	debug_print(DEBUG_MAIN, 1, "length:0x%x\n",
		memory[location].length);
	debug_print(DEBUG_MAIN, 1, "init_value_type:0x%x\n",
		memory[location].init_value_type);
	debug_print(DEBUG_MAIN, 1, "init:0x%"PRIx64"\n",
		memory[location].init_value);
	debug_print(DEBUG_MAIN, 1, "offset:0x%"PRIx64"\n",
		memory[location].offset_value);
	debug_print(DEBUG_MAIN, 1, "indirect_init:0x%"PRIx64"\n",
		memory[location].indirect_init_value);
	debug_print(DEBUG_MAIN, 1, "indirect_offset:0x%"PRIx64"\n",
		memory[location].indirect_offset_value);
	debug_print(DEBUG_MAIN, 1, "value_type:0x%x\n",
		memory[location].value_type);
	debug_print(DEBUG_MAIN, 1, "ref_memory:0x%"PRIx32"\n",
		memory[location].ref_memory);
	debug_print(DEBUG_MAIN, 1, "ref_log:0x%"PRIx32"\n",
		memory[location].ref_log);
	debug_print(DEBUG_MAIN, 1, "value_scope:0x%x\n",
		memory[location].value_scope);
	debug_print(DEBUG_MAIN, 1, "value_id:0x%"PRIx64"\n",
		memory[location].value_id);
	debug_print(DEBUG_MAIN, 1, "valid:0x%"PRIx64"\n",
		memory[location].valid);
	return 0;
}

int external_entry_points_init(struct external_entry_point_s *external_entry_points, void *handle_void)
{
	int tmp;
	int n;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;

	tmp = external_entry_points_init_bfl(external_entry_points, handle_void);
	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if (external_entry_points[n].valid != 0) {
			external_entry_points[n].process_state.memory_text =
				calloc(MEMORY_TEXT_SIZE, sizeof(struct memory_s));
			external_entry_points[n].process_state.memory_stack =
				calloc(MEMORY_STACK_SIZE, sizeof(struct memory_s));
			external_entry_points[n].process_state.memory_reg =
				calloc(MEMORY_REG_SIZE, sizeof(struct memory_s));
			external_entry_points[n].process_state.memory_data =
				calloc(MEMORY_DATA_SIZE, sizeof(struct memory_s));
			external_entry_points[n].process_state.memory_used =
				calloc(MEMORY_USED_SIZE, sizeof(int));
			//memory_text = external_entry_points[n].process_state.memory_text;
			memory_stack = external_entry_points[n].process_state.memory_stack;
			memory_reg = external_entry_points[n].process_state.memory_reg;
			memory_data = external_entry_points[n].process_state.memory_data;
			//memory_used = external_entry_points[n].process_state.memory_used;

			ram_init(memory_data);
			reg_init(memory_reg);
			stack_init(memory_stack);
			/* Set EIP entry point equal to symbol table entry point */
			//memory_reg[2].init_value = EIP_START;
			memory_reg[2].offset_value = external_entry_points[n].value;

			print_mem(memory_reg, 1);
		}
	}
	return tmp;
}

int find_empty_ast_entry(struct ast_entry_s *ast_entry, int *entry)
{
	int found;
	int n;

	found = 0;
	for (n = 0; n < 100; n++) {
		if (!ast_entry[n].type) {
			found = 1;
			*entry = n;
			break;
		}
	}
	return found;
}

int print_ast_container(struct ast_container_s *ast_container)
{
	int n;
	if (ast_container->length) {
		debug_print(DEBUG_MAIN, 1, "ast_container->length = 0x%x\n", ast_container->length);
	}
	debug_print(DEBUG_MAIN, 1, "parent = 0x%x, 0x%"PRIx64", 0x%x\n",
		ast_container->parent.type, ast_container->parent.index, ast_container->parent.offset);
	if (ast_container->object) {
		for (n = 0; n < ast_container->length; n++) {
			debug_print(DEBUG_MAIN, 1, "0x%d:type = 0x%x, index = 0x%"PRIx64"\n",
				n,
				ast_container->object[n].type,
				ast_container->object[n].index);
		}
	} else if (ast_container->length > 0) {
		debug_print(DEBUG_MAIN, 1, "print_ast_container invalid\n");
	}
	return 0;
}

int is_member_of_loop(struct control_flow_node_s *nodes, int loop_node, int test_node) {
	int n;
	int found = 0;

	for (n = 0; n < nodes[test_node].member_of_loop_size; n++) {
		if (loop_node == nodes[test_node].member_of_loop[n]) {
			found = 1;
			break;
		}
	}
	return found;
}

/* Convert Control flow graph to Abstract syntax tree */
/* One list with just a list of Type, Index pairs.
 * The Type will be one of:
 *	Node: A particular Node
 *	Container: For another list of types. Type, Index pairs.
 *	If: For a if...then...else contruct. Contains the Node for the if expression, then Containers for True, and False paths.
 *	Loop: For a loop contruct. A loop has First Node, and Subsequent Nodes in the loop body.
 *		Later Loop will be converted to for() or while().
 */
int cfg_to_ast(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct ast_s *ast, int start_node)
{
	struct ast_container_s *ast_container;
	struct ast_if_then_else_s *ast_if_then_else;
	struct ast_if_then_goto_s *ast_if_then_goto;
	struct ast_loop_s *ast_loop;
	struct ast_loop_then_else_s *ast_loop_then_else;
	struct ast_loop_container_s *ast_loop_container;
	struct ast_entry_s *ast_entry;
	int found;
	int n;
	//int m;
	int entry;
	int type;
	int node;
	int node_end;
	int container_index = 0;
	int if_then_else_index = 0;
	int if_then_goto_index = 0;
	int loop_index = 0;
	int loop_then_else_index = 0;
	int loop_container_index = 0;
	int index;
	int length;
	int tmp;
	int tmp_entry = 0;
	int link_goto = 0;
	int link_norm = 1;
	int ret = 0;

	ast_container = ast->ast_container;
	ast_if_then_else = ast->ast_if_then_else;
	ast_if_then_goto = ast->ast_if_then_goto;
	ast_loop = ast->ast_loop;
	ast_loop_then_else = ast->ast_loop_then_else;
	ast_loop_container = ast->ast_loop_container;
	ast_entry = ast->ast_entry;
	container_index = ast->container_size;
	if_then_else_index = ast->if_then_else_size;
	if_then_goto_index = ast->if_then_goto_size;
	loop_index = ast->loop_size;
	loop_then_else_index = ast->loop_then_else_size;
	loop_container_index = ast->loop_container_size;

	ast_entry[0].type = AST_TYPE_CONTAINER;
	ast_entry[0].sub_type = 0; /* for normal container */
	ast_entry[0].index = container_index;
	ast_entry[0].sub_index = 0;
	ast_entry[0].node = start_node;
	ast_entry[0].node_end = 0;
	if (container_index >= AST_SIZE) { 
		debug_print(DEBUG_MAIN, 1, "container_index too large 0\n");
		ret = 1;
		goto exit_cfg_to_ast;
	}
	ast->ast_container[container_index].start_node = start_node;
	container_index++;
	if (container_index >= AST_SIZE) { 
		debug_print(DEBUG_MAIN, 1, "container_index too large 0\n");
		ret = 1;
		goto exit_cfg_to_ast;
	}

	do {
		found = 0;
		for (n = 0; n < AST_SIZE; n++) {
			if (ast_entry[n].type) {
				found = 1;
				entry = n;
				break;
			}
		}
		if (!found) {
			break;
		}
		debug_print(DEBUG_MAIN, 1, "BEFORE ast_entry entry = 0x%x\n", entry);
		debug_print(DEBUG_MAIN, 1, "ast_type = 0x%x\n", ast_entry[entry].type);
		debug_print(DEBUG_MAIN, 1, "ast_index = 0x%x\n", ast_entry[entry].index);
		debug_print(DEBUG_MAIN, 1, "ast_sub_index = 0x%x\n", ast_entry[entry].sub_index);
		debug_print(DEBUG_MAIN, 1, "ast_node = 0x%x\n", ast_entry[entry].node);
		debug_print(DEBUG_MAIN, 1, "ast_node_end = 0x%x\n", ast_entry[entry].node_end);

		node = ast_entry[entry].node;
		node_end = ast_entry[entry].node_end;
		type = AST_TYPE_EMPTY;
		if (nodes[node].type == NODE_TYPE_IF_THEN_ELSE) {
			type = AST_TYPE_IF_THEN_ELSE;
		} else if (nodes[node].type == NODE_TYPE_IF_THEN_GOTO) {
			type = AST_TYPE_IF_THEN_GOTO;
		} else if (nodes[node].type == NODE_TYPE_LOOP) {
			type = AST_TYPE_LOOP;
		} else if (nodes[node].type == NODE_TYPE_LOOP_THEN_ELSE) {
			type = AST_TYPE_LOOP_THEN_ELSE;
		} else {
			type = AST_TYPE_NODE;
		};
		debug_print(DEBUG_MAIN, 1, "new_node_end = 0x%x\n", node_end);
		debug_print(DEBUG_MAIN, 1, "AST: Type = 0x%x\n", type);
		switch (type) {
		case AST_TYPE_IF_THEN_ELSE:
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				debug_print(DEBUG_MAIN, 1, "failed type != 2\n");
				exit(1);
			}
			length = ast_container[index].length;
			if (0 == length) {
				ast_container[index].object = malloc(sizeof(struct ast_type_index_s));
				ast_container[index].length = 1;
			} else {
				tmp = length + 1;
				ast_container[index].object = realloc(ast_container[index].object, tmp * sizeof(struct ast_type_index_s));
				ast_container[index].length = tmp;
			}
			ast_container[index].object[length].type = type;
			ast_container[index].object[length].index = if_then_else_index;
			ast_if_then_else[if_then_else_index].expression_node.type = AST_TYPE_NODE;
			ast_if_then_else[if_then_else_index].expression_node.index = node;
			/* Handle the if_then path */
			if (!(nodes[node].next_size)) {
				ast_if_then_else[if_then_else_index].if_then.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[0].node == nodes[node].if_tail) {
				ast_if_then_else[if_then_else_index].if_then.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[0].is_loop_edge) {
				ast_if_then_else[if_then_else_index].if_then.type = AST_TYPE_EMPTY;
			} else {
				debug_print(DEBUG_MAIN, 1, "Creating if_then container 0x%x\n", container_index);
				ast_if_then_else[if_then_else_index].if_then.type = AST_TYPE_CONTAINER;
				ast_if_then_else[if_then_else_index].if_then.index = container_index;
				tmp = find_empty_ast_entry(ast_entry, &tmp_entry);
				ast_entry[tmp_entry].type = AST_TYPE_CONTAINER;
				ast_entry[tmp_entry].sub_type = 0; /* for normal container */
				ast_entry[tmp_entry].index = container_index;
				ast_entry[tmp_entry].sub_index = 0;
				ast_entry[tmp_entry].node = nodes[node].link_next[0].node;
				ast_entry[tmp_entry].node_end = nodes[node].if_tail;
				container_index++;
				if (container_index >= AST_SIZE) { 
					debug_print(DEBUG_MAIN, 1, "container_index too large 1\n");
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			/* Handle the if_else path */
			if (!(nodes[node].next_size)) {
				ast_if_then_else[if_then_else_index].if_else.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[1].node == nodes[node].if_tail) {
				ast_if_then_else[if_then_else_index].if_else.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[1].is_loop_edge) {
				ast_if_then_else[if_then_else_index].if_else.type = AST_TYPE_EMPTY;
			} else {
				debug_print(DEBUG_MAIN, 1, "Creating if_else container 0x%x\n", container_index);
				ast_if_then_else[if_then_else_index].if_else.type = AST_TYPE_CONTAINER;
				ast_if_then_else[if_then_else_index].if_else.index = container_index;
				tmp = find_empty_ast_entry(ast_entry, &tmp_entry);
				ast_entry[tmp_entry].type = AST_TYPE_CONTAINER;
				ast_entry[tmp_entry].sub_type = 0; /* for normal container */
				ast_entry[tmp_entry].index = container_index;
				ast_entry[tmp_entry].sub_index = 0;
				ast_entry[tmp_entry].node = nodes[node].link_next[1].node;
				ast_entry[tmp_entry].node_end = nodes[node].if_tail;
				container_index++;
				if (container_index >= AST_SIZE) { 
					debug_print(DEBUG_MAIN, 1, "container_index too large 2\n");
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}

			if (nodes[node].if_tail == ast_entry[entry].node_end) {
				ast_entry[entry].type = AST_TYPE_EMPTY;
			} else {
				ast_entry[entry].sub_index = ast_container[index].length;
				ast_entry[entry].node = nodes[node].if_tail;
			}

			if_then_else_index++;
			if (if_then_else_index >= AST_SIZE) {
				debug_print(DEBUG_MAIN, 1, "if_then_else_index too large\n");
				ret = 1;
				goto exit_cfg_to_ast;
			}
			break;
		case AST_TYPE_IF_THEN_GOTO:
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				debug_print(DEBUG_MAIN, 1, "AST_TYPE_IF_THEN_GOTO:failed type != 2\n");
				exit(1);
			}
			length = ast_container[index].length;
			if (0 == length) {
				ast_container[index].object = malloc(sizeof(struct ast_type_index_s));
				ast_container[index].length = 1;
			} else {
				tmp = length + 1;
				ast_container[index].object = realloc(ast_container[index].object, tmp * sizeof(struct ast_type_index_s));
				ast_container[index].length = tmp;
			}
			ast_container[index].object[length].type = type;
			ast_container[index].object[length].index = if_then_goto_index;
			ast_if_then_goto[if_then_goto_index].parent.type = AST_TYPE_CONTAINER;
			ast_if_then_goto[if_then_goto_index].parent.index = index;
			ast_if_then_goto[if_then_goto_index].parent.offset = length; /* Point to the parent that points to us */

			ast_if_then_goto[if_then_goto_index].expression_node.type = AST_TYPE_NODE;
			ast_if_then_goto[if_then_goto_index].expression_node.index = node;

			if (nodes[node].link_next[0].is_loop_exit) {
				link_goto = 0;
				link_norm = 1;
			} else if (nodes[node].link_next[1].is_loop_exit) {
				link_goto = 1;
				link_norm = 0;
			} else {
				debug_print(DEBUG_MAIN, 1, "FAILED: No is_exit entry in IF_THEN_GOTO\n");
				exit(1);
			}
			/* Only handle the is_exit path.
			 * There is not "else" path with a if_then_goto
			 */
			if (!(nodes[node].next_size)) {
				ast_if_then_goto[if_then_goto_index].if_then_goto.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[link_goto].node == nodes[node].if_tail) {
				ast_if_then_goto[if_then_goto_index].if_then_goto.type = AST_TYPE_EMPTY;
			} else {
				debug_print(DEBUG_MAIN, 1, "Creating if_then container 0x%x\n", container_index);
				ast_if_then_goto[if_then_goto_index].if_then_goto.type = AST_TYPE_CONTAINER;
				ast_if_then_goto[if_then_goto_index].if_then_goto.index = container_index;
				tmp = find_empty_ast_entry(ast_entry, &tmp_entry);
				ast_entry[tmp_entry].type = AST_TYPE_CONTAINER;
				ast_entry[tmp_entry].sub_type = 0; /* for normal container */
				ast_entry[tmp_entry].index = container_index;
				ast_entry[tmp_entry].sub_index = 0;
				ast_entry[tmp_entry].node = nodes[node].link_next[link_goto].node;
				ast_entry[tmp_entry].node_end = nodes[node].if_tail;
				container_index++;
				if (container_index >= AST_SIZE) { 
					debug_print(DEBUG_MAIN, 1, "container_index too large 3\n");
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			/* FIXME: Fix case where link_norm is a loop edge, and link_goto does not exit the loop */
			ast_entry[entry].sub_index = ast_container[index].length;
			ast_entry[entry].node = nodes[node].link_next[link_norm].node;
			if (ast_entry[entry].sub_type == 1) {
				if (!is_member_of_loop(nodes, node, ast_entry[entry].node)) {
					int exit_index = ast_entry[entry].index;
					debug_print(DEBUG_MAIN, 1, "parent = 0x%x, 0x%"PRIx64", 0x%x\n",
						ast_container[ast_entry[entry].index].parent.type,
						ast_container[ast_entry[entry].index].parent.index,
						ast_container[ast_entry[entry].index].parent.offset);
					ast_entry[entry].type = ast_container[exit_index].parent.type;
					ast_entry[entry].sub_type = ast_container[exit_index].sub_type;
					ast_entry[entry].index = ast_container[exit_index].parent.index;
					ast_entry[entry].sub_index = ast_container[exit_index].parent.offset;
					ast_entry[entry].node = nodes[node].link_next[link_goto].node;
					ast_entry[entry].node_end = ast_container[exit_index].length;
				}
			} else if (ast_entry[entry].node == ast_entry[entry].node_end) {
				ast_entry[entry].type = AST_TYPE_EMPTY;
			}

			if_then_goto_index++;
			if (if_then_goto_index >= AST_SIZE) {
				debug_print(DEBUG_MAIN, 1, "if_then_goto_index too large\n");
				ret = 1;
				goto exit_cfg_to_ast;
			}
			break;
		case AST_TYPE_NODE:
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				debug_print(DEBUG_MAIN, 1, "AST_TYPE_NODE failed type != 2\n");
				exit(1);
			}
			length = ast_container[index].length;
			if (0 == length) {
				ast_container[index].object = malloc(sizeof(struct ast_type_index_s));
				ast_container[index].length = 1;
			} else {
				tmp = length + 1;
				ast_container[index].object = realloc(ast_container[index].object, tmp * sizeof(struct ast_type_index_s));
				ast_container[index].length = tmp;
			}
			ast_container[index].object[length].type = type;
			ast_container[index].object[length].index = node;
			if (nodes[node].next_size > 0) {
				ast_entry[entry].sub_index = ast_container[index].length;
				ast_entry[entry].node = nodes[node].link_next[0].node;
				if (ast_entry[entry].node == ast_entry[entry].node_end) {
					ast_entry[entry].type = AST_TYPE_EMPTY;
				}
			} else {
				ast_entry[entry].type = AST_TYPE_EMPTY;
			}
			break;
		case AST_TYPE_LOOP:
			/* node_end will == loop_head node. */
			/* This is valid no matter how many loop edges there are */
			debug_print(DEBUG_MAIN, 1, "AST_TYPE_LOOP type = 0x%x, node = 0x%x\n", type, node);
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				debug_print(DEBUG_MAIN, 1, "failed type != 2\n");
				exit(1);
			}
			ast_loop[loop_index].first_node.type = AST_TYPE_NODE;
			ast_loop[loop_index].first_node.index = node;
			length = ast_container[index].length;
			if (0 == length) {
				ast_container[index].object = malloc(sizeof(struct ast_type_index_s));
				ast_container[index].length = 1;
			} else {
				tmp = length + 1;
				ast_container[index].object = realloc(ast_container[index].object, tmp * sizeof(struct ast_type_index_s));
				ast_container[index].length = tmp;
			}
			ast_container[index].object[length].type = type;
			ast_container[index].object[length].index = loop_index;
			//ast_loop[loop_index].expression_node.type = AST_TYPE_NODE;
			//ast_loop[loop_index].expression_node.index = node;
			/* Default to an empty body. This covers the edge to self case */
			ast_loop[loop_index].body.type = AST_TYPE_EMPTY;
			ast_loop[loop_index].body.index = 0;

			if (nodes[node].link_next[0].is_normal) {
				debug_print(DEBUG_MAIN, 1, "Creating loop container 0x%x\n", container_index);
				ast_loop[loop_index].body.type = AST_TYPE_CONTAINER;
				ast_loop[loop_index].body.index = container_index;
				tmp = find_empty_ast_entry(ast_entry, &tmp_entry);
				ast_entry[tmp_entry].type = AST_TYPE_CONTAINER;
				ast_entry[tmp_entry].sub_type = 0; /* for normal container */
				ast_entry[tmp_entry].index = container_index;
				ast_entry[tmp_entry].sub_index = 0;
				ast_entry[tmp_entry].node = nodes[node].link_next[0].node;
				ast_entry[tmp_entry].node_end = node;
				container_index++;
				if (container_index >= AST_SIZE) { 
					debug_print(DEBUG_MAIN, 1, "container_index too large 4\n");
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			if (nodes[node].link_next[1].is_normal) {
				debug_print(DEBUG_MAIN, 1, "Creating loop container 0x%x\n", container_index);
				ast_loop[loop_index].body.type = AST_TYPE_CONTAINER;
				ast_loop[loop_index].body.index = container_index;
				/* FIXME: Only add this if the container first node != if_tail */
				tmp = find_empty_ast_entry(ast_entry, &tmp_entry);
				ast_entry[tmp_entry].type = AST_TYPE_CONTAINER;
				ast_entry[tmp_entry].sub_type = 0; /* for normal container */
				ast_entry[tmp_entry].index = container_index;
				ast_entry[tmp_entry].sub_index = 0;
				ast_entry[tmp_entry].node = nodes[node].link_next[1].node;
				ast_entry[tmp_entry].node_end = node;
				container_index++;
				if (container_index >= AST_SIZE) { 
					debug_print(DEBUG_MAIN, 1, "container_index too large 5 node = 0x%x, if_tail = 0x%x\n", node, nodes[node].if_tail);
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			ast_entry[entry].sub_index = ast_container[index].length;
			ast_entry[entry].node = nodes[node].if_tail;

			loop_index++;
			if (loop_index >= AST_SIZE) { 
				debug_print(DEBUG_MAIN, 1, "loop_index too large\n");
				ret = 1;
				goto exit_cfg_to_ast;
			}
			break;
		case AST_TYPE_LOOP_THEN_ELSE:
			/* FIXME: Need to expand this into two containers.
			 *	A LOOP Container and an if_then_else container.
			 */
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				debug_print(DEBUG_MAIN, 1, "failed type != 2\n");
				exit(1);
			}
			length = ast_container[index].length;
			if (0 == length) {
				ast_container[index].object = malloc(sizeof(struct ast_type_index_s));
				ast_container[index].length = 1;
				debug_print(DEBUG_MAIN, 1, "Add object 0x%x to container 0x%x\n", ast_container[index].length - 1, index);
			} else {
				tmp = length + 1;
				ast_container[index].object = realloc(ast_container[index].object, tmp * sizeof(struct ast_type_index_s));
				ast_container[index].length = tmp;
				debug_print(DEBUG_MAIN, 1, "Add object 0x%x to container 0x%x\n", ast_container[index].length - 1, index);
			}
			/* Create two containers. The loop_container, and inside the loop_container, the if_then_else */
			ast_container[index].object[length].type = AST_TYPE_CONTAINER;
			ast_container[index].object[length].index = container_index;
			debug_print(DEBUG_MAIN, 1, "ast_container[0x%x].object[0x%x] set to AST_TYPE_CONTAINER and index = 0x%x\n",
				index, length, container_index);
			debug_print(DEBUG_MAIN, 1, "JCD: container_index 0x%x, index 0x%x, length 0x%x  container_length 0x%x\n",
				container_index, index, length, ast_container[index].length);
			ast_container[index + 1].object = malloc(sizeof(struct ast_type_index_s));
			ast_container[index + 1].length = 1;
			debug_print(DEBUG_MAIN, 1, "Add object 0x%x to container 0x%x\n", ast_container[index + 1].length - 1, index + 1);
			ast_container[index + 1].object[0].type = AST_TYPE_IF_THEN_ELSE;
			ast_container[index + 1].sub_type = 1;
			ast_container[index + 1].object[0].index = if_then_else_index;
			ast_container[index + 1].length = 1;
			ast_container[index + 1].start_node = node;
			ast_container[index + 1].parent.type = AST_TYPE_CONTAINER;
			ast_container[index + 1].parent.index = index;
			ast_container[index + 1].parent.offset = length; /* Point to the parent that points to us */
			debug_print(DEBUG_MAIN, 1, "ast_container[0x%x].object[0x%x] set to AST_TYPE_IF_THEN_ELSE and index = 0x%x\n",
				index + 1, 0, if_then_else_index);
			debug_print(DEBUG_MAIN, 1, "ast_container[0x%x].parent set to AST_TYPE_CONTAINER, 0x%x, 0x%x\n",
				index + 1, index, ast_container[index].length);
			container_index++;
			if (container_index >= AST_SIZE) { 
				debug_print(DEBUG_MAIN, 1, "container_index too large 2\n");
				ret = 1;
				goto exit_cfg_to_ast;
			}
			ast_if_then_else[if_then_else_index].parent.type = AST_TYPE_CONTAINER;
			ast_if_then_else[if_then_else_index].parent.index = index + 1 ;
			ast_if_then_else[if_then_else_index].parent.offset = 0; /* Point to the parent that points to us */
			ast_if_then_else[if_then_else_index].expression_node.type = AST_TYPE_NODE;
			ast_if_then_else[if_then_else_index].expression_node.index = node;
			/* Handle the loop_then path */
			if (!(nodes[node].next_size)) {
				ast_if_then_else[if_then_else_index].if_then.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[0].node == nodes[node].if_tail) {
				ast_if_then_else[if_then_else_index].if_then.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[0].is_loop_edge) {
				ast_if_then_else[if_then_else_index].if_then.type = AST_TYPE_EMPTY;
			} else {
				debug_print(DEBUG_MAIN, 1, "Creating loop_then container 0x%x\n", container_index);
				ast_if_then_else[if_then_else_index].if_then.type = AST_TYPE_CONTAINER;
				ast_if_then_else[if_then_else_index].if_then.index = container_index;
				tmp = find_empty_ast_entry(ast_entry, &tmp_entry);
				ast_entry[tmp_entry].type = AST_TYPE_CONTAINER;
				ast_entry[tmp_entry].sub_type = 0; /* for normal container */
				ast_entry[tmp_entry].index = container_index;
				ast_entry[tmp_entry].sub_index = 0;
				ast_entry[tmp_entry].node = nodes[node].link_next[0].node;
				ast_entry[tmp_entry].node_end = nodes[node].if_tail;
				container_index++;
				if (container_index >= AST_SIZE) { 
					debug_print(DEBUG_MAIN, 1, "container_index too large 3\n");
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			/* Handle the loop_else path */
			if (!(nodes[node].next_size)) {
				ast_if_then_else[if_then_else_index].if_else.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[1].node == nodes[node].if_tail) {
				ast_if_then_else[if_then_else_index].if_else.type = AST_TYPE_EMPTY;
			} else if (nodes[node].link_next[1].is_loop_edge) {
				ast_if_then_else[if_then_else_index].if_else.type = AST_TYPE_EMPTY;
			} else {
				debug_print(DEBUG_MAIN, 1, "Creating loop_else container 0x%x\n", container_index);
				ast_if_then_else[if_then_else_index].if_else.type = AST_TYPE_CONTAINER;
				ast_if_then_else[if_then_else_index].if_else.index = container_index;
				tmp = find_empty_ast_entry(ast_entry, &tmp_entry);
				ast_entry[tmp_entry].type = AST_TYPE_CONTAINER;
				ast_entry[tmp_entry].sub_type = 0; /* for normal container */
				ast_entry[tmp_entry].index = container_index;
				ast_entry[tmp_entry].sub_index = 0;
				ast_entry[tmp_entry].node = nodes[node].link_next[1].node;
				ast_entry[tmp_entry].node_end = nodes[node].if_tail;
				container_index++;
				if (container_index >= AST_SIZE) { 
					debug_print(DEBUG_MAIN, 1, "container_index too large 2\n");
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			if (!is_member_of_loop(nodes, node, nodes[node].if_tail)) {
//			if (nodes[node].if_tail == ast_entry[entry].node_end) {
				debug_print(DEBUG_MAIN, 1, "JCD: loop_container_node NOT 0x%x, 0x%x\n", node, nodes[node].if_tail);
				ast_entry[entry].type = AST_TYPE_EMPTY;
			} else {
				debug_print(DEBUG_MAIN, 1, "JCD: loop_container_node = 0x%x\n", nodes[node].if_tail);
				ast_entry[entry].type = AST_TYPE_CONTAINER;
				ast_entry[entry].sub_type = 1; /* for LOOP container */
				ast_entry[entry].index = index + 1;
				ast_entry[entry].sub_index = ast_container[index + 1].length;
				ast_entry[entry].node = nodes[node].if_tail;
				ast_entry[entry].node_end = 0; /* Unknown */
			}
			/* Fixme, set this to the end of the if_then_else bit,
			 * and check that it is still inside the loop_container */
			//ast_entry[entry].type = AST_TYPE_EMPTY;

			if_then_else_index++;
			if (if_then_else_index >= AST_SIZE) {
				debug_print(DEBUG_MAIN, 1, "if_then_else_index too large\n");
				ret = 1;
				goto exit_cfg_to_ast;
			}
#if 0
			loop_container_index++;
			if (loop_container_index >= AST_SIZE) {
				debug_print(DEBUG_MAIN, 1, "loop_container_index too large\n");
				exit(1);
			}
#endif
			break;
		case AST_TYPE_LOOP_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "UNHANDLED LOOP_CONTAINER = 0x%x\n", type);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "UNHANDLED type = 0x%x\n", type);
			ast_entry[entry].type = AST_TYPE_EMPTY;
			break;
		}

		debug_print(DEBUG_MAIN, 1, "AFTER ast_entry entry = 0x%x\n", entry);
		debug_print(DEBUG_MAIN, 1, "ast_type = 0x%x\n", ast_entry[entry].type);
		debug_print(DEBUG_MAIN, 1, "ast_index = 0x%x\n", ast_entry[entry].index);
		debug_print(DEBUG_MAIN, 1, "ast_sub_index = 0x%x\n", ast_entry[entry].sub_index);
		debug_print(DEBUG_MAIN, 1, "ast_node = 0x%x\n", ast_entry[entry].node);
		debug_print(DEBUG_MAIN, 1, "ast_node_end = 0x%x\n", ast_entry[entry].node_end);

	} while(1);
exit_cfg_to_ast:
#if 0
	if (container_index >= AST_SIZE) {
		container_index = AST_SIZE - 1;
	}
	if (if_then_else_index >= AST_SIZE) {
		exit(1);
		if_then_else_index = AST_SIZE - 1;
	}
	if (if_then_goto_index >= AST_SIZE) {
		exit(1);
		if_then_goto_index = AST_SIZE - 1;
	}
	if (loop_index >= AST_SIZE) {
		exit(1);
		loop_index = AST_SIZE - 1;
	}
	if (loop_then_else_index >= AST_SIZE) {
		exit(1);
		loop_then_else_index = AST_SIZE - 1;
	}
	if (loop_container_index >= AST_SIZE) {
		exit(1);
		loop_container_index = AST_SIZE - 1;
	}
#endif
	ast->container_size = container_index;
	ast->if_then_else_size = if_then_else_index;
	ast->if_then_goto_size = if_then_goto_index;
	ast->loop_size = loop_index;
	ast->loop_then_else_size = loop_then_else_index;
	ast->loop_container_size = loop_container_index;
	return ret;
}

int print_ast(struct self_s *self, struct ast_s *ast) {
	struct ast_container_s *ast_container = ast->ast_container;
	struct ast_if_then_else_s *ast_if_then_else = ast->ast_if_then_else;
	struct ast_if_then_goto_s *ast_if_then_goto = ast->ast_if_then_goto;
	struct ast_loop_s *ast_loop = ast->ast_loop;
	struct ast_loop_then_else_s *ast_loop_then_else = ast->ast_loop_then_else;
	//struct ast_entry_s *ast_entry = ast->ast_entry;
	int container_index = ast->container_size;
	int if_then_else_index = ast->if_then_else_size;
	int if_then_goto_index = ast->if_then_goto_size;
	int loop_index = ast->loop_size;
	int loop_then_else_index = ast->loop_then_else_size;
	//int n;
	int m;
	int tmp;

	debug_print(DEBUG_MAIN, 1, "AST OUTPUT\n");
	for (m = 0; m < container_index; m++) {
		debug_print(DEBUG_MAIN, 1, "ast_container[%d]", m);
		if (m >= AST_SIZE) {
			break;
		}
		print_ast_container(&ast_container[m]);
	}
	for (m = 0; m < if_then_else_index; m++) {
		int type;
		debug_print(DEBUG_MAIN, 1, "parent = 0x%x, 0x%"PRIx64", 0x%x\n",
			ast_if_then_else[m].parent.type,
			ast_if_then_else[m].parent.index,
			ast_if_then_else[m].parent.offset);
		if (m >= AST_SIZE) {
			break;
		}
		type = ast_if_then_else[m].expression_node.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else expression_node empty\n");
			break;
		case AST_TYPE_NODE:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].expression_node.type = 0x%x\n", m, ast_if_then_else[m].expression_node.type);
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].expression_node.index = 0x%"PRIx64"\n", m, ast_if_then_else[m].expression_node.index);
			break;
		case AST_TYPE_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].expression_node\n", m);
			tmp = ast_if_then_else[m].expression_node.index;
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else expression_node default\n");
			break;
		}
		type = ast_if_then_else[m].if_then.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else if_then empty\n");
			break;
		case AST_TYPE_NODE:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].if_then.type = 0x%x\n", m, ast_if_then_else[m].if_then.type);
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].if_then.index = 0x%"PRIx64"\n", m, ast_if_then_else[m].if_then.index);
			break;
		case AST_TYPE_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].if_then\n", m);
			tmp = ast_if_then_else[m].if_then.index;
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else if_then default\n");
			break;
		}
		type = ast_if_then_else[m].if_else.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else if_else empty\n");
			break;
		case AST_TYPE_NODE:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].if_else.type = 0x%x\n", m, ast_if_then_else[m].if_else.type);
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].if_else.index = 0x%"PRIx64"\n", m, ast_if_then_else[m].if_else.index);
			break;
		case AST_TYPE_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else[%d].if_else\n", m);
			tmp = ast_if_then_else[m].if_else.index;
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_else if_else default\n");
			break;
		}
	}
	for (m = 0; m < if_then_goto_index; m++) {
		int type;
		debug_print(DEBUG_MAIN, 1, "parent = 0x%x, 0x%"PRIx64", 0x%x\n",
			ast_if_then_goto[m].parent.type,
			ast_if_then_goto[m].parent.index,
			ast_if_then_goto[m].parent.offset);
		if (m >= AST_SIZE) {
			break;
		}
		type = ast_if_then_goto[m].expression_node.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto expression_node empty\n");
			break;
		case AST_TYPE_NODE:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto[%d].expression_node.type = 0x%x\n", m, ast_if_then_goto[m].expression_node.type);
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto[%d].expression_node.index = 0x%"PRIx64"\n", m, ast_if_then_goto[m].expression_node.index);
			break;
		case AST_TYPE_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto[%d].expression_node\n", m);
			tmp = ast_if_then_goto[m].expression_node.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto expression_node default\n");
			break;
		}
		type = ast_if_then_goto[m].if_then_goto.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto if_then empty\n");
			break;
		case AST_TYPE_NODE:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto[%d].if_then_goto.type = 0x%x\n", m, ast_if_then_goto[m].if_then_goto.type);
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto[%d].if_then_goto.index = 0x%"PRIx64"\n", m, ast_if_then_goto[m].if_then_goto.index);
			break;
		case AST_TYPE_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto[%d].if_then_goto\n", m);
			tmp = ast_if_then_goto[m].if_then_goto.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "ast_if_then_goto if_then_goto default\n");
			break;
		}
	}
	for (m = 0; m < loop_index; m++) {
		debug_print(DEBUG_MAIN, 1, "ast_loop[%d].body\n", m);
		if (m >= AST_SIZE) {
			break;
		}
		tmp = ast_loop[m].body.index;
		if (tmp >= AST_SIZE) {
			break;
		}
		print_ast_container(&ast_container[tmp]);
	}
	for (m = 0; m < loop_then_else_index; m++) {
		int type;
		if (m >= AST_SIZE) {
			break;
		}
		type = ast_loop_then_else[m].expression_node.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else expression_node empty\n");
			break;
		case AST_TYPE_NODE:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].expression_node.type = 0x%x\n", m, ast_loop_then_else[m].expression_node.type);
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].expression_node.index = 0x%"PRIx64"\n", m, ast_loop_then_else[m].expression_node.index);
			break;
		case AST_TYPE_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].expression_node\n", m);
			tmp = ast_loop_then_else[m].expression_node.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else expression_node default\n");
			break;
		}
		type = ast_loop_then_else[m].loop_then.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else loop_then empty\n");
			break;
		case AST_TYPE_NODE:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].loop_then.type = 0x%x\n", m, ast_loop_then_else[m].loop_then.type);
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].loop_then.index = 0x%"PRIx64"\n", m, ast_loop_then_else[m].loop_then.index);
			break;
		case AST_TYPE_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].loop_then\n", m);
			tmp = ast_loop_then_else[m].loop_then.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else loop_then default\n");
			break;
		}
		type = ast_loop_then_else[m].loop_else.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else loop_else empty\n");
			break;
		case AST_TYPE_NODE:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].loop_else.type = 0x%x\n", m, ast_loop_then_else[m].loop_else.type);
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].loop_else.index = 0x%"PRIx64"\n", m, ast_loop_then_else[m].loop_else.index);
			break;
		case AST_TYPE_CONTAINER:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else[%d].loop_else\n", m);
			tmp = ast_loop_then_else[m].loop_else.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "ast_loop_then_else loop_else default\n");
			break;
		}
	}
	return 0;
}

/* Search the used register table for the value ID to use. */
int get_value_id_from_node_reg(struct self_s *self, int entry_point, int node, int reg, int *value_id)
{
	struct control_flow_node_s *nodes =  self->nodes;
	int inst;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct instruction_s *instruction;
	int ret = 0;

	*value_id = 0;
	printf("get_value:node:0x%x, reg:0x%x\n", node, reg);
	if (node < 1) {
		*value_id = self->external_entry_points[entry_point].param_reg_label[reg];
		printf("get_value:value_id:0x%x\n", *value_id);
		return 0;
	}
	inst = nodes[node].used_register[reg].dst;
	printf("inst:0x%x\n", inst);
	inst_log1 = &inst_log_entry[inst];
	instruction =  &inst_log1->instruction;
	switch (instruction->opcode) {
	case MOV:
	case ADD:
	case ADC:
	case SUB:
	case SBB:
	case MUL:
	case IMUL:
	case OR:
	case XOR:
	case rAND:
	case NOT:
	case NEG:
	case SHL:
	case SHR:
	case SAL:
	case SAR:
	case SEX:
		if ((instruction->dstA.store == STORE_REG) &&
			(instruction->dstA.indirect == IND_DIRECT)) {
			*value_id = inst_log1->value3.value_id;
			}
		break;
	/* DSTA = nothing, SRCA, SRCB == DSTA */
	case TEST:
	/* DSTA = nothing, SRCA, SRCB == DSTA */
	case CMP:
		ret = 1;
		break;
	/* DSTA = EAX, SRCN = parameters */
	case CALL:
		if ((instruction->dstA.store == STORE_REG) &&
			(instruction->dstA.indirect == IND_DIRECT)) {
			*value_id = inst_log1->value3.value_id;
			}
		break;
	case IF:
		/* This does nothing to the table */
		ret = 1;
		break;
	/* DSTA = nothing, SRCA, SRCB = nothing */
	case RET:
		ret = 1;
		break;
	/* DSTA = nothing, SRCN = nothing */
	case JMP:
		ret = 1;
		break;
	/* DSTA = nothing, SRCA = table index , but not known yet. = Pointer + 8 * index.
	 * Eventually it will be the label for the index */
	case JMPT:
		ret = 1;
		break;
	default:
		debug_print(DEBUG_MAIN, 1, "FIXME: get_value_id: unknown instruction OP 0x%x\n", instruction->opcode);
		ret = 1;
		break;
	}
	return ret;
}

int output_cfg_dot(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size,
                         struct label_redirect_s *label_redirect, struct label_s *labels, int entry_point)
{
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct process_state_s *process_state;
	char *filename;
	FILE *fd;
	int node;
	int tmp;
	int n;
	int m;
	int member;
	int block_end;
	int node_size_limited;
	const char *font = "graph.font";
	const char *color;
	const char *name;
	int value_id;

	if (external_entry_points[entry_point].member_nodes_size == 0) {
		debug_print(DEBUG_MAIN, 1, "external_entry_point 0x%x empty\n", entry_point);
		return 1;
	}
	filename = calloc(1024, sizeof(char));
	tmp = snprintf(filename, 1024, "./cfg/test-0x%04x-%s.dot", entry_point, external_entry_points[entry_point].name);

	fd = fopen(filename, "w");
	if (!fd) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%p\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".dot fd=%p\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out dot to file\n");
	tmp = fprintf(fd, "digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"%s\" fontsize=\"8\"];\n", font);
	node_size_limited = nodes_size;
#if 0
	if (node_size_limited > 50) {
		node_size_limited = 50;
	}
#endif
	for (member = 0; member < external_entry_points[entry_point].member_nodes_size; member++) {
		node = external_entry_points[entry_point].member_nodes[member];
//	for (node = 1; node <= node_size_limited; node++) {
#if 0
		if ((node != 0x13) && 
			(node != 0x14) && 
			(node != 0x15) && 
			(node != 0x16) && 
			(node != 0x17) &&
			(node != 0x123)) {
			continue;
		}
#endif
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		if (node == external_entry_points[nodes[node].entry_point - 1].start_node) {
			name = external_entry_points[nodes[node].entry_point - 1].name;
		} else {
			name = "";
		}
		tmp = fprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        node,
					node, "lightgray", node, name);
		tmp = fprintf(fd, "type = 0x%x\\l",
				nodes[node].type);
		if (nodes[node].if_tail) {
			tmp = fprintf(fd, "if_tail = 0x%x\\l",
				nodes[node].if_tail);
		}
		if (nodes[node].phi_size) {
			for (n = 0; n < nodes[node].phi_size; n++) {
				tmp = fprintf(fd, "phi[%d] = REG0x%x:0x%x ",
					n, nodes[node].phi[n].reg, nodes[node].phi[n].value_id);
				for (m = 0; m < nodes[node].phi[n].phi_node_size; m++) {
					tmp = get_value_id_from_node_reg(self, nodes[node].entry_point, nodes[node].phi[n].phi_node[m].node, nodes[node].phi[n].reg, &value_id);
					tmp = fprintf(fd, "FPN:0x%x:SN:0x%x:L:0x%x, ",
						nodes[node].phi[n].phi_node[m].first_prev_node,
						nodes[node].phi[n].phi_node[m].node,
						value_id);
				}
#if 0
				for (m = 0; m < nodes[node].path_size; m++) {
					tmp = fprintf(fd, "P0x%x:FPN:0x%x:SN:0x%x, ",
						nodes[node].phi[n].path_node[m].path,
						nodes[node].phi[n].path_node[m].first_prev_node,
						nodes[node].phi[n].path_node[m].node);
				}
				for (m = 0; m < nodes[node].looped_path_size; m++) {
					tmp = fprintf(fd, "LP0x%x:FPN:0x%x:SN:0x%x, ",
						nodes[node].phi[n].looped_path_node[m].path,
						nodes[node].phi[n].looped_path_node[m].first_prev_node,
						nodes[node].phi[n].looped_path_node[m].node);
				}
#endif
				tmp = fprintf(fd, "\\l");
			}
		}
		process_state = &external_entry_points[nodes[node].entry_point - 1].process_state;
		n = nodes[node].inst_start;
		block_end = 0;
		do {
			inst_log1 =  &inst_log_entry[n];
			instruction =  &inst_log1->instruction;
			//tmp = write_inst(self, fd, instruction, n, NULL);
			//tmp = fprintf(fd, "\\l");
			printf("output_cfg:Inst 0x%x: label1 = 0x%"PRIx64", label2 = 0x%"PRIx64", label3 = 0x%"PRIx64"\n",
				n,
				inst_log1->value1.value_id,
				inst_log1->value2.value_id,
				inst_log1->value3.value_id);
			tmp = output_inst_in_c(self, process_state, fd, n, label_redirect, labels, "\\l");
			//tmp = fprintf(fd, "\\l\n");
			if (inst_log1->node_end || !(inst_log1->next_size)) {
				block_end = 1;
			} else {
				n = inst_log1->next[0];
			}
		} while (!block_end);
		tmp = fprintf(fd, "\"];\n");
		for (n = 0; n < nodes[node].next_size; n++) {
			char *label;
			if (nodes[node].next_size < 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else {
					color = "blue";
				}
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color);
			} else if (nodes[node].next_size == 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else if (0 == n) {
					color = "red";
				} else {
					color = "green";
				}
				if (0 == n) {
					label = "false";
				} else {
					label = "true";
				}
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color, label);
			} else {
				/* next_size > 2 */
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"0x%x\"];\n",
					node, nodes[node].link_next[n].node, color, n);
			}
		}
	}
	tmp = fprintf(fd, "}\n");
	fclose(fd);
	return 0;
}

int output_cfg_dot_basic(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	char *filename;
	FILE *fd;
	int node;
	int tmp;
	int n;
	int node_size_limited;
	const char *font = "graph.font";
	const char *color;
	const char *name;

	filename = calloc(1024, sizeof(char));
	tmp = snprintf(filename, 1024, "./cfg/basic.dot");

	fd = fopen(filename, "w");
	if (!fd) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%p\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".dot fd=%p\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out dot to file\n");
	tmp = fprintf(fd, "digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"%s\" fontsize=\"8\"];\n", font);
	node_size_limited = nodes_size;

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		if (node == external_entry_points[nodes[node].entry_point - 1].start_node) {
			name = external_entry_points[nodes[node].entry_point - 1].name;
		} else {
			name = "";
		}
		tmp = fprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        node,
					node, "lightgray", node, name);
		tmp = fprintf(fd, "type = 0x%x\\l",
				nodes[node].type);
		if (nodes[node].if_tail) {
			tmp = fprintf(fd, "if_tail = 0x%x\\l",
				nodes[node].if_tail);
		}
		tmp = fprintf(fd, "\"];\n");

		for (n = 0; n < nodes[node].next_size; n++) {
			char *label;
			if (nodes[node].next_size < 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else {
					color = "blue";
				}
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color);
			} else if (nodes[node].next_size == 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else if (0 == n) {
					color = "red";
				} else {
					color = "green";
				}
				if (0 == n) {
					label = "false";
				} else {
					label = "true";
				}
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color, label);
			} else {
				/* next_size > 2 */
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"0x%x\"];\n",
					node, nodes[node].link_next[n].node, color, n);
			}
		}
	}
	tmp = fprintf(fd, "}\n");
	fclose(fd);
	return 0;
}

int output_cfg_dot_basic2(struct self_s *self, struct external_entry_point_s *external_entry_point)
{
	char *filename;
	FILE *fd;
	int node;
	int nodes_size = external_entry_point->nodes_size;
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	int tmp;
	int n;
	int node_size_limited;
	const char *font = "graph.font";
	const char *color;
	const char *name;

	filename = calloc(1024, sizeof(char));
	tmp = snprintf(filename, 1024, "./cfg/basic-%s.dot", external_entry_point->name);

	fd = fopen(filename, "w");
	if (!fd) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%p\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".dot fd=%p\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out dot to file\n");
	tmp = fprintf(fd, "digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"%s\" fontsize=\"8\"];\n", font);
	node_size_limited = nodes_size;

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		if (node == external_entry_point->start_node) {
			name = external_entry_point->name;
		} else {
			name = "";
		}
		tmp = fprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        node,
					node, "lightgray", node, name);
		tmp = fprintf(fd, "type = 0x%x\\l",
				external_entry_point->nodes[node].type);
		if (external_entry_point->nodes[node].if_tail) {
			tmp = fprintf(fd, "if_tail = 0x%x\\l",
				external_entry_point->nodes[node].if_tail);
		}
		tmp = fprintf(fd, "\"];\n");

		for (n = 0; n < external_entry_point->nodes[node].next_size; n++) {
			char *label;
			if (nodes[node].next_size < 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else {
					color = "blue";
				}
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color);
			} else if (nodes[node].next_size == 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else if (0 == n) {
					color = "red";
				} else {
					color = "green";
				}
				if (0 == n) {
					label = "false";
				} else {
					label = "true";
				}
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color, label);
			} else {
				/* next_size > 2 */
				tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"0x%x\"];\n",
					node, nodes[node].link_next[n].node, color, n);
			}
		}
	}
	tmp = fprintf(fd, "}\n");
	fclose(fd);
	return 0;
}

int output_ast_dot(struct self_s *self, struct ast_s *ast, struct control_flow_node_s *nodes, int *node_size)
{
	struct ast_container_s *ast_container = ast->ast_container;
	struct ast_if_then_else_s *ast_if_then_else = ast->ast_if_then_else;
	struct ast_if_then_goto_s *ast_if_then_goto = ast->ast_if_then_goto;
	struct ast_loop_s *ast_loop = ast->ast_loop;
	struct ast_loop_then_else_s *ast_loop_then_else = ast->ast_loop_then_else;
	struct ast_loop_container_s *ast_loop_container = ast->ast_loop_container;
	//struct ast_entry_s *ast_entry = ast->ast_entry;
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	int container_index = ast->container_size;
	int if_then_else_index = ast->if_then_else_size;
	int if_then_goto_index = ast->if_then_goto_size;
	int loop_index = ast->loop_size;
	int loop_then_else_index = ast->loop_then_else_size;
	int loop_container_index = ast->loop_container_size;
	char *filename;
	FILE *fd;
	int start_node;
	int tmp;
	int index;
	int n;
	int m;
	//int container;
	const char *font = "graph.font";
	const char *color;
	const char *name;
	filename = "test-ast.dot";

	fd = fopen(filename, "w");
	if (!fd) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%p\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".dot fd=%p\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out dot to file\n");
	tmp = fprintf(fd, "digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"%s\" fontsize=\"8\"];\n", font);
	for (n = 0; n < container_index; n++) {
		if (n >= AST_SIZE) {
			break;
		}
		start_node = ast_container[n].start_node;
		if (start_node && nodes[start_node].entry_point) {
			name = external_entry_points[nodes[start_node].entry_point - 1].name;
		} else {
			name = "";
		}
		tmp = fprintf(fd, " \"Container:0x%08x\" ["
                                        "URL=\"Container:0x%08x\" color=\"%s\", label=\"Container:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = fprintf(fd, "\"]\n");
		name = "";
		for (m = 0; m < ast_container[n].length; m++) {
			index = ast_container[n].object[m].index;
			switch (ast_container[n].object[m].type) {
			case AST_TYPE_NODE:
				tmp = fprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        index,
					index, "lightgray", index, name);
				tmp = fprintf(fd, "\"]\n");
				color = "red";
				tmp = fprintf(fd, "\"Container:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_CONTAINER:
				color = "blue";
				tmp = fprintf(fd, "\"Container:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP_CONTAINER:
				color = "blue";
				tmp = fprintf(fd, "\"Container:0x%08x\" -> \"Loop_Container:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_IF_THEN_ELSE:
				color = "blue";
				tmp = fprintf(fd, "\"Container:0x%08x\" -> \"if_then_else:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_IF_THEN_GOTO:
				color = "blue";
				tmp = fprintf(fd, "\"Container:0x%08x\" -> \"if_then_goto:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP:
				color = "blue";
				tmp = fprintf(fd, "\"Container:0x%08x\" -> \"loop:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP_THEN_ELSE:
				color = "blue";
				tmp = fprintf(fd, "\"Container:0x%08x\" -> \"loop_then_else:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			default:
				break;
			}
		}
	}
	for (n = 0; n < loop_container_index; n++) {
		if (n >= AST_SIZE) {
			break;
		}
		start_node = ast_loop_container[n].start_node;
		if (start_node && nodes[start_node].entry_point) {
			name = external_entry_points[nodes[start_node].entry_point - 1].name;
		} else {
			name = "";
		}
		tmp = fprintf(fd, " \"Loop_Container:0x%08x\" ["
                                        "URL=\"Loop_Container:0x%08x\" color=\"%s\", label=\"Loop_Container:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = fprintf(fd, "\"]\n");
		name = "";
		for (m = 0; m < ast_loop_container[n].length; m++) {
			index = ast_loop_container[n].object[m].index;
			switch (ast_loop_container[n].object[m].type) {
			case AST_TYPE_NODE:
				tmp = fprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        index,
					index, "lightgray", index, name);
				tmp = fprintf(fd, "\"]\n");
				color = "red";
				tmp = fprintf(fd, "\"Loop_Container:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_CONTAINER:
				break;
			case AST_TYPE_LOOP_CONTAINER:
				color = "blue";
				tmp = fprintf(fd, "\"Loop_Container:0x%08x\" -> \"Loop_container:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_IF_THEN_ELSE:
				color = "blue";
				tmp = fprintf(fd, "\"Loop_Container:0x%08x\" -> \"if_then_else:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_IF_THEN_GOTO:
				color = "blue";
				tmp = fprintf(fd, "\"Loop_Container:0x%08x\" -> \"if_then_goto:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP:
				color = "blue";
				tmp = fprintf(fd, "\"Loop_Container:0x%08x\" -> \"loop:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP_THEN_ELSE:
				color = "blue";
				tmp = fprintf(fd, "\"Loop_Container:0x%08x\" -> \"loop_then_else:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			default:
				break;
			}
		}
	}
	for (n = 0; n < if_then_else_index; n++) {
		if (n >= AST_SIZE) {
			break;
		}
		name = "";
		tmp = fprintf(fd, " \"if_then_else:0x%08x\" ["
                                        "URL=\"if_then_else:0x%08x\" color=\"%s\", label=\"if_then_else:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = fprintf(fd, "\"]\n");
		index = ast_if_then_else[n].expression_node.index;
		switch (ast_if_then_else[n].expression_node.type) {
		case AST_TYPE_NODE:
			color = "gold";
			tmp = fprintf(fd, "\"if_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "gold";
			tmp = fprintf(fd, "\"if_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_if_then_else[n].if_then.index;
		switch (ast_if_then_else[n].if_then.type) {
		case AST_TYPE_NODE:
			color = "green";
			tmp = fprintf(fd, "\"if_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "green";
			tmp = fprintf(fd, "\"if_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_if_then_else[n].if_else.index;
		switch (ast_if_then_else[n].if_else.type) {
		case AST_TYPE_NODE:
			color = "red";
			debug_print(DEBUG_MAIN, 1, "if_then_else:0x%x TYPE_NODE \n", n);
			tmp = fprintf(fd, "\"if_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "red";
			debug_print(DEBUG_MAIN, 1, "if_then_else:0x%x TYPE_CONTAINER \n", n);
			tmp = fprintf(fd, "\"if_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "if_then_else:0x%x TYPE 0x%x UNKNOWN \n", n, ast_if_then_else[n].if_else.type);
			break;
		}
	}
	for (n = 0; n < if_then_goto_index; n++) {
		if (n >= AST_SIZE) {
			break;
		}
		name = "";
		tmp = fprintf(fd, " \"if_then_goto:0x%08x\" ["
                                        "URL=\"if_then_goto:0x%08x\" color=\"%s\", label=\"if_then_goto:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = fprintf(fd, "\"]\n");
		index = ast_if_then_goto[n].expression_node.index;
		switch (ast_if_then_goto[n].expression_node.type) {
		case AST_TYPE_NODE:
			color = "gold";
			tmp = fprintf(fd, "\"if_then_goto:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "gold";
			tmp = fprintf(fd, "\"if_then_goto:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_if_then_goto[n].if_then_goto.index;
		switch (ast_if_then_goto[n].if_then_goto.type) {
		case AST_TYPE_NODE:
			color = "green";
			tmp = fprintf(fd, "\"if_then_goto:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "green";
			tmp = fprintf(fd, "\"if_then_goto:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
	}
	for (n = 0; n < loop_index; n++) {
		if (n >= AST_SIZE) {
			break;
		}
		name = "";
		tmp = fprintf(fd, " \"loop:0x%08x\" ["
                                        "URL=\"loop:0x%08x\" color=\"%s\", label=\"loop:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = fprintf(fd, "\"]\n");
		index = ast_loop[n].first_node.index;
		tmp = fprintf(fd, " \"Node:0x%08x\" ["
			"URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
			index,
			index, "lightgray", index, name);
		tmp = fprintf(fd, "\"]\n");
		color = "gold";
		tmp = fprintf(fd, "\"loop:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
			n, index, color);
		index = ast_loop[n].body.index;
		switch (ast_loop[n].body.type) {
		case AST_TYPE_NODE:
			color = "red";
			tmp = fprintf(fd, "\"loop:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "red";
			tmp = fprintf(fd, "\"loop:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_IF_THEN_ELSE:
			color = "blue";
			tmp = fprintf(fd, "\"loop:0x%08x\" -> \"if_then_else:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_LOOP:
			color = "blue";
			tmp = fprintf(fd, "\"loop:0x%08x\" -> \"loop:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
	}
	for (n = 0; n < loop_then_else_index; n++) {
		if (n >= AST_SIZE) {
			break;
		}
		name = "";
		tmp = fprintf(fd, " \"loop_then_else:0x%08x\" ["
                                        "URL=\"loop_then_else:0x%08x\" color=\"%s\", label=\"loop_then_else:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = fprintf(fd, "\"]\n");
		index = ast_loop_then_else[n].expression_node.index;
		switch (ast_loop_then_else[n].expression_node.type) {
		case AST_TYPE_NODE:
			color = "gold";
			tmp = fprintf(fd, "\"loop_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "gold";
			tmp = fprintf(fd, "\"loop_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_loop_then_else[n].loop_then.index;
		switch (ast_loop_then_else[n].loop_then.type) {
		case AST_TYPE_NODE:
			color = "green";
			tmp = fprintf(fd, "\"loop_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "green";
			tmp = fprintf(fd, "\"loop_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_loop_then_else[n].loop_else.index;
		switch (ast_loop_then_else[n].loop_else.type) {
		case AST_TYPE_NODE:
			color = "red";
			tmp = fprintf(fd, "\"loop_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "red";
			tmp = fprintf(fd, "\"loop_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
	}
#if 0
	for (n = 0; n < nodes[node].next_size; n++) {
		color = "blue";
		tmp = fprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
			node, nodes[node].link_next[n].node, color);
	}
#endif
	tmp = fprintf(fd, "}\n");
	fclose(fd);
	return 0;
}

int init_node_used_register_table(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	int node;
	for (node = 1; node <= nodes_size; node++) {
		nodes[node].used_register = calloc(MAX_REG, sizeof(struct node_used_register_s));
	}
	return 0;
}

int fill_node_used_register_table(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	int node;
	int inst;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct instruction_s *instruction;

	for (node = 1; node <= nodes_size; node++) {
		inst = nodes[node].inst_start;
		debug_print(DEBUG_MAIN, 1, "In Block:0x%x\n", node);
		do {
			debug_print(DEBUG_MAIN, 1, "inst:0x%x\n", inst);
			inst_log1 = &inst_log_entry[inst];
			instruction =  &inst_log1->instruction;
			switch (instruction->opcode) {
			case NOP:
				/* Nothing to do */
				break;
			/* DSTA, SRCA, SRCB == nothing */
			case MOV:
				/* If SRC and DST in same instruction, let SRC dominate. */
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1:0x%"PRIx64"\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1\n");
					}
				}
				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect != IND_DIRECT)) {
					/* This is a special case, where the dst register is indirect, so actually a src. */
					nodes[node].used_register[instruction->dstA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1D:0x%"PRIx64"\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 1;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						nodes[node].used_register[instruction->dstA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1D\n");
					}
				}

				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->dstA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "Seen2:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 2;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						debug_print(DEBUG_MAIN, 1, "Set2\n");
					}
				}
				break;
			/* DSTA, SRCA, SRCB == DSTA */
			case ADD:
			case ADC:
			case SUB:
			case SBB:
			case MUL:
			case IMUL:
			case OR:
			case XOR:
			case rAND:
			case NOT:
			case NEG:
			case SHL:
			case SHR:
			case SAL:
			case SAR:
			case SEX:
			case ICMP:
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1A:0x%"PRIx64", SRC\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1A\n");
					}
				}
				if ((instruction->srcB.store == STORE_REG) &&
					(instruction->srcB.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcB.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1B:0x%"PRIx64" SRC\n", instruction->srcB.index);
					if (nodes[node].used_register[instruction->srcB.index].seen == 0) {
						nodes[node].used_register[instruction->srcB.index].seen = 1;
						nodes[node].used_register[instruction->srcB.index].size = instruction->srcB.value_size;
						nodes[node].used_register[instruction->srcB.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1B\n");
					}
				}
				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->dstA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "Seen2:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 2;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						debug_print(DEBUG_MAIN, 1, "Set2\n");
					}
				}
				break;

			/* Specially handled because value3 is not assigned and writen to a destination. */
			/* DSTA = nothing, SRCA, SRCB == DSTA */
			case TEST:
			/* DSTA = nothing, SRCA, SRCB == DSTA */
			case CMP:
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					/* CMP and TEST do not have a dst */
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1A:0x%"PRIx64"\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1A\n");
					}
				}
				if ((instruction->srcB.store == STORE_REG) &&
					(instruction->srcB.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcB.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1B:0x%"PRIx64"\n", instruction->srcB.index);
					if (nodes[node].used_register[instruction->srcB.index].seen == 0) {
						nodes[node].used_register[instruction->srcB.index].seen = 1;
						nodes[node].used_register[instruction->srcB.index].size = instruction->srcB.value_size;
						nodes[node].used_register[instruction->srcB.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1B\n");
					}
				}
				break;

			/* DSTA = EAX, SRCN = parameters */
			case CALL:
				/* FIXME: TODO params */
				if ((instruction->dstA.store == STORE_REG) &&
					(instruction->dstA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->dstA.index].dst = inst;
					debug_print(DEBUG_MAIN, 1, "CALL Seen2:0x%"PRIx64", DST\n", instruction->dstA.index);
					if (nodes[node].used_register[instruction->dstA.index].seen == 0) {
						nodes[node].used_register[instruction->dstA.index].seen = 2;
						nodes[node].used_register[instruction->dstA.index].size = instruction->dstA.value_size;
						debug_print(DEBUG_MAIN, 1, "Set2\n");
					}
				}
				break;

			case IF:
				/* This does nothing to the table */
				break;
			case BC:
				/* Branch Conditional */
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					/* CMP and TEST do not have a dst */
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1A:0x%"PRIx64"\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1A\n");
					}
				}
			/* DSTA = nothing, SRCA, SRCB = nothing */
			case RET:
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT)) {
					nodes[node].used_register[instruction->srcA.index].src = inst;
					debug_print(DEBUG_MAIN, 1, "Seen1:0x%"PRIx64"\n", instruction->srcA.index);
					if (nodes[node].used_register[instruction->srcA.index].seen == 0) {
						nodes[node].used_register[instruction->srcA.index].seen = 1;
						nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
						nodes[node].used_register[instruction->srcA.index].src_first = inst;
						debug_print(DEBUG_MAIN, 1, "Set1\n");
					}
				}
				break;
			/* DSTA = nothing, SRCN = nothing */
			case JMP:
			/* DSTA = nothing, SRCA = table index , but not known yet. = Pointer + 8 * index.
			 * Eventually it will be the label for the index */
			case JMPT:
				if ((instruction->srcA.store == STORE_REG) &&
					(instruction->srcA.indirect == IND_DIRECT) &&
					(nodes[node].used_register[instruction->srcA.index].seen == 0)) {
					/* TODO: Add register src index here */
					debug_print(DEBUG_MAIN, 1, "Seen1:0x%"PRIx64" SET\n", instruction->srcA.index);
					nodes[node].used_register[instruction->srcA.index].seen = 1;
					nodes[node].used_register[instruction->srcA.index].size = instruction->srcA.value_size;
					nodes[node].used_register[instruction->srcA.index].src_first = inst;
				}
				break;
			default:
				debug_print(DEBUG_MAIN, 1, "FIXME: fill node used register table: unknown instruction OP 0x%x\n", instruction->opcode);
				return 1;
				break;
			}
		if (!inst_log1->node_end) {
			inst = inst_log1->next[0];
		}

        	} while (!(inst_log1->node_end));
	}
	return 0;
}

int search_back_for_join(struct control_flow_node_s *nodes, int nodes_size, int node, int *phi_node) 
{
	struct control_flow_node_s *this_node;

	*phi_node = 0;
	do {
		this_node = &(nodes[node]);
		if (this_node->prev_size > 1) {
			*phi_node = node;
			return 0;
		}
		if (this_node->prev_size == 1) {
			node = this_node->prev_node[0];
		}
	} while (node > 0 && this_node->prev_size == 1);

	return 1;
}

int add_phi_to_node(struct control_flow_node_s *node, int reg)
{
	int n;

	if (node->phi_size == 0) {
		node->phi = calloc(1, sizeof(struct phi_s));
		node->phi[0].reg = reg;
		node->phi[0].path_node_size = 0;
		node->phi_size = 1;
	} else {
		for (n = 0; n < node->phi_size; n++) {
			if (node->phi[n].reg == reg) {
				return 1;
			}
		}
		node->phi = realloc(node->phi, (node->phi_size + 1) * sizeof(struct phi_s));
		node->phi[node->phi_size].reg = reg;
		node->phi[node->phi_size].path_node_size = 0;
		node->phi_size++;
	}
	return 0;
}

/* Input: path to search in.
 *        node to search for.
 * Output: common base_path that the node is part of.
 *         common base_step that the node is part of.
 */
int path_node_to_base_path(struct self_s *self, struct path_s *paths, int paths_size, int path, int node, int *base_path, int *base_step)
{
	int step;
	int tmp;
	int ret;

	ret = 0;
	*base_path = path;
	step = paths[path].path_size - 1; /* convert size to index */
	*base_step = step;
	tmp = paths[path].path[step];
	if (tmp == node) {
		*base_path = path;
		ret = 0;
		goto exit_path_node_to_base_path;
	}
	while (1) {
		step--;
		if (step < 0) {
			/* If path_prev == path, we have reached the beginning of the path list */
			if (paths[path].path_prev != path) {
				tmp = paths[path].path_prev;
				step = paths[path].path_prev_index;
				path = tmp;
			} else {
				/* Node not found in path */
				ret = 1;
				break;
			}
		}
		tmp = paths[path].path[step];
		if (tmp == node) {
			*base_path = path;
			*base_step = step;
			ret = 0;
			break;
		}
	}
exit_path_node_to_base_path:
	return ret;
}

/* Input: path to search in.
 *        step to step back from.
	  node is the current node.
 * Output: prev_path that is the previous node.
 *         prev_step that is the previous node.
 *	   prev_node
 */
int find_prev_path_step_node(struct self_s *self, struct path_s *paths, int paths_size, int path, int step, int node, int *prev_path, int *prev_step, int *prev_node)
{
	int tmp;
	int ret;

	ret = 0;
	*prev_node = 0;
	*prev_path = 0;
	*prev_step = 0;
	/* Sanity checks */
	if (step > paths[path].path_size - 1) { /* convert size to index */
		ret = 1;
		goto exit_find_prev_path_step_node;
	}
	/* Sanity checks */
	if (path >= paths_size) {
		ret = 1;
		goto exit_find_prev_path_step_node;
	}
	/* Sanity checks */
	tmp = paths[path].path[step];
	if (tmp != node) {
		ret = 1;
		goto exit_find_prev_path_step_node;
	}

	step--;
	if (step < 0) {
		/* If path_prev == path, we have reached the beginning of the path list */
		if (paths[path].path_prev != path) {
			tmp = paths[path].path_prev;
			step = paths[path].path_prev_index;
			path = tmp;
		} else {
			/* finished following path */
			ret = 1;
			goto exit_find_prev_path_step_node;
		}
	}
	*prev_node = paths[path].path[step];
	*prev_path = path;
	*prev_step = step;

exit_find_prev_path_step_node:
	return ret;
}

int fill_node_phi_dst(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	int node;
	int phi_node;
	int n;
	int tmp;

	for (node = 1; node <= nodes_size; node++) {
		tmp = search_back_for_join(nodes, nodes_size, node, &phi_node);
		if (tmp) {
			/* No previous join node found */
			continue;
		}
		for (n = 0; n < MAX_REG; n++) {
			if (nodes[node].used_register[n].seen == 1) {
				debug_print(DEBUG_ANALYSE_PHI, 1, "Adding register 0x%x to phi_node 0x%x\n", n, phi_node);
				tmp = add_phi_to_node(&(nodes[phi_node]), n);
				debug_print(DEBUG_ANALYSE_PHI, 1, "Adding register 0x%x to phi_node 0x%x, status = %d\n", n, phi_node, tmp);
			}
		}
	}
	return 0;
}

int find_phi_src_node_reg(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct path_s *paths, int paths_size, int path, int step, int node, int reg, int *src_node, int *first_prev_node)
{
	int prev_path;
	int prev_step;
	int prev_node;
	int tmp = 0;
	int tmp2 = 0;
	int tmp_node;
	int ret = 1;
	int first = 1;
	int n;
	

	*src_node = 0;
	*first_prev_node = 0;
	tmp_node = node;
	while (tmp == 0) {
		tmp = find_prev_path_step_node(self, paths, paths_size, path, step, tmp_node, &prev_path, &prev_step, &prev_node);
		path = prev_path;
		step = prev_step;
		tmp_node = prev_node;
		if (first) {
			*first_prev_node = prev_node;
			first = 0;
		}
		if (tmp == 0) {
			/* Check used_registers of the prev_node. tmp2 points to the last instruction in the node/block */
			tmp2 = nodes[tmp_node].used_register[reg].dst;
			if (node <= 4) {
				debug_print(DEBUG_ANALYSE_PHI, 1, "phi_src:tmp = 0x%x, tmp2 = 0x%x, prev_path = 0x%x, prev_step = 0x%x, prev_node = 0x%x\n", tmp, tmp2, prev_path, prev_step, prev_node);
				}
			if (tmp2) {
				*src_node = tmp_node;
				ret = 0; /* Found */
				goto exit_find_phi_src_node_reg;
			}
			/* Check phi of the prev_node */
			for (n = 0; n < nodes[tmp_node].phi_size; n++) {
				if (nodes[tmp_node].phi[n].reg == reg) {
					*src_node = tmp_node;
					ret = 0; /* Found */
					debug_print(DEBUG_ANALYSE_PHI, 1, "FOUND PHI: node = 0x%x, src_node = 0x%x, reg = 0x%x\n", node, tmp_node, reg);
					goto exit_find_phi_src_node_reg;
				}
			}
		}
	}
exit_find_phi_src_node_reg:
	return ret;
}

int fill_node_phi_src(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	int path;
	int node;
	int tmp;
	int node_size_limited;
	int base_path;
	int base_step;
	int src_node;
	int first_prev_node;
	struct path_s *paths;
	int paths_size;
	int reg = 0;
	int n, m;
	struct external_entry_point_s *external_entry_points = self->external_entry_points;

	node_size_limited = nodes_size;
#if 0
	if (node_size_limited > 50) {
		node_size_limited = 50;
	}
#endif
	for (node = 1; node <= node_size_limited; node++) {
		if (nodes[node].phi_size > 0) {
			for (n = 0; n < nodes[node].phi_size; n++) {
				debug_print(DEBUG_ANALYSE_PHI, 1, "phi_src:node=0x%x, node->entry:0x%x, name=%s\n", node, nodes[node].entry_point,
					external_entry_points[nodes[node].entry_point - 1].name);
				paths = external_entry_points[nodes[node].entry_point - 1].paths;
				paths_size = external_entry_points[nodes[node].entry_point - 1].paths_size;
				debug_print(DEBUG_ANALYSE_PHI, 1, "phi_src:paths = %p, paths_size = 0x%x\n", paths, paths_size);
				reg = nodes[node].phi[n].reg;
				if (nodes[node].path_size > 0) {
					nodes[node].phi[n].path_node = calloc(nodes[node].path_size, sizeof(struct path_node_s));
					nodes[node].phi[n].path_node_size = nodes[node].path_size;
				} else {
					nodes[node].phi[n].path_node_size = 0;
				}
				if (nodes[node].looped_path_size > 0) {
					nodes[node].phi[n].looped_path_node = calloc(nodes[node].looped_path_size, sizeof(struct path_node_s));
					nodes[node].phi[n].looped_path_node_size = nodes[node].looped_path_size;
				} else {
					nodes[node].phi[n].looped_path_node_size = 0;
				}

				for (m = 0; m < nodes[node].path_size; m++) {
					path = nodes[node].path[m];
					tmp = path_node_to_base_path(self, paths, paths_size, path, node, &base_path, &base_step);
					debug_print(DEBUG_ANALYSE_PHI, 1, "path:tmp = %d, reg = 0x%x, base_path = 0x%x, base_step = 0x%x\n", tmp, reg, base_path, base_step);
					tmp = find_phi_src_node_reg(self, nodes, nodes_size, paths, paths_size, base_path, base_step, node, reg, &src_node, &first_prev_node);
					debug_print(DEBUG_ANALYSE_PHI, 1, "path:path = 0x%x, tmp = 0x%x, src_node = 0x%x, first_prev_node = 0x%x\n", path, tmp, src_node, first_prev_node);
					debug_print(DEBUG_ANALYSE_PHI, 1, "node = 0x%x, phi:n = 0x%x, path_node:m = 0x%x\n", node, n, m);
					nodes[node].phi[n].path_node[m].path = path;
					nodes[node].phi[n].path_node[m].first_prev_node = first_prev_node;
					nodes[node].phi[n].path_node[m].node = src_node;
					
				}
				for (m = 0; m < nodes[node].looped_path_size; m++) {
					path = nodes[node].looped_path[m];
					tmp = path_node_to_base_path(self, paths, paths_size, path, node, &base_path, &base_step);
					debug_print(DEBUG_ANALYSE_PHI, 1, "looped_path:tmp = %d, reg = 0x%x, base_path = 0x%x, base_step = 0x%x\n", tmp, reg, base_path, base_step);
					tmp = find_phi_src_node_reg(self, nodes, nodes_size, paths, paths_size, base_path, base_step, node, reg, &src_node, &first_prev_node);
					debug_print(DEBUG_ANALYSE_PHI, 1, "looped_path:path = 0x%x, tmp = 0x%x, src_node = 0x%x, first_prev_node = 0x%x\n", path, tmp, src_node, first_prev_node);
					debug_print(DEBUG_ANALYSE_PHI, 1, "node = 0x%x, phi:n = 0x%x, path_node:m = 0x%x\n", node, n, m);
					nodes[node].phi[n].looped_path_node[m].path = path;
					nodes[node].phi[n].looped_path_node[m].first_prev_node = first_prev_node;
					nodes[node].phi[n].looped_path_node[m].node = src_node;
				}
			}
		}
	}
		
	return 0;
}

int fill_phi_node_list(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	int node;
	int n;
	int m;
	int l;
	printf("fill_phi: entered\n");

	for (node = 1; node <= nodes_size; node++) {
		printf("node = 0x%x\n", node);
		if (nodes[node].phi_size > 0) {
			printf("phi_size = 0x%x, prev_size = 0x%x\n", nodes[node].phi_size, nodes[node].prev_size);
			for (n = 0; n < nodes[node].phi_size; n++) {
				nodes[node].phi[n].phi_node = calloc(nodes[node].prev_size, sizeof(struct phi_node_s));
				nodes[node].phi[n].phi_node_size = nodes[node].prev_size;
				for (m = 0; m < nodes[node].prev_size; m++) {
					printf("n = 0x%x, m = 0x%x\n", n, m);
					nodes[node].phi[n].phi_node[m].first_prev_node = nodes[node].prev_node[m];
					nodes[node].phi[n].phi_node[m].node = 0;
					nodes[node].phi[n].phi_node[m].path_count = 0;
					nodes[node].phi[n].phi_node[m].value_id = 0;
					for (l = 0; l < nodes[node].phi[n].path_node_size; l++) {
						if (nodes[node].phi[n].path_node[l].first_prev_node == nodes[node].phi[n].phi_node[m].first_prev_node) {
							if ((nodes[node].phi[n].phi_node[m].path_count > 0) &&
								(nodes[node].phi[n].phi_node[m].node != nodes[node].phi[n].path_node[l].node)) {
								printf("FAILED at node 0x%x, phi_node = 0x%x, path_node = 0x%x\n",
									node,
									nodes[node].phi[n].phi_node[m].node,
									nodes[node].phi[n].path_node[l].node);
							}
							nodes[node].phi[n].phi_node[m].node = 
								nodes[node].phi[n].path_node[l].node;
							nodes[node].phi[n].phi_node[m].path_count++;
						}
					}
					for (l = 0; l < nodes[node].phi[n].looped_path_node_size; l++) {
						if (nodes[node].phi[n].looped_path_node[l].first_prev_node == nodes[node].phi[n].phi_node[m].first_prev_node) {
							nodes[node].phi[n].phi_node[m].node = 
								nodes[node].phi[n].looped_path_node[l].node;
							nodes[node].phi[n].phi_node[m].path_count++;
						}
					}
					printf("fill_phi: first_prev_node = 0x%x, node = 0x%x, path_count = 0x%x\n",
						nodes[node].phi[n].phi_node[m].first_prev_node,
						nodes[node].phi[n].phi_node[m].node,
						nodes[node].phi[n].phi_node[m].path_count);
				}
			}
		}
	}
	printf("fill_phi: exit\n");
	return 0;
}

int find_reg_in_phi_list(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, int node, int reg, int *value_id)
{
	int n;
	int ret = 1;

	*value_id = 0;
	for (n = 0; n < nodes[node].phi_size; n++) {
		if (nodes[node].phi[n].reg == reg) {
			ret = 0;
			*value_id = nodes[node].phi[n].value_id;
			break;
		}
	}
	return ret;
}

/* Not need any more as it is built earler without needing the paths */
#if 0
int build_entry_point_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point, int nodes_size)
{
	int *nodes;
	int members_size;
	int members_offset;
	int n, m;
	nodes = calloc(nodes_size + 1, sizeof(int));
	if (!nodes) {
		return 1;
	}
	for (n = 0; n < external_entry_point->paths_size; n++) {
		for (m = 0; m < external_entry_point->paths[n].path_size; m++) {
			nodes[external_entry_point->paths[n].path[m]] = 1;
		}
	}	
	for (n = 0; n < external_entry_point->paths_size; n++) {
		for (m = 0; m < external_entry_point->paths[n].path_size; m++) {
			nodes[external_entry_point->paths[n].path[m]] = 1;
		}
	}
	members_size = 0;
	for (n = 0; n <= nodes_size; n++) {
		if (nodes[n] == 1) {
			members_size++;
		}
	}
	external_entry_point->member_nodes = calloc(members_size, sizeof(int));
	external_entry_point->member_nodes_size = members_size;
	members_offset = 0;
	for (n = 0; n <= nodes_size; n++) {
		if (nodes[n] == 1) {
			external_entry_point->member_nodes[members_offset] = n;
			members_offset++;
		}
	}
	free(nodes);
	return 0;
}
#endif

int print_entry_point_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point)
{
	int n;

	printf("Members of function %s\n", external_entry_point->name);
	for (n = 0; n < external_entry_point->member_nodes_size; n++) {
		printf("0x%x ", external_entry_point->member_nodes[n]);
	}
	printf("\n");
	return 0;
}

/* FIXME: Implement */
int search_back_for_register(struct self_s *self, int l, int node, int inst, int source,
						struct label_s *label, int *new_label) {
	/* 1) search back from this instruction until the beginning of the node */
	/* 2) search the PHI instructions for the register. */
	/* 3) search for a previous node. This is only needed is special cases, i.e. only one previous node.
		The step (2) PHI should have taken care of the more than one previous node.
		This step (3) is unlikely to occur. */
	/* 4) reached the beginning of the function. Previous nodes == 0. label it as a param. */
	
	return 0;
}


int assign_labels_to_src(struct self_s *self, int *label_id)
{
	struct control_flow_node_s *nodes = self->nodes;
	int nodes_size = self->nodes_size;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct label_redirect_s *label_redirect = self->label_redirect;
	struct label_s *labels = self->labels;
	int n;
	int m;
	struct inst_log_entry_s *inst_log1;
	struct instruction_s *instruction;
	int variable_id = *label_id;

	for (n = 1; n <= nodes_size; n++) {
		int inst;
		int node;
		struct label_s label;
		int found = 0;
		int reg_tracker[MAX_REG];
		node = n;
		/* Initialise the reg_tracker at each node */
		for (m = 0; m < MAX_REG; m++) {
			if (nodes[node].used_register[m].seen == 1) {
				reg_tracker[m] = nodes[node].used_register[m].src_first_value_id;
				debug_print(DEBUG_MAIN, 1, "Node 0x%x: reg 0x%x given value_id = 0x%x\n", node, m,
					reg_tracker[m]);
			} else {
				reg_tracker[m] = 0;
				//debug_print(DEBUG_MAIN, 1, "Node 0x%x: reg 0x%x given value_id no value\n", node, m);
			}
		}

		inst = nodes[node].inst_start;
		do {
			inst_log1 =  &inst_log_entry[inst];
			instruction =  &inst_log1->instruction;
			switch (instruction->opcode) {
			case NOP:
				break;
			case MOV:
				switch (instruction->srcA.store) {
				case STORE_DIRECT:
					memset(&label, 0, sizeof(struct label_s));
					if (instruction->srcA.indirect == IND_MEM) {
						label.scope = 3;
						label.type = 1;
						label.lab_pointer = 1;
						label.value = instruction->dstA.index;
					} else if (instruction->srcA.relocated) {
						label.scope = 3;
						label.type = 2;
						label.lab_pointer = 0;
						label.value = instruction->dstA.index;
					} else {
						label.scope = 3;
						label.type = 3;
						label.lab_pointer = 0;
						label.value = instruction->srcA.index;
					}
					
					inst_log1->value1.value_id = variable_id;
					label_redirect[variable_id].redirect = variable_id;
					labels[variable_id].scope = label.scope;
					labels[variable_id].type = label.type;
					labels[variable_id].lab_pointer += label.lab_pointer;
					labels[variable_id].value = label.value;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA direct given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value1.value_id); 
					variable_id++;
					break;
				case STORE_REG:
					/* FIXME: TODO*/
					inst_log1->value1.value_id = 
						reg_tracker[instruction->srcA.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value1.value_id); 
					break;
				}
				switch (instruction->dstA.store) {
				case STORE_DIRECT:
					break;
				case STORE_REG:
					reg_tracker[instruction->dstA.index] = inst_log1->value3.value_id;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: reg 0x%"PRIx64" given value_id = 0x%"PRIx64"\n", inst,
						instruction->dstA.index,
						inst_log1->value3.value_id); 
					break;
				}
				break;
			case ADD:
			case ADC:
			case SUB:
			case SBB:
			case MUL:
			case IMUL:
			case OR:
			case XOR:
			case rAND:
			case NOT:
			case NEG:
			case SHL:
			case SHR:
			case SAL:
			case SAR:
			case SEX:
			case ICMP:
				switch (instruction->srcA.store) {
				case STORE_DIRECT:
					memset(&label, 0, sizeof(struct label_s));
					if (instruction->srcA.indirect == IND_MEM) {
						label.scope = 3;
						label.type = 1;
						label.lab_pointer = 1;
						label.value = instruction->srcA.index;
					} else if (instruction->srcA.relocated) {
						label.scope = 3;
						label.type = 2;
						label.lab_pointer = 0;
						label.value = instruction->srcA.index;
					} else {
						printf("srcA.index = 0x%"PRIx64"\n", instruction->srcA.index);
						label.scope = 3;
						label.type = 3;
						label.lab_pointer = 0;
						label.value = instruction->srcA.index;
					}
					
					inst_log1->value1.value_id = variable_id;
					label_redirect[variable_id].redirect = variable_id;
					labels[variable_id].scope = label.scope;
					labels[variable_id].type = label.type;
					labels[variable_id].lab_pointer += label.lab_pointer;
					labels[variable_id].value = label.value;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA direct given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value1.value_id); 
					variable_id++;
					break;
				case STORE_REG:
					/* FIXME: TODO*/
					/* srcA */
					//tmp = search_back_for_register(self, l, node, inst, 0,
					//	&label, &new_label);
					inst_log1->value1.value_id = 
						reg_tracker[instruction->srcA.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value1.value_id); 
					break;
				}
				switch (instruction->srcB.store) {
				case STORE_DIRECT:
					memset(&label, 0, sizeof(struct label_s));
					if (instruction->srcB.indirect == IND_MEM) {
						label.scope = 3;
						label.type = 1;
						label.lab_pointer = 1;
						label.value = instruction->srcB.index;
					} else if (instruction->srcB.relocated) {
						label.scope = 3;
						label.type = 2;
						label.lab_pointer = 0;
						label.value = instruction->srcB.index;
					} else {
						label.scope = 3;
						label.type = 3;
						label.lab_pointer = 0;
						label.value = instruction->srcB.index;
					}
					
					inst_log1->value2.value_id = variable_id;
					label_redirect[variable_id].redirect = variable_id;
					labels[variable_id].scope = label.scope;
					labels[variable_id].type = label.type;
					labels[variable_id].lab_pointer += label.lab_pointer;
					labels[variable_id].value = label.value;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcB direct given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value2.value_id); 
					variable_id++;
					break;
				case STORE_REG:
					/* FIXME: TODO*/
					/* srcB */
					//search_back_for_register(self, l, node, inst, 1,
					//	&label, &new_label);
					inst_log1->value2.value_id = 
						reg_tracker[instruction->srcB.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcB given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value2.value_id); 
					break;
				}
				switch (instruction->dstA.store) {
				case STORE_DIRECT:
					break;
				case STORE_REG:
					reg_tracker[instruction->dstA.index] = inst_log1->value3.value_id;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: reg 0x%"PRIx64" given value_id = 0x%"PRIx64"\n", inst,
						instruction->dstA.index,
						inst_log1->value3.value_id); 
					break;
				}
				break;
			/* Specially handled because value3 is not assigned and writen to a destination. */
			case TEST:
			case CMP:
				/* FIXME: TODO*/
				switch (instruction->srcA.store) {
				case STORE_DIRECT:
					memset(&label, 0, sizeof(struct label_s));
					if (instruction->srcA.indirect == IND_MEM) {
						label.scope = 3;
						label.type = 1;
						label.lab_pointer = 1;
						label.value = instruction->srcA.index;
					} else if (instruction->srcA.relocated) {
						label.scope = 3;
						label.type = 2;
						label.lab_pointer = 0;
						label.value = instruction->srcA.index;
					} else {
						printf("srcA.index = 0x%"PRIx64"\n", instruction->srcA.index);
						label.scope = 3;
						label.type = 3;
						label.lab_pointer = 0;
						label.value = instruction->srcA.index;
					}
					
					inst_log1->value1.value_id = variable_id;
					label_redirect[variable_id].redirect = variable_id;
					labels[variable_id].scope = label.scope;
					labels[variable_id].type = label.type;
					labels[variable_id].lab_pointer += label.lab_pointer;
					labels[variable_id].value = label.value;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA direct given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value1.value_id); 
					variable_id++;
					break;
				case STORE_REG:
					/* FIXME: TODO*/
					/* srcA */
					//tmp = search_back_for_register(self, l, node, inst, 0,
					//	&label, &new_label);
					inst_log1->value1.value_id = 
						reg_tracker[instruction->srcA.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value1.value_id); 
					break;
				}
				switch (instruction->srcB.store) {
				case STORE_DIRECT:
					memset(&label, 0, sizeof(struct label_s));
					if (instruction->srcB.indirect == IND_MEM) {
						label.scope = 3;
						label.type = 1;
						label.lab_pointer = 1;
						label.value = instruction->srcB.index;
					} else if (instruction->srcB.relocated) {
						label.scope = 3;
						label.type = 2;
						label.lab_pointer = 0;
						label.value = instruction->srcB.index;
					} else {
						label.scope = 3;
						label.type = 3;
						label.lab_pointer = 0;
						label.value = instruction->srcB.index;
					}
					
					inst_log1->value2.value_id = variable_id;
					label_redirect[variable_id].redirect = variable_id;
					labels[variable_id].scope = label.scope;
					labels[variable_id].type = label.type;
					labels[variable_id].lab_pointer += label.lab_pointer;
					labels[variable_id].value = label.value;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcB direct given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value2.value_id); 
					variable_id++;
					break;
				case STORE_REG:
					/* FIXME: TODO*/
					/* srcB */
					//search_back_for_register(self, l, node, inst, 1,
					//	&label, &new_label);
					inst_log1->value2.value_id = 
						reg_tracker[instruction->srcB.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcB given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value2.value_id); 
					break;
				}
				break;
			case CALL:
				/* FIXME: TODO*/
				break;
			case IF:
				break;
			case BC:
				switch (instruction->srcA.store) {
				case STORE_DIRECT:
					memset(&label, 0, sizeof(struct label_s));
					if (instruction->srcA.indirect == IND_MEM) {
						label.scope = 3;
						label.type = 1;
						label.lab_pointer = 1;
						label.value = instruction->dstA.index;
					} else if (instruction->srcA.relocated) {
						label.scope = 3;
						label.type = 2;
						label.lab_pointer = 0;
						label.value = instruction->dstA.index;
					} else {
						label.scope = 3;
						label.type = 3;
						label.lab_pointer = 0;
						label.value = instruction->srcA.index;
					}
					
					inst_log1->value1.value_id = variable_id;
					label_redirect[variable_id].redirect = variable_id;
					labels[variable_id].scope = label.scope;
					labels[variable_id].type = label.type;
					labels[variable_id].lab_pointer += label.lab_pointer;
					labels[variable_id].value = label.value;
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA direct given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value1.value_id); 
					variable_id++;
					break;
				case STORE_REG:
					/* FIXME: TODO*/
					inst_log1->value1.value_id = 
						reg_tracker[instruction->srcA.index];
					debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA given value_id = 0x%"PRIx64"\n", inst,
						inst_log1->value1.value_id); 
					break;
				}
			case RET:
				inst_log1->value1.value_id = 
					reg_tracker[instruction->srcA.index];
				debug_print(DEBUG_MAIN, 1, "Inst 0x%x: srcA given value_id = 0x%"PRIx64"\n", inst,
					inst_log1->value1.value_id); 
				break;
			case JMP:
				break;
			case JMPT:
				/* FIXME: TODO*/
				break;
			default:
				debug_print(DEBUG_MAIN, 1, "SSA1 failed for Inst:0x%x, OP 0x%x\n", n, instruction->opcode);
				return 1;
				break;
			}
			if (inst == nodes[node].inst_end) {
				found = 1;
			}
			if (inst_log1->next_size > 0) {
				inst = inst_log1->next[0];
			} else {
				/* Exit here */
				found = 1;
			}
		} while (!found);
	}
	*label_id = variable_id;
	return 0;
}

int insert_nop_before(struct self_s *self, int inst, int *new_inst);
int insert_nop_after(struct self_s *self, int inst, int *new_inst);

int substitute_inst(struct self_s *self, int inst, int new_inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	inst_log_entry[new_inst].instruction.opcode =
		inst_log_entry[inst].instruction.opcode;
	inst_log_entry[new_inst].instruction.flags =
		inst_log_entry[inst].instruction.flags;
	inst_log_entry[new_inst].instruction.srcA.store =
		inst_log_entry[inst].instruction.srcA.store;
	inst_log_entry[new_inst].instruction.srcA.indirect =
		inst_log_entry[inst].instruction.srcA.indirect;
	inst_log_entry[new_inst].instruction.srcA.indirect_size =
		inst_log_entry[inst].instruction.srcA.indirect_size;
	inst_log_entry[new_inst].instruction.srcA.index =
		inst_log_entry[inst].instruction.srcA.index;
	inst_log_entry[new_inst].instruction.srcA.relocated =
		inst_log_entry[inst].instruction.srcA.relocated;
	inst_log_entry[new_inst].instruction.srcA.value_size =
		inst_log_entry[inst].instruction.srcA.value_size;
	inst_log_entry[new_inst].instruction.srcB.store =
		inst_log_entry[inst].instruction.srcB.store;
	inst_log_entry[new_inst].instruction.srcB.indirect =
		inst_log_entry[inst].instruction.srcB.indirect;
	inst_log_entry[new_inst].instruction.srcB.indirect_size =
		inst_log_entry[inst].instruction.srcB.indirect_size;
	inst_log_entry[new_inst].instruction.srcB.index =
		inst_log_entry[inst].instruction.srcB.index;
	inst_log_entry[new_inst].instruction.srcB.relocated =
		inst_log_entry[inst].instruction.srcB.relocated;
	inst_log_entry[new_inst].instruction.srcB.value_size =
		inst_log_entry[inst].instruction.srcB.value_size;
	inst_log_entry[new_inst].instruction.dstA.store =
		inst_log_entry[inst].instruction.dstA.store;
	inst_log_entry[new_inst].instruction.dstA.indirect =
		inst_log_entry[inst].instruction.dstA.indirect;
	inst_log_entry[new_inst].instruction.dstA.indirect_size =
		inst_log_entry[inst].instruction.dstA.indirect_size;
	inst_log_entry[new_inst].instruction.dstA.index =
		inst_log_entry[inst].instruction.dstA.index;
	inst_log_entry[new_inst].instruction.dstA.relocated =
		inst_log_entry[inst].instruction.dstA.relocated;
	inst_log_entry[new_inst].instruction.dstA.value_size =
		inst_log_entry[inst].instruction.dstA.value_size;
	return 0;
}


int build_flag_dependency_table(struct self_s *self)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log1_flags;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct instruction_s *instruction;
	int l,n;
	int found;
	int tmp;
	int new_inst;
	int inst_max = self->flag_dependency_size;

	for (n = 1; n < inst_max; n++) {
		self->flag_result_users[n] = 0;
	}

	for (n = 1; n < inst_max; n++) {
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		switch (instruction->opcode) {
		case RCR:
		case RCL:
		case ADC:
		case SBB:
		case IF:
			debug_print(DEBUG_MAIN, 1, "flag user inst 0x%x OP:0x%x\n", n, instruction->opcode);
			found = 0;
			tmp = 30; /* Limit the scan backwards */
			inst_log1_flags =  inst_log1;
			do {
				if (inst_log1_flags->prev > 0) {
					l = inst_log1_flags->prev[0];
				} else {
					break;
				}
				tmp--;
				inst_log1_flags =  &inst_log_entry[l];
				debug_print(DEBUG_MAIN, 1, "Previous opcode 0x%x\n", inst_log1_flags->instruction.opcode);
				debug_print(DEBUG_MAIN, 1, "Previous flags 0x%x\n", inst_log1_flags->instruction.flags);
				if (1 == inst_log1_flags->instruction.flags) {
					found = 1;
				}
				debug_print(DEBUG_MAIN, 1, "Previous flags instruction size 0x%x\n", inst_log1_flags->prev_size);
				tmp--;
			} while ((0 == found) && (0 < tmp) && (0 != l));
			if (found == 0) {
				debug_print(DEBUG_MAIN, 1, "Previous flags instruction not found. found=%d, tmp=%d, l=0x%x\n", found, tmp, l);
				return 1;
			} else {
				debug_print(DEBUG_MAIN, 1, "Previous flags instruction found. found=%d, tmp=%d, l=0x%x n=0x%x\n", found, tmp, l, n);
				if (self->flag_result_users[l] > 0) {
					if (inst_log_entry[l].instruction.opcode != CMP) {
						debug_print(DEBUG_MAIN, 1, "TOO MANY FLAGGED NON CMP. Opcode = 0x%x\n",
							inst_log_entry[l].instruction.opcode);
						exit(1);
					}
					/* Use "before" because after will cause a race condition */
					tmp = insert_nop_before(self, l, &new_inst);
					/* copy CMP into it */
					tmp = substitute_inst(self, l, new_inst);
					self->flag_dependency[n] = new_inst;
					self->flag_dependency_opcode[n] = inst_log1_flags->instruction.opcode;
					self->flag_result_users[new_inst]++;
					if (new_inst > 0xe20) {
						debug_print(DEBUG_MAIN, 1, "ADDING NEW INST 0x%x, flagged = 0x%x, flag_dep_size = 0x%x\n",
							new_inst, self->flag_result_users[new_inst], self->flag_dependency_size);
					}
				} else {		
					self->flag_dependency[n] = l;
					self->flag_dependency_opcode[n] = inst_log1_flags->instruction.opcode;
					self->flag_result_users[l]++;
					if (l > 0xe20) {
						debug_print(DEBUG_MAIN, 1, "ADDING FLAGGED 0x%x, flagged = 0x%x, flag_dep_size = 0x%x\n",
							l, self->flag_result_users[l], self->flag_dependency_size);
					}
				}
			}
			break;
		default:
			break;
		}
	}
	found = 0;
	for (n = 1; n < inst_max; n++) {
		if (self->flag_result_users[n] > 1) {
			debug_print(DEBUG_MAIN, 1, "Duplicate Previous flags instruction found. inst 0x%x:0x%x\n", n, self->flag_result_users[n]);
			found = 1;
		}
		if (self->flag_result_users[n] > 0) {
			debug_print(DEBUG_MAIN, 1, "FLAG RESULT USED. inst 0x%x:0x%x opcode=0x%x\n", n, self->flag_result_users[n], inst_log_entry[n].instruction.opcode);
		}

	}
	if (found) {
		printf("build_flag_dependency_table: Exiting\n");
		exit(1);
	}
	
	return 0;
}

int matcher_sbb(struct self_s *self, int inst, int *sbb_match, int *n1, int *n2, int *n3, int *flags_result_used)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	int match = 0;
	int prev = self->flag_dependency[inst];
	int next1 = 0;
	int next2 = 0;
	int next3 = 0;
	int nexts_present = 0;
	int cmp_sbb_and_add = 0;
	int cmp_sbb_add = 0;
	int reg = 0;
	int reg_size = 0;
	int is_reg = 0;
	int ssb_same_reg = 0;
	int next1_same_reg = 0;
	int next2_same_reg = 0;
	int m;
	int max_log = inst_log;
	inst_log1 =  &inst_log_entry[inst];

	if (self->flag_result_users[inst] > 0) {
		for (m = 1; m < max_log; m++) {
			if (self->flag_dependency[m] == inst) {
				debug_print(DEBUG_MAIN, 1, "flag: SBB leaves users. inst 0x%x uses flag from inst 0x%x\n", m, inst);
			}
		}
		*flags_result_used = 1;
		debug_print(DEBUG_MAIN, 1, "flag: NOT HANDLED: SBB leaves users. inst ???? uses flag from inst 0x%x\n", inst);
	}
	if (inst_log1->next_size) {
		next1 = inst_log1->next[0];
	}
	if (inst_log_entry[next1].next_size) {
		next2 = inst_log_entry[next1].next[0];
	}
	if (inst_log_entry[next2].next_size) {
		next3 = inst_log_entry[next2].next[0];
	}
	if ((prev != 0) && (next1 != 0) && (next2 != 0)) {
		nexts_present = 1;
	}
	if ((nexts_present) &&
		(inst_log_entry[prev].instruction.opcode == CMP) && 
		(inst_log_entry[next1].instruction.opcode == rAND) && 
		(inst_log_entry[next2].instruction.opcode == ADD)) {
		cmp_sbb_and_add = 1;
	}
	if ((prev != 0) && (next1 != 0) &&
		(inst_log_entry[prev].instruction.opcode == CMP) && 
		(inst_log_entry[next1].instruction.opcode == ADD)) { 
		cmp_sbb_add = 1;
	}
	if ((inst_log1->instruction.dstA.store == STORE_REG) &&
		(inst_log1->instruction.dstA.indirect == IND_DIRECT)) {
		reg = inst_log1->instruction.dstA.index;
		reg_size = inst_log1->instruction.dstA.value_size;
		is_reg = 1;
	}
	if (inst_log1->instruction.srcA.index == 
		inst_log1->instruction.srcB.index) {
		ssb_same_reg = 1;
	}
	if ((inst_log_entry[next1].instruction.srcB.index == reg) &&
		(inst_log_entry[next1].instruction.dstA.index == reg)) {
		next1_same_reg = 1;
	}
	if ((inst_log_entry[next2].instruction.srcB.index == reg) &&
		(inst_log_entry[next2].instruction.dstA.index == reg)) {
		next2_same_reg = 1;
	}

	if ((*flags_result_used == 0) &&
		nexts_present &&
		cmp_sbb_and_add &&
		is_reg &&
		ssb_same_reg &&
		next1_same_reg &&
		next2_same_reg) {
		/* cmp_sbb_and_add to icmp_bc */
		match = 5;
	} else if ((*flags_result_used == 0) &&
		nexts_present &&
		cmp_sbb_add &&
		is_reg &&
		ssb_same_reg &&
		next1_same_reg &&
		next2_same_reg) {
		/* cmp_sbb_add to icmp_bc */
		match = 4;
	} else if ((*flags_result_used == 0) &&
		is_reg &&
		ssb_same_reg) {
		/* cmp_sbb_to_icmp_sex */
		match = 3;
	} else if (*flags_result_used == 0) {
		/* cmp_ssb_to_icmp_sex_add_sub */
		match = 2;
	} else {
		/* Not yet handled */
		match = 1;
	}
	*n1 = next1;
	*n2 = next2;
	*n3 = next3;
	*sbb_match = match;

	return 0;
}

int fix_flag_dependency_instructions(struct self_s *self)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log1_flags;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct instruction_s *instruction;
	int m,n;
	int tmp;
	int prev;
	int next1;
	int next2;
	int next3;
	int sbb_match;
	int flags_result_used;
	int reg;
	int reg_size;
	int new_inst = 0;
	int64_t working_var1;
	int64_t working_var2;
	int64_t working_var3;
	int max_log;

	/* Use max_log and not inst_log in case inst_log changes when adding nop instructions */
	max_log = self->flag_dependency_size;
	debug_print(DEBUG_MAIN, 1, "flag: MAX_LOG = 0x%x\n", max_log);

	for (n = 1; n < max_log; n++) {
		if (!self->flag_dependency[n]) {
			/* Go round loop again */
			continue;
		}
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		prev = self->flag_dependency[n];
		next1 = 0;
		next2 = 0;
		next3 = 0;
		sbb_match = 0;
		debug_print(DEBUG_MAIN, 1, "flag user inst 0x%x OP:0x%x\n", n, instruction->opcode);
		switch (instruction->opcode) {
		case ADC:
			debug_print(DEBUG_MAIN, 1, "flag: ADC NOT HANDLED yet\n");
			exit(1);
			break;
		case SBB:
			tmp = matcher_sbb(self, n, &sbb_match, &next1, &next2, &next3, &flags_result_used);
			debug_print(DEBUG_MAIN, 1, "SBB: match 0x%x\n", sbb_match);
			if (self->flag_result_users[n] > 0) {
				for (m = 1; m < max_log; m++) {
					if (self->flag_dependency[m] == n) {
						debug_print(DEBUG_MAIN, 1, "flag: SBB leaves users. inst 0x%x uses flag from inst 0x%x\n", m, n);
					}
				}
				debug_print(DEBUG_MAIN, 1, "flag: NOT HANDLED: SBB leaves users. inst ???? uses flag from inst 0x%x\n", n);
				exit(1);
			}
			/* Match tests passed. Now do the substitution */
			switch (sbb_match) {
			case 5:
				working_var1 = inst_log_entry[next1].instruction.srcA.index;
				working_var2 = inst_log_entry[next2].instruction.srcA.index;
				working_var3 = working_var1 + working_var2;
				tmp = insert_nop_after(self, n, &new_inst);
				debug_print(DEBUG_MAIN, 1, "flag: working_var1 = 0x%"PRIx64", working_var2 = 0x%"PRIx64", working_var3 = 0x%"PRIx64"\n",
					working_var1,
					working_var2,
					working_var3);
				inst_log_entry[prev].instruction.opcode = ICMP;
				inst_log_entry[prev].instruction.flags = 0;
				inst_log_entry[prev].instruction.predicate = LESS;
				inst_log_entry[prev].instruction.dstA.index = REG_LESS;
				inst_log_entry[prev].instruction.dstA.store = STORE_REG;
				inst_log_entry[prev].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[prev].instruction.dstA.relocated = 0;
				inst_log_entry[prev].instruction.dstA.value_size = 1;
				inst_log_entry[prev].value3.value_scope =  2;
				instruction->opcode = BC;
				instruction->srcA.index = REG_LESS;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				
				debug_print(DEBUG_MAIN, 1, "flag: realloc: inst_log1->next_size = 0x%x, %p\n", inst_log1->next_size, inst_log1->next);
				inst_log1->next = realloc(inst_log1->next, 2 * sizeof(int));
				debug_print(DEBUG_MAIN, 1, "flag: realloc: inst_log1->next_size = 0x%x, %p\n", inst_log1->next_size, inst_log1->next);
				
				inst_log1->next[0] = next2;
				inst_log1->next[1] = new_inst;
				inst_log1->next_size = 2;
	
				inst_log_entry[new_inst].instruction.opcode = MOV;
				inst_log_entry[new_inst].instruction.flags = 0;
				inst_log_entry[new_inst].instruction.predicate = 0;
				inst_log_entry[new_inst].instruction.srcA.index = working_var3;
				inst_log_entry[new_inst].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.relocated = 0;
				inst_log_entry[new_inst].instruction.srcA.value_size = reg_size;
				inst_log_entry[new_inst].instruction.srcB.index = reg;
				inst_log_entry[new_inst].instruction.srcB.store = STORE_REG;
				inst_log_entry[new_inst].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcB.relocated = 0;
				inst_log_entry[new_inst].instruction.srcB.value_size = reg_size;
				inst_log_entry[new_inst].instruction.dstA.index = reg;
				inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
				inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.dstA.relocated = 0;
				inst_log_entry[new_inst].instruction.dstA.value_size = reg_size;
				inst_log_entry[new_inst].value3.value_scope =  2;

				inst_log_entry[next1].instruction.opcode = JMP;
				inst_log_entry[next1].instruction.flags = 0;
				inst_log_entry[next1].instruction.predicate = 0;
				inst_log_entry[next1].instruction.srcA.index = working_var2;
				inst_log_entry[next1].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[next1].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[next1].instruction.srcA.relocated = 0;
				inst_log_entry[next1].instruction.srcA.value_size = reg_size;
				inst_log_entry[next1].instruction.srcB.index = reg;
				inst_log_entry[next1].instruction.srcB.store = STORE_REG;
				inst_log_entry[next1].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[next1].instruction.srcB.relocated = 0;
				inst_log_entry[next1].instruction.srcB.value_size = reg_size;
				inst_log_entry[next1].instruction.dstA.index = reg;
				inst_log_entry[next1].instruction.dstA.store = STORE_REG;
				inst_log_entry[next1].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[next1].instruction.dstA.relocated = 0;
				inst_log_entry[next1].instruction.dstA.value_size = reg_size;
				inst_log_entry[next1].value3.value_scope =  2;
				inst_log_entry[next1].next[0] = next3;
				tmp = inst_log_entry[next3].prev_size;
				inst_log_entry[next3].prev = realloc(inst_log_entry[next3].prev, (tmp +  1) * sizeof(int));
				inst_log_entry[next3].prev[tmp] = next1;
				inst_log_entry[next3].prev_size++;

				inst_log_entry[next2].instruction.opcode = MOV;
				inst_log_entry[next2].instruction.flags = 0;
				inst_log_entry[next2].instruction.predicate = 0;
				inst_log_entry[next2].instruction.srcA.index = working_var2;
				inst_log_entry[next2].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[next2].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[next2].instruction.srcA.relocated = 0;
				inst_log_entry[next2].instruction.srcA.value_size = reg_size;
				inst_log_entry[next2].instruction.srcB.index = reg;
				inst_log_entry[next2].instruction.srcB.store = STORE_REG;
				inst_log_entry[next2].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[next2].instruction.srcB.relocated = 0;
				inst_log_entry[next2].instruction.srcB.value_size = reg_size;
				inst_log_entry[next2].instruction.dstA.index = reg;
				inst_log_entry[next2].instruction.dstA.store = STORE_REG;
				inst_log_entry[next2].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[next2].instruction.dstA.relocated = 0;
				inst_log_entry[next2].instruction.dstA.value_size = reg_size;
				inst_log_entry[next2].value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "flag: SBB 5 handled\n");
				break;
			case 3:
				inst_log_entry[prev].instruction.opcode = ICMP;
				inst_log_entry[prev].instruction.flags = 0;
				inst_log_entry[prev].instruction.predicate = BELOW;
				inst_log_entry[prev].instruction.dstA.index = REG_BELOW;
				inst_log_entry[prev].instruction.dstA.store = STORE_REG;
				inst_log_entry[prev].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[prev].instruction.dstA.relocated = 0;
				inst_log_entry[prev].instruction.dstA.value_size = 1;
				inst_log_entry[prev].value3.value_scope =  2;
				instruction->opcode = SEX;
				instruction->flags = 0;
				instruction->srcA.index = REG_BELOW;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				debug_print(DEBUG_MAIN, 1, "flag: SBB 3 handled\n");
				break;
			default:
				debug_print(DEBUG_MAIN, 1, "flag: SBB 0x%x NOT HANDLED\n", sbb_match);
				break;
			}
			
			//exit(1);
			break;
		case IF:
			debug_print(DEBUG_MAIN, 1, "flag IF inst 0x%x OP:0x%x\n", n, instruction->opcode);
			inst_log1_flags =  &inst_log_entry[self->flag_dependency[n]];
			if (inst_log1_flags->instruction.opcode != self->flag_dependency_opcode[n]) {
				return 1;
			}
			switch (inst_log1_flags->instruction.opcode) {
			case CMP:
				inst_log1_flags->instruction.opcode = ICMP;
				inst_log1_flags->instruction.flags = 0;
				inst_log1_flags->instruction.predicate = inst_log1->instruction.srcA.index;
				inst_log1_flags->instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				inst_log1_flags->instruction.dstA.store = STORE_REG;
				inst_log1_flags->instruction.dstA.indirect = IND_DIRECT;
				inst_log1_flags->instruction.dstA.relocated = 0;
				inst_log1_flags->instruction.dstA.value_size = 1;
				inst_log1_flags->value3.value_scope =  2;
				/* FIXME: fill in rest of instruction dstA and then its value3 */
				instruction->opcode = BC;
				instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				break;
			case TEST:
				//if (inst_log1_flags->instruction.srcA.index != inst_log1_flags->instruction.srcB.index) {
				//	debug_print(DEBUG_MAIN, 1, "flag NOT HANDLED inst 0x%x TEST OP:0x%x\n", n, inst_log1_flags->instruction.opcode);
				//	exit (1);
				//}
				tmp = insert_nop_after(self, self->flag_dependency[n], &new_inst);
				reg_size = inst_log1_flags->instruction.srcA.value_size;
				inst_log1_flags->instruction.opcode = rAND;
				inst_log1_flags->instruction.flags = 0;
				inst_log1_flags->instruction.dstA.index = REG_TMP1;
				inst_log1_flags->instruction.dstA.store = STORE_REG;
				inst_log1_flags->instruction.dstA.indirect = IND_DIRECT;
				inst_log1_flags->instruction.dstA.relocated = 0;
				inst_log1_flags->instruction.dstA.value_size = reg_size;

				inst_log_entry[new_inst].instruction.opcode = ICMP;
				inst_log_entry[new_inst].instruction.flags = 0;
				inst_log_entry[new_inst].instruction.predicate = inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.srcA.index = 0;
				inst_log_entry[new_inst].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.relocated = 0;
				inst_log_entry[new_inst].instruction.srcA.value_size = reg_size;
				inst_log_entry[new_inst].instruction.srcB.index = REG_TMP1;
				inst_log_entry[new_inst].instruction.srcB.store = STORE_REG;
				inst_log_entry[new_inst].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcB.relocated = 0;
				inst_log_entry[new_inst].instruction.srcB.value_size = reg_size;
				inst_log_entry[new_inst].instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
				inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.dstA.relocated = 0;
				inst_log_entry[new_inst].instruction.dstA.value_size = 1;
				inst_log_entry[new_inst].value3.value_scope =  2;

				/* FIXME: fill in rest of instruction dstA and then its value3 */
				instruction->opcode = BC;
				instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				break;
			case rAND:
				tmp = insert_nop_after(self, self->flag_dependency[n], &new_inst);
				reg = inst_log1_flags->instruction.dstA.index;
				reg_size = inst_log1_flags->instruction.dstA.value_size;

				inst_log_entry[new_inst].instruction.opcode = ICMP;
				inst_log_entry[new_inst].instruction.flags = 0;
				inst_log_entry[new_inst].instruction.predicate = inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.srcA.index = 0;
				inst_log_entry[new_inst].instruction.srcA.store = STORE_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcA.relocated = 0;
				inst_log_entry[new_inst].instruction.srcA.value_size = reg_size;
				inst_log_entry[new_inst].instruction.srcB.index = reg;
				inst_log_entry[new_inst].instruction.srcB.store = STORE_REG;
				inst_log_entry[new_inst].instruction.srcB.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.srcB.relocated = 0;
				inst_log_entry[new_inst].instruction.srcB.value_size = reg_size;
				inst_log_entry[new_inst].instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
				inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.dstA.relocated = 0;
				inst_log_entry[new_inst].instruction.dstA.value_size = 1;
				inst_log_entry[new_inst].value3.value_scope =  2;

				/* FIXME: fill in rest of instruction dstA and then its value3 */
				instruction->opcode = BC;
				instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				break;
			case SUB:
				tmp = insert_nop_before(self, self->flag_dependency[n], &new_inst);
				reg = inst_log1_flags->instruction.dstA.index;
				reg_size = inst_log1_flags->instruction.dstA.value_size;
				tmp = substitute_inst(self, self->flag_dependency[n], new_inst);

				inst_log_entry[new_inst].instruction.opcode = ICMP;
				inst_log_entry[new_inst].instruction.flags = 0;
				inst_log_entry[new_inst].instruction.predicate = inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
				inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
				inst_log_entry[new_inst].instruction.dstA.relocated = 0;
				inst_log_entry[new_inst].instruction.dstA.value_size = 1;
				inst_log_entry[new_inst].value3.value_scope =  2;

				/* FIXME: fill in rest of instruction dstA and then its value3 */
				instruction->opcode = BC;
				instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
				instruction->srcA.store = STORE_REG;
				instruction->srcA.indirect = IND_DIRECT;
				instruction->srcA.relocated = 0;
				instruction->srcA.value_size = 1;
				inst_log1->value3.value_scope =  2;
				debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				break;
			case ADD:
				tmp = inst_log1->instruction.srcA.index;
				if ((tmp == EQUAL) || (tmp == NOT_EQUAL)) {
					int inst = self->flag_dependency[n];
					tmp = insert_nop_after(self, inst, &new_inst);
					reg = inst_log1_flags->instruction.dstA.index;
					reg_size = inst_log1_flags->instruction.dstA.value_size;

					inst_log_entry[new_inst].instruction.opcode = ICMP;
					inst_log_entry[new_inst].instruction.flags = 0;
					inst_log_entry[new_inst].instruction.predicate = inst_log1->instruction.srcA.index;
					inst_log_entry[new_inst].instruction.srcA.index = 0;
					inst_log_entry[new_inst].instruction.srcA.store = STORE_DIRECT;
					inst_log_entry[new_inst].instruction.srcA.indirect = IND_DIRECT;
					inst_log_entry[new_inst].instruction.srcA.relocated = 0;
					inst_log_entry[new_inst].instruction.srcA.value_size = reg_size;
					inst_log_entry[new_inst].instruction.srcB.store =
						inst_log_entry[inst].instruction.dstA.store;
					inst_log_entry[new_inst].instruction.srcB.indirect =
						inst_log_entry[inst].instruction.dstA.indirect;
					inst_log_entry[new_inst].instruction.srcB.indirect_size =
						inst_log_entry[inst].instruction.dstA.indirect_size;
					inst_log_entry[new_inst].instruction.srcB.index =
						inst_log_entry[inst].instruction.dstA.index;
					inst_log_entry[new_inst].instruction.srcB.relocated =
						inst_log_entry[inst].instruction.dstA.relocated;
					inst_log_entry[new_inst].instruction.srcB.value_size =
						inst_log_entry[inst].instruction.dstA.value_size;

					inst_log_entry[new_inst].instruction.dstA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
					inst_log_entry[new_inst].instruction.dstA.store = STORE_REG;
					inst_log_entry[new_inst].instruction.dstA.indirect = IND_DIRECT;
					inst_log_entry[new_inst].instruction.dstA.relocated = 0;
					inst_log_entry[new_inst].instruction.dstA.value_size = 1;
					inst_log_entry[new_inst].value3.value_scope =  2;

					/* FIXME: fill in rest of instruction dstA and then its value3 */
					instruction->opcode = BC;
					instruction->srcA.index = REG_OVERFLOW + inst_log1->instruction.srcA.index;
					instruction->srcA.store = STORE_REG;
					instruction->srcA.indirect = IND_DIRECT;
					instruction->srcA.relocated = 0;
					instruction->srcA.value_size = 1;
					inst_log1->value3.value_scope =  2;
					debug_print(DEBUG_MAIN, 1, "Pair of instructions adjusted. inst 0x%x:0x%x\n", n, self->flag_dependency[n]);
				} else {
					debug_print(DEBUG_MAIN, 1, "flag NOT HANDLED inst 0x%x OP:ADD:0x%x:PRED=0x%"PRIx64"\n",
						n,
						inst_log1_flags->instruction.opcode,
						inst_log1->instruction.srcA.index);
				}
				break;


			default:
				debug_print(DEBUG_MAIN, 1, "flag NOT HANDLED inst 0x%x OP:0x%x\n", n, inst_log1_flags->instruction.opcode);
				exit (1);
				break;
			}
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "flag: UNKNOWNN:0x%x NOT HANDLED yet. inst 0x%x:0x%x\n",
				instruction->opcode, n, self->flag_dependency[n]);
			exit(1);
			break;
		}
	}
	return 0;
}

int print_flag_dependency_table(struct self_s *self)
{
	int n;
	for (n = 1; n < self->flag_dependency_size; n++) {
		if (self->flag_dependency[n]) {
			debug_print(DEBUG_MAIN, 1, "FLAGS: Inst 0x%x linked to previous Inst 0x%x:0x%x\n", n, self->flag_dependency[n], self->flag_dependency_opcode[n]);
		}
	}
	return 0;
}	

int insert_nop_before(struct self_s *self, int inst, int *new_inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1 = &inst_log_entry[inst];
	struct inst_log_entry_s *inst_log1_previous;
	struct inst_log_entry_s *inst_log1_new;
	int l,m,n;
	int inst_new;

	inst_new = inst_log;
	inst_log1_new = &inst_log_entry[inst_new];
	inst_log++;
	self->flag_dependency = realloc(self->flag_dependency, (inst_log) * sizeof(int));
	self->flag_dependency[inst_log - 1] = 0;
	self->flag_dependency_opcode = realloc(self->flag_dependency_opcode, (inst_log) * sizeof(int));
	self->flag_dependency_opcode[inst_log - 1] = 0;
	self->flag_result_users = realloc(self->flag_result_users, (inst_log) * sizeof(int));
	self->flag_result_users[inst_log - 1] = 0;
	debug_print(DEBUG_MAIN, 1, "INFO: Insert nop before: Old dep size = 0x%x, new dep size = 0x%"PRIx64"\n", self->flag_dependency_size, inst_log);
	debug_print(DEBUG_MAIN, 1, "INFO: Setting flag_result_users[0x%"PRIx64"] = 0\n", inst_log - 1);
	self->flag_dependency_size = inst_log;

	inst_log1_new->instruction.opcode = NOP;
        inst_log1_new->instruction.flags = 0;
	if (inst_log1->prev_size) {
		inst_log1_new->prev = calloc(inst_log1->prev_size, sizeof(int));
		inst_log1_new->prev_size = inst_log1->prev_size;
		for (n = 0; n < inst_log1->prev_size; n++) {
			inst_log1_new->prev[n] = inst_log1->prev[n];
			if (inst_log1->prev[n] == 0) {
				debug_print(DEBUG_MAIN, 1, "ERROR: Insert nop before first instruction not yet supported. Case 0\n");
				/* Move the entry point. Should never get here */
				exit(1);
			}
			inst_log1_previous = &inst_log_entry[inst_log1->prev[n]];
			for (m = 0; m < inst_log1_previous->next_size; m++) {
				if (inst_log1_previous->next[m] == inst) {
					inst_log1_previous->next[m] = inst_new;
				}
			}
		}
	} else {
		for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
			if ((self->external_entry_points[l].valid != 0) &&
				(self->external_entry_points[l].type == 1) &&
				(self->external_entry_points[l].inst_log == inst)) {
					self->external_entry_points[l].inst_log = inst_new;
				debug_print(DEBUG_MAIN, 1, "fixing entry point[0x%x] from 0x%x to 0x%x\n",
					l, inst, inst_new);
			}
		}
	}
	inst_log1_new->next = calloc(1, sizeof(int));
	inst_log1_new->next_size = 1;
	inst_log1_new->next[0] = inst;
	if (0 == inst_log1->prev_size) {
		inst_log1->prev = calloc(1, sizeof(int));
	}
	inst_log1->prev_size = 1;
	inst_log1->prev[0] = inst_new;
	*new_inst = inst_new;

	return 0;
}

int insert_nop_after(struct self_s *self, int inst, int *new_inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1 = &inst_log_entry[inst];
	struct inst_log_entry_s *inst_log1_next;
	struct inst_log_entry_s *inst_log1_new;
	int m,n;
	int inst_new;

	inst_new = inst_log;
	if (inst_log1->next_size > 1) {
		debug_print(DEBUG_MAIN, 1, "insert_nop_after: FAILED Inst 0x%x\n", inst);
		return 1;
	}
	inst_log1_new = &inst_log_entry[inst_log];
	inst_log++;
	self->flag_dependency = realloc(self->flag_dependency, (inst_log) * sizeof(int));
	self->flag_dependency[inst_log - 1] = 0;
	self->flag_dependency_opcode = realloc(self->flag_dependency_opcode, (inst_log) * sizeof(int));
	self->flag_dependency_opcode[inst_log - 1] = 0;
	self->flag_result_users = realloc(self->flag_result_users, (inst_log) * sizeof(int));
	self->flag_result_users[inst_log - 1] = 0;
	debug_print(DEBUG_MAIN, 1, "INFO: Insert nop after: Old dep size = 0x%x, new dep size = 0x%"PRIx64"\n", self->flag_dependency_size, inst_log);
	self->flag_dependency_size = inst_log;

	inst_log1_new->instruction.opcode = NOP;
        inst_log1_new->instruction.flags = 0;
	if (inst_log1->next_size) {
		inst_log1_new->next = calloc(inst_log1->next_size, sizeof(int));
		inst_log1_new->next_size = inst_log1->next_size;
		for (n = 0; n < inst_log1->next_size; n++) {
			inst_log1_new->next[n] = inst_log1->next[n];
			inst_log1_next = &inst_log_entry[inst_log1->next[n]];
			for (m = 0; m < inst_log1_next->prev_size; m++) {
				if (inst_log1_next->prev[m] == inst) {
					inst_log1_next->prev[m] = inst_new;
				}
			}
		}
	}
	inst_log1_new->prev = calloc(1, sizeof(int));
	inst_log1_new->prev_size = 1;
	inst_log1_new->prev[0] = inst;
	inst_log1->next_size = 1;
	inst_log1->next[0] = inst_new;
	*new_inst = inst_new;

	return 0;
}

int create_function_node_members(struct self_s *self, struct external_entry_point_s *external_entry_point)
{
	int m, n;
	int global_nodes_size = self->nodes_size;
	struct control_flow_node_s *global_nodes = self->nodes;
	int member_nodes_size;
	int *member_nodes;
	int *node_list;
	int found = 0;
	int count = 1;
	int node;
	int next_node;
	int tmp;

	struct mid_node_s {
		int node;
		int valid;
	};
	struct mid_node_s *mid_node;

	
	node_list = calloc(global_nodes_size, sizeof(int));
	mid_node = calloc(100, sizeof(struct mid_node_s));

	mid_node[0].node = external_entry_point->start_node;
	mid_node[0].valid = 1;

	do {
		for (n = 0; n < 100; n++) {
			if (mid_node[n].valid == 1) {
				node = mid_node[n].node;
				mid_node[n].valid = 0;
				break;
			}
		}
		if (n == 100) {
			/* finished */
			found = 1;
			break;
		}	
		if (node_list[node] == 0) {
			node_list[node] = count;
			count++;
		}
		for (n = 0; n < global_nodes[node].next_size; n++) {
			next_node = global_nodes[node].link_next[n].node;
			if (node_list[next_node] == 0) {
				for (m = 0; m < 100; m++) {
					if (mid_node[m].valid == 0) {
						mid_node[m].node = next_node;
						mid_node[m].valid = 1;
						break;
					}
				}
				if (m == 100) {
					printf("Failed in create_function_node_members(). No free mid_nodes.\n");
					exit(1);
				}
			}
		}
	} while (found == 0);
	member_nodes = calloc(count, sizeof(int));
	member_nodes_size = count;
	for (n = 1; n <= global_nodes_size; n++) {
		tmp = node_list[n];
		if (tmp != 0 && tmp < member_nodes_size) {
			member_nodes[tmp] = n;
		}
	}
	external_entry_point->member_nodes_size = member_nodes_size;
	external_entry_point->member_nodes = member_nodes;
	external_entry_point->nodes_size = member_nodes_size;
	external_entry_point->nodes = calloc(member_nodes_size, sizeof(struct control_flow_node_s));

	/* node 0 is intentionally not used */
	for (n = 1; n < member_nodes_size; n++) {
		memcpy(&(external_entry_point->nodes[n]), &(global_nodes[member_nodes[n]]), sizeof (struct control_flow_node_s));
		external_entry_point->nodes[n].prev_node = calloc(external_entry_point->nodes[n].prev_size, sizeof(int));
		memcpy(&(external_entry_point->nodes[n].prev_node), &(global_nodes[member_nodes[n]].prev_node), external_entry_point->nodes[n].prev_size * sizeof (int));
		for (m = 0; m < external_entry_point->nodes[n].prev_size; m++) {
			external_entry_point->nodes[n].prev_node[m] = node_list[external_entry_point->nodes[n].prev_node[m]];
		}
		external_entry_point->nodes[n].prev_link_index = calloc(external_entry_point->nodes[n].prev_size, sizeof(int));
		memcpy(&(external_entry_point->nodes[n].prev_link_index), &(global_nodes[member_nodes[n]].prev_link_index), external_entry_point->nodes[n].prev_size * sizeof (int));
		external_entry_point->nodes[n].link_next = calloc(external_entry_point->nodes[n].next_size, sizeof(struct node_link_s));
		memcpy(&(external_entry_point->nodes[n].link_next), &(global_nodes[member_nodes[n]].link_next), external_entry_point->nodes[n].next_size * sizeof (struct node_link_s));
		for (m = 0; m < external_entry_point->nodes[n].next_size; m++) {
			external_entry_point->nodes[n].link_next[m].node = node_list[external_entry_point->nodes[n].link_next[m].node];
		}
	}
	free(mid_node);
	free(node_list);
#if 0
	printf("function: %s\n", external_entry_point->name);
	for (n = 1; n < member_nodes_size; n++) {
		printf("Node=0x%x\n", member_nodes[n]);
	}
#endif

	return 0;
}

int main(int argc, char *argv[])
{
	int n = 0;
//	uint64_t offset = 0;
//	int instruction_offset = 0;
//	int octets = 0;
//	int result;
	char *filename;
	uint32_t arch;
	uint64_t mach;
	FILE *fd;
	int tmp;
	int err;
	const char *file = "test.obj";
//	size_t inst_size = 0;
//	uint64_t reloc_size = 0;
	int l, m;
	struct instruction_s *instruction;
//	struct instruction_s *instruction_prev;
	struct inst_log_entry_s *inst_log1;
//	struct inst_log_entry_s *inst_log1_prev;
	struct inst_log_entry_s *inst_exe;
	struct inst_log_entry_s *inst_log_entry;
//	struct memory_s *value;
	uint64_t inst_log_prev = 0;
	int param_present[100];
	int param_size[100];
	char *expression;
	int not_finished;
	struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	int *memory_used;
	struct label_redirect_s *label_redirect;
	struct label_s *labels;
	struct relocation_s *relocations;
	struct external_entry_point_s *external_entry_points;
	struct control_flow_node_s *nodes;
	int nodes_size;
	struct path_s *paths;
	int paths_size = 300000;
	struct loop_s *loops;
	int loops_size = 2000;
	struct ast_s *ast;
	int *section_number_mapping;
	int variable_id = 0;

	debug_print(DEBUG_MAIN, 1, "Hello loops 0x%x\n", 2000);

	if (argc != 2) {
		debug_print(DEBUG_MAIN, 1, "Syntax error\n");
		debug_print(DEBUG_MAIN, 1, "Usage: dis64 filename\n");
		debug_print(DEBUG_MAIN, 1, "Where \"filename\" is the input .o file\n");
		exit(1);
	}
	file = argv[1];

	expression = malloc(1000); /* Buffer for if expressions */

	handle_void = bf_test_open_file(file);
	if (!handle_void) {
		debug_print(DEBUG_MAIN, 1, "Failed to find or recognise file\n");
		return 1;
	}
	tmp = bf_get_arch_mach(handle_void, &arch, &mach);
	if ((arch != 9) ||
		(mach != 8)) {
		debug_print(DEBUG_MAIN, 1, "File not the correct arch(0x%x) and mach(0x%"PRIx64")\n", arch, mach);
		return 1;
	}

	bf_print_symtab(handle_void);

	bf_init_section_number_mapping(handle_void, &section_number_mapping);

	bf_print_sectiontab(handle_void);

	debug_print(DEBUG_MAIN, 1, "Setup ok\n");
	inst_size = bf_get_code_size(handle_void);
	inst = malloc(inst_size);
	/* valgrind does not know about bf_copy_data_section */
	memset(inst, 0, inst_size);
	bf_copy_code_section(handle_void, inst, inst_size);
	debug_print(DEBUG_MAIN, 1, "dis:.text Data at %p, size=0x%"PRIx64"\n", inst, inst_size);
	for (n = 0; n < inst_size; n++) {
		debug_print(DEBUG_MAIN, 1,  "0x%02x", inst[n]);
	}
	debug_print(DEBUG_MAIN, 1, "\n");

	data_size = bf_get_data_size(handle_void);
	data = malloc(data_size);
	/* valgrind does not know about bf_copy_data_section */
	memset(data, 0, data_size);
	bf_copy_data_section(handle_void, data, data_size);
	debug_print(DEBUG_MAIN, 1, "dis:.data Data at %p, size=0x%"PRIx64"\n", data, data_size);
	for (n = 0; n < data_size; n++) {
		debug_print(DEBUG_MAIN, 1,  "0x%02x", data[n]);
	}
	debug_print(DEBUG_MAIN, 1, "\n");

	rodata_size = bf_get_rodata_size(handle_void);
	rodata = malloc(rodata_size);
	/* valgrind does not know about bf_copy_data_section */
	memset(rodata, 0, rodata_size);
	bf_copy_rodata_section(handle_void, rodata, rodata_size);
	debug_print(DEBUG_MAIN, 1, "dis:.rodata Data at %p, size=0x%"PRIx64"\n", rodata, rodata_size);
	for (n = 0; n < rodata_size; n++) {
		debug_print(DEBUG_MAIN, 1,  "0x%02x", rodata[n]);
	}
	debug_print(DEBUG_MAIN, 1, "\n");

	inst_log_entry = calloc(INST_LOG_ENTRY_SIZE, sizeof(struct inst_log_entry_s));
	relocations =  calloc(RELOCATION_SIZE, sizeof(struct relocation_s));
	external_entry_points = calloc(EXTERNAL_ENTRY_POINTS_MAX, sizeof(struct external_entry_point_s));
	self = malloc(sizeof *self);
	debug_print(DEBUG_MAIN, 1, "sizeof struct self_s = 0x%"PRIx64"\n", sizeof *self);
	self->section_number_mapping = section_number_mapping;
	self->data_size = data_size;
	self->data = data;
	self->rodata_size = data_size;
	self->rodata = data;
	self->inst_log_entry = inst_log_entry;
	self->relocations = relocations;
	self->external_entry_points = external_entry_points;
	self->entry_point = calloc(ENTRY_POINTS_SIZE, sizeof(struct entry_point_s));
	self->entry_point_list_length = ENTRY_POINTS_SIZE;
	self->local_counter = 0x100;
	self->search_back_seen = calloc(INST_LOG_ENTRY_SIZE, sizeof(int));

	nodes = calloc(1000, sizeof(struct control_flow_node_s));
	nodes_size = 0;
	self->nodes = nodes;
	self->nodes_size = nodes_size;
	
	/* valgrind does not know about bf_copy_data_section */
	memset(data, 0, data_size);
	bf_copy_data_section(handle_void, data, data_size);
	debug_print(DEBUG_MAIN, 1, "dis:.data Data at %p, size=0x%"PRIx64"\n", data, data_size);
	for (n = 0; n < data_size; n++) {
		debug_print(DEBUG_MAIN, 1, " 0x%02x", data[n]);
	}
	debug_print(DEBUG_MAIN, 1, "\n");

	bf_get_reloc_table_code_section(handle_void);
#if 0
	debug_print(DEBUG_MAIN, 1, "reloc_table_code_sz=0x%"PRIx64"\n", handle->reloc_table_code_sz);
	for (n = 0; n < handle->reloc_table_code_sz; n++) {
		debug_print(DEBUG_MAIN, 1, "reloc_table_code:addr = 0x%"PRIx64", size = 0x%"PRIx64", value = 0x%"PRIx64", section_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_code[n].address,
			handle->reloc_table_code[n].size,
			handle->reloc_table_code[n].value,
			handle->reloc_table_code[n].section_index,
			handle->reloc_table_code[n].section_name,
			handle->reloc_table_code[n].symbol_name);
	}
#endif
	bf_get_reloc_table_data_section(handle_void);
#if 0
	for (n = 0; n < handle->reloc_table_data_sz; n++) {
		debug_print(DEBUG_MAIN, 1, "reloc_table_data:addr = 0x%"PRIx64", size = 0x%"PRIx64", value = 0x%"PRIx64", section_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_data[n].address,
			handle->reloc_table_data[n].size,
			handle->reloc_table_data[n].value,
			handle->reloc_table_data[n].section_index,
			handle->reloc_table_data[n].section_name,
			handle->reloc_table_data[n].symbol_name);
	}
#endif
	bf_get_reloc_table_rodata_section(handle_void);
#if 0
	for (n = 0; n < handle->reloc_table_rodata_sz; n++) {
		debug_print(DEBUG_MAIN, 1, "reloc_table_rodata:addr = 0x%"PRIx64", size = 0x%"PRIx64", value = 0x%"PRIx64", section_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_rodata[n].address,
			handle->reloc_table_rodata[n].size,
			handle->reloc_table_rodata[n].value,
			handle->reloc_table_rodata[n].section_index,
			handle->reloc_table_rodata[n].section_name,
			handle->reloc_table_rodata[n].symbol_name);
	}
#endif	
	debug_print(DEBUG_MAIN, 1, "handle=%p\n", handle_void);
	tmp = bf_disassemble_init(handle_void, inst_size, inst);
	//tmp = bf_disassembler_set_options(handle_void, "att");

	dis_instructions.bytes_used = 0;
	inst_exe = &inst_log_entry[0];

	tmp = external_entry_points_init(external_entry_points, handle_void);
	if (tmp) return 1;

	debug_print(DEBUG_MAIN, 1, "Number of functions = %d\n", n);
	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if (external_entry_points[n].valid != 0) {
		debug_print(DEBUG_MAIN, 1, "%d: type = %d, sect_offset = %d, sect_id = %d, sect_index = %d, &%s() = 0x%04"PRIx64"\n",
			n,
			external_entry_points[n].type,
			external_entry_points[n].section_offset,
			external_entry_points[n].section_id,
			external_entry_points[n].section_index,
			external_entry_points[n].name,
			external_entry_points[n].value);
		}
	}

	tmp = bf_link_reloc_table_code_to_external_entry_point(handle_void, external_entry_points);
	if (tmp) return 1;

#if 0
	for (n = 0; n < handle->reloc_table_code_sz; n++) {
		debug_print(DEBUG_MAIN, 1, "reloc_table_code:addr = 0x%"PRIx64", size = 0x%"PRIx64", type = %d, function_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_code[n].address,
			handle->reloc_table_code[n].size,
			handle->reloc_table_code[n].type,
			handle->reloc_table_code[n].external_functions_index,
			handle->reloc_table_code[n].section_name,
			handle->reloc_table_code[n].symbol_name);
	}
#endif			
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1)) {  /* 1 == Implemented in this .o file */
			struct process_state_s *process_state;
			struct entry_point_s *entry_point = self->entry_point;
			
			debug_print(DEBUG_MAIN, 1, "Start function block: %s:0x%"PRIx64"\n", external_entry_points[l].name, external_entry_points[l].value);	
			process_state = &external_entry_points[l].process_state;
			memory_text = process_state->memory_text;
			memory_stack = process_state->memory_stack;
			memory_reg = process_state->memory_reg;
			memory_data = process_state->memory_data;
			memory_used = process_state->memory_used;
			external_entry_points[l].inst_log = inst_log;
			/* EIP is a parameter for process_block */
			/* Update EIP */
			//memory_reg[2].offset_value = 0;
			//inst_log_prev = 0;
			entry_point[0].used = 1;
			entry_point[0].esp_init_value = memory_reg[0].init_value;
			entry_point[0].esp_offset_value = memory_reg[0].offset_value;
			entry_point[0].ebp_init_value = memory_reg[1].init_value;
			entry_point[0].ebp_offset_value = memory_reg[1].offset_value;
			entry_point[0].eip_init_value = memory_reg[2].init_value;
			entry_point[0].eip_offset_value = memory_reg[2].offset_value;
			entry_point[0].previous_instuction = 0;

			print_mem(memory_reg, 1);
			debug_print(DEBUG_MAIN, 1, "LOGS: inst_log = 0x%"PRIx64"\n", inst_log);
			do {
				not_finished = 0;
				for (n = 0; n < self->entry_point_list_length; n++ ) {
					/* EIP is a parameter for process_block */
					/* Update EIP */
					//debug_print(DEBUG_MAIN, 1, "entry:%d\n",n);
					if (entry_point[n].used) {
						memory_reg[0].init_value = entry_point[n].esp_init_value;
						memory_reg[0].offset_value = entry_point[n].esp_offset_value;
						memory_reg[1].init_value = entry_point[n].ebp_init_value;
						memory_reg[1].offset_value = entry_point[n].ebp_offset_value;
						memory_reg[2].init_value = entry_point[n].eip_init_value;
						memory_reg[2].offset_value = entry_point[n].eip_offset_value;
						inst_log_prev = entry_point[n].previous_instuction;
						not_finished = 1;
						debug_print(DEBUG_MAIN, 1, "LOGS: EIPinit = 0x%"PRIx64"\n", memory_reg[2].init_value);
						debug_print(DEBUG_MAIN, 1, "LOGS: EIPoffset = 0x%"PRIx64"\n", memory_reg[2].offset_value);
						err = process_block(self, process_state, handle_void, inst_log_prev, inst_size);
						/* clear the entry after calling process_block */
						if (err) {
							debug_print(DEBUG_MAIN, 1, "process_block failed\n");
							return err;
						}
						entry_point[n].used = 0;
					}
				}
			} while (not_finished);	
			external_entry_points[l].inst_log_end = inst_log - 1;
			debug_print(DEBUG_MAIN, 1, "LOGS: inst_log_end = 0x%"PRIx64"\n", inst_log);
		}
	}
/*
	if (entry_point_list_length > 0) {
		for (n = 0; n < entry_point_list_length; n++ ) {
			debug_print(DEBUG_MAIN, 1, "eip = 0x%"PRIx64", prev_inst = 0x%"PRIx64"\n",
				entry_point[n].eip_offset_value,
				entry_point[n].previous_instuction);
		}
	}
*/
	//inst_log--;
	debug_print(DEBUG_MAIN, 1, "EXE FINISHED\n");
	debug_print(DEBUG_MAIN, 1, "Instructions=%"PRId64", entry_point_list_length=%"PRId64"\n",
		inst_log,
		self->entry_point_list_length);

	/* Correct inst_log to identify how many dis_instructions there have been */
	//inst_log--;

	print_dis_instructions(self);
	debug_print(DEBUG_MAIN, 1, "start tidy\n");
	tmp = tidy_inst_log(self);
	print_dis_instructions(self);
	self->flag_dependency = calloc(inst_log, sizeof(int));
	self->flag_dependency_opcode = calloc(inst_log, sizeof(int));
	self->flag_result_users = calloc(inst_log, sizeof(int));
	self->flag_dependency_size = inst_log;
	debug_print(DEBUG_MAIN, 1, "got here I-0\n");
	debug_print(DEBUG_MAIN, 1, "INFO: flag_dep_size initialised to 0x%"PRIx64"\n", inst_log);
	if (inst_log > 0xe2c) {
		debug_print(DEBUG_MAIN, 1, "INFO: flag_result_users 0xe2c = 0x%x\n", self->flag_result_users[0xe2c]);
	}
	debug_print(DEBUG_MAIN, 1, "start build_flag_dependency_table\n");
	tmp = build_flag_dependency_table(self);
	debug_print(DEBUG_MAIN, 1, "got here I-1\n");
	if (inst_log > 0xe2c) {
		debug_print(DEBUG_MAIN, 1, "INFO: flag_result_users 0xe2c = 0x%x\n", self->flag_result_users[0xe2c]);
	}
	debug_print(DEBUG_MAIN, 1, "got here I-2\n");
	debug_print(DEBUG_MAIN, 1, "start print_flag_dependency_table\n");
	tmp = print_flag_dependency_table(self);
	debug_print(DEBUG_MAIN, 1, "got here I-3\n");
	if (inst_log > 0xe2c) {
		debug_print(DEBUG_MAIN, 1, "INFO: flag_result_users 0xe2c = 0x%x\n", self->flag_result_users[0xe2c]);
	}
	debug_print(DEBUG_MAIN, 1, "got here I-4\n");
	tmp = fix_flag_dependency_instructions(self);
	if (inst_log > 0xe2c) {
		debug_print(DEBUG_MAIN, 1, "INFO: flag_result_users 0xe2c = 0x%x\n", self->flag_result_users[0xe2c]);
	}
	//tmp = insert_nop_after(self, 4);
	print_dis_instructions(self);
	/* Build the control flow nodes from the instructions. */
	tmp = build_control_flow_nodes(self, nodes, &nodes_size);
	self->nodes_size = nodes_size;
	tmp = print_control_flow_nodes(self, nodes, nodes_size);
//	print_dis_instructions(self);
	debug_print(DEBUG_MAIN, 1, "got here 1\n");
	/* enter the start node into each external_entry_point */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = find_node_from_inst(self, nodes, nodes_size, external_entry_points[l].inst_log);
			if (tmp == 0) {
				debug_print(DEBUG_MAIN, 1, "find_node_from_inst failed. entry[0x%x:%s]:start inst = 0x%"PRIx64", start node = 0x%x\n",
					l,
					external_entry_points[l].name,
					external_entry_points[l].inst_log,
					external_entry_points[l].start_node);
				exit(1);
			}
			external_entry_points[l].start_node = tmp;
			debug_print(DEBUG_MAIN, 1, "entry[0x%x]:start inst = 0x%"PRIx64", start node = 0x%x\n",
				l,
				external_entry_points[l].inst_log,
				external_entry_points[l].start_node);
		}
	}
	/* extract the nodes from the global nodes list and assign them to each external_entry point.
	 * extract the instructions from the global instruction log and assign them to each external_entry_point.
	 * This will permit future optimizations, allowing processing of each external_entry point in parallel. */
	/* This will also permit early complexity analysis by gathering the number of branches in each function
	 * and multiplying them together. This will give the number of required "paths". */
	/* This will also permit a labels table per function, so local varibales in one function
	 * can have the same label as a local varibale in another function because they have no overlapping scope.
	 * This is particularly useful for stack variables naming and their subsequent representation in LLVM IR.
	 */
	/* tmp = create_function_node_members() mapping from nodes in externel_entry_point to the global nodes list. */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = create_function_node_members(self, &external_entry_points[l]);
		}
	}
	
	tmp = output_cfg_dot_basic(self, nodes, nodes_size);

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid) && (external_entry_points[l].type == 1)) {
			tmp = output_cfg_dot_basic2(self, &external_entry_points[l]);
		}
	}
	paths = calloc(paths_size, sizeof(struct path_s));
	for (n = 0; n < paths_size; n++) {
		paths[n].path = calloc(1000, sizeof(int));
	}
	loops = calloc(loops_size, sizeof(struct loop_s));

	for (n = 0; n < loops_size; n++) {
		loops[n].list = calloc(1000, sizeof(int));
	}

	ast = calloc(1, sizeof(struct ast_s));
	ast->ast_container = calloc(AST_SIZE, sizeof(struct ast_container_s));
	ast->ast_if_then_else = calloc(AST_SIZE, sizeof(struct ast_if_then_else_s));
	ast->ast_if_then_goto = calloc(AST_SIZE, sizeof(struct ast_if_then_goto_s));
	ast->ast_loop = calloc(AST_SIZE, sizeof(struct ast_loop_s));
	ast->ast_loop_container = calloc(AST_SIZE, sizeof(struct ast_loop_container_s));
	ast->ast_loop_then_else = calloc(AST_SIZE, sizeof(struct ast_loop_then_else_s));
	ast->ast_entry = calloc(AST_SIZE, sizeof(struct ast_entry_s));
	ast->container_size = 0;
	ast->if_then_else_size = 0;
	ast->if_then_goto_size = 0;
	ast->loop_size = 0;
	ast->loop_container_size = 0;
	ast->loop_then_else_size = 0;


	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
//	for (l = 17; l < 19; l++) {
//	for (l = 37; l < 38; l++) {
//		if (external_entry_points[l].valid) {
//			nodes[external_entry_points[l].start_node].entry_point = l + 1;
//		}
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "Starting external entry point %d:%s\n", l, external_entry_points[l].name);
			int paths_used = 0;
			int loops_used = 0;
			int *multi_ret = NULL;
			int multi_ret_size;

			for (n = 0; n < paths_size; n++) {
				paths[n].used = 0;
				paths[n].path_prev = 0;
				paths[n].path_prev_index = 0;
				paths[n].path_size = 0;
				paths[n].type = PATH_TYPE_UNKNOWN;
				paths[n].loop_head = 0;
			}
			for (n = 0; n < loops_size; n++) {
				loops[n].size = 0;
				loops[n].head = 0;
				loops[n].nest = 0;
			}

			tmp = build_control_flow_paths(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size,
				paths, &paths_size, &paths_used, external_entry_points[l].start_node);
			debug_print(DEBUG_MAIN, 1, "tmp = %d, PATHS used = %d\n", tmp, paths_used);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Failed at external entry point %d:%s\n", l, external_entry_points[l].name);
				exit(1);
			}
			tmp = analyse_multi_ret(self, paths, &paths_size, &multi_ret_size, &multi_ret);
			if (multi_ret_size) {
				debug_print(DEBUG_MAIN, 1, "tmp = %d, multi_ret_size = %d\n", tmp, multi_ret_size);
				for (m = 0; m < multi_ret_size; m++) {
					debug_print(DEBUG_MAIN, 1, "multi_ret: node 0x%x\n", multi_ret[m]);
				}
				if (multi_ret_size == 2) {
					tmp = analyse_merge_nodes(self, external_entry_points[l].nodes, &(external_entry_points[l].nodes_size), multi_ret[0], multi_ret[1]);
					tmp = build_control_flow_paths(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size,
						paths, &paths_size, &paths_used, external_entry_points[l].start_node);
				} else if (multi_ret_size > 2) {
					debug_print(DEBUG_MAIN, 1, "multi_ret_size > 2 not yet handled\n");
					exit(1);
				}
			}
			//tmp = print_control_flow_paths(self, paths, &paths_size);

			tmp = build_control_flow_loops(self, paths, &paths_size, loops, &loops_size);
			tmp = build_control_flow_loops_node_members(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size, loops, &loops_size);
			tmp = build_node_paths(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size, paths, &paths_size, l + 1);

			external_entry_points[l].paths_size = paths_used;

			external_entry_points[l].paths = calloc(paths_used, sizeof(struct path_s));
			if (0 == paths_used) {
				debug_print(DEBUG_MAIN, 1, "INFO: paths_used = 0, %s, %p\n", external_entry_points[l].name, external_entry_points[l].paths);
				exit(1);
			}
			for (n = 0; n < paths_used; n++) {
				external_entry_points[l].paths[n].used = paths[n].used;
				external_entry_points[l].paths[n].path_prev = paths[n].path_prev;
				external_entry_points[l].paths[n].path_prev_index = paths[n].path_prev_index;
				external_entry_points[l].paths[n].path_size = paths[n].path_size;
				external_entry_points[l].paths[n].type = paths[n].type;
				external_entry_points[l].paths[n].loop_head = paths[n].loop_head;

				external_entry_points[l].paths[n].path = calloc(paths[n].path_size, sizeof(int));
				for (m = 0; m  < paths[n].path_size; m++) {
					external_entry_points[l].paths[n].path[m] = paths[n].path[m];
				}

			}
			for (n = 0; n < loops_size; n++) {
				if (loops[n].size != 0) {
					loops_used = n + 1;
				}
			}
			debug_print(DEBUG_MAIN, 1, "loops_used = 0x%x\n", loops_used);
			external_entry_points[l].loops_size = loops_used;
			external_entry_points[l].loops = calloc(loops_used, sizeof(struct loop_s));
			for (n = 0; n < loops_used; n++) {
				external_entry_points[l].loops[n].head = loops[n].head;
				external_entry_points[l].loops[n].size = loops[n].size;
				external_entry_points[l].loops[n].nest = loops[n].nest;
				external_entry_points[l].loops[n].list = calloc(loops[n].size, sizeof(int));
				for (m = 0; m  < loops[n].size; m++) {
					external_entry_points[l].loops[n].list[m] = loops[n].list[m];
				}
			}
		}
	}
	debug_print(DEBUG_MAIN, 1, "got here 2\n");
	/* Node specific processing */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = build_node_dominance(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
			tmp = analyse_control_flow_node_links(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
			tmp = build_node_type(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
			//tmp = build_control_flow_depth(self, nodes, &nodes_size,
			//		paths, &paths_size, &paths_used, external_entry_points[l].start_node);
			tmp = build_control_flow_loops_multi_exit(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size,
				external_entry_points[l].loops, external_entry_points[l].loops_size);
		}
	}
	debug_print(DEBUG_MAIN, 1, "got here 3\n");

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "print_control_flow_nodes for function %s\n", external_entry_points[l].name);
			tmp = print_control_flow_nodes(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}
	debug_print(DEBUG_MAIN, 1, "got here 4\n");


	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			tmp = build_node_if_tail(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
			for (n = 0; n < external_entry_points[l].nodes_size; n++) {
				if ((external_entry_points[l].nodes[n].type == NODE_TYPE_IF_THEN_ELSE) &&
					(external_entry_points[l].nodes[n].if_tail == 0)) {
					debug_print(DEBUG_MAIN, 1, "FAILED: Node 0x%x with no if_tail\n", n);
				}
			}
		}
	}
	/* Build the node members list for each function */
	/* This allows us to output a single function in the .dot output files. */	
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid) {
			/* Not needed any more */
			/* tmp = build_entry_point_node_members(self, &external_entry_points[l], nodes_size); */
			tmp = print_entry_point_node_members(self, &external_entry_points[l]);
		}
	}
	
#if 1
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
//	for (l = 21; l < 22; l++) {
//	for (l = 37; l < 38; l++) {
		if (external_entry_points[l].valid) {
			tmp = external_entry_points[l].start_node;
			debug_print(DEBUG_ANALYSE_PATHS, 1, "External entry point %d: type=%d, name=%s inst_log=0x%lx, start_node=0x%x\n", l, external_entry_points[l].type, external_entry_points[l].name, external_entry_points[l].inst_log, tmp);
			tmp = print_control_flow_paths(self, external_entry_points[l].paths, &(external_entry_points[l].paths_size));
			tmp = print_control_flow_loops(self, external_entry_points[l].loops, &(external_entry_points[l].loops_size));
		}
	}
#endif
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			debug_print(DEBUG_MAIN, 1, "print_control_flow_nodes for function %s\n", external_entry_points[l].name);
			tmp = print_control_flow_nodes(self, external_entry_points[l].nodes, external_entry_points[l].nodes_size);
		}
	}

//	Doing this after SSA now.
#if 0
//      Don't bother with the AST output for now 
//	tmp = output_cfg_dot(self, nodes, nodes_size);
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
//	for (l = 0; l < 21; l++) {
//	for (l = 21; l < 22; l++) {
//	for (l = 4; l < 5; l++) {
//		if (l == 21) continue;

		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			/* Control flow graph to Abstract syntax tree */
			debug_print(DEBUG_MAIN, 1, "cfg_to_ast. external entry point %d:%s\n", l, external_entry_points[l].name);
			external_entry_points[l].start_ast_container = ast->container_size;
			tmp = cfg_to_ast(self, nodes, &nodes_size, ast, external_entry_points[l].start_node);
			tmp = print_ast(self, ast);
		}
	}
	tmp = output_ast_dot(self, ast, nodes, &nodes_size);
	/* FIXME */
	//goto end_main;
#endif

#if 1


	if (self->entry_point_list_length > 0) {
		for (n = 0; n < self->entry_point_list_length; n++ ) {
			struct entry_point_s *entry_point = self->entry_point;

			if (entry_point[n].used) {
				debug_print(DEBUG_MAIN, 1, "%d, eip = 0x%"PRIx64", prev_inst = 0x%"PRIx64"\n",
					entry_point[n].used,
					entry_point[n].eip_offset_value,
					entry_point[n].previous_instuction);
			}
		}
	}


	/****************************************************************
	 * This section deals with building the node_used_register table
	 * The nodes can be processed in any order for this step.
	 * SRC, DST -> PHI SRC
	 * DST, SRC -> No PHI needed.
	 * DST first -> No PHI needed.
	 * SRC first -> PHI SRC.
	 * 0 = not seen.
	 * 1 = SRC first
	 * 2 = DST first
	 * If SRC and DST in same instruction, set SRC first.
	 ****************************************************************/
	/* FIXME: TODO convert nodes to external_entry_points[l].nodes */
	exit(1);
	tmp = init_node_used_register_table(self, nodes, nodes_size);
	tmp = fill_node_used_register_table(self, nodes, nodes_size);
	if (tmp) {
		debug_print(DEBUG_MAIN, 1, "FIXME: fill node used register table failed\n");
		exit(1);
	}

	/****************************************************************
	 * This section deals with building the initial PHI DST instructions
	 * Create a PHI instruction for each entry in the node_used_register table,
	 * the PHI instruction DST register is identified and set.
         * This problem is then reduced to a node level problem, and not an instruction level problem.
         * The nodes can be processed in any order for this step.
	 ****************************************************************/

	tmp = fill_node_phi_dst(self, nodes, nodes_size);

	/****************************************************************
	 * Then for each path running through each PHI node, locate the previous node that used that register.
	 * Enter the path number, previously used node into the phi list for that register.
	 * The nodes must be processed in path order for this step.
	 * Optimizations can be made if paths are not unique at the current PHI node or above.
	 * Start at end of path, search back down the path to the current node,
	 * return which base path it is on. Only process if not a previous path.
	 ****************************************************************/

	tmp = fill_node_phi_src(self, nodes, nodes_size);
	/* Scan each of the list of paths in the src, and reduce the list to
	 * a list of immediately/first previous nodes with assocated node that assigned the register.
         * Also do sanity checks on the path nodes lists based on first_prev_node. 
	 * This reduces the PHI to a format similar to that used in LLVM */
	tmp = fill_phi_node_list(self, nodes, nodes_size);
	/************************************************************
	 * This section deals with starting true SSA.
	 * This bit sets the valid_id to 0 for both dst and src.
	 ************************************************************/
	for (n = 1; n < inst_log; n++) {
		inst_log1 =  &inst_log_entry[n];
		inst_log1->value1.value_id = 0;
		inst_log1->value1.indirect_value_id = 0;
		inst_log1->value2.value_id = 0;
		inst_log1->value2.indirect_value_id = 0;
		inst_log1->value3.value_id = 0;
		inst_log1->value3.indirect_value_id = 0;
	}
	
	/************************************************************
	 * This bit assigned a variable ID and label to each assignment (dst).
	 ************************************************************/

	label_redirect = calloc(10000, sizeof(struct label_redirect_s));
	self->label_redirect = label_redirect;
	labels = calloc(10000, sizeof(struct label_s));
	self->labels = labels;
	variable_id = 0x100;
	/* n < inst_log verified to be correct limit */
	for (n = 1; n < inst_log; n++) {
		struct label_s label;
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		debug_print(DEBUG_MAIN, 1, "value to log_to_label:inst = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64"\n",
				n,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value,
				inst_log1->value1.indirect_value_id);

		switch (instruction->opcode) {
		case NOP:
			break;
		case MOV:
		case ADD:
		case ADC:
		case SUB:
		case SBB:
		case MUL:
		case IMUL:
		case OR:
		case XOR:
		case rAND:
		case NOT:
		case NEG:
		case SHL:
		case SHR:
		case SAL:
		case SAR:
		case SEX:
		case ICMP:
			/* If dstA.indirect, assign the dst label to indirect_value_id
			   In the indirect case the value_id is a SRC and not a DST */
			/* If not dstA.indirect, assign the dst label to value_id. */
			if (IND_DIRECT != instruction->dstA.indirect) {
				inst_log1->value3.indirect_value_id = variable_id;
			} else {
				inst_log1->value3.value_id = variable_id;
			}
			/* Override the EXE setting for now */
			if (inst_log1->value3.value_scope == 1) {
				inst_log1->value3.value_scope = 2;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->dstA.store,
				instruction->dstA.indirect,
				instruction->dstA.index,
				instruction->dstA.relocated,
				inst_log1->value3.value_scope,
				inst_log1->value3.value_id,
				inst_log1->value3.indirect_offset_value,
				inst_log1->value3.indirect_value_id,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value3 unknown label %x\n", n);
			}
			if (!tmp) {
				label_redirect[variable_id].redirect = variable_id;
				labels[variable_id].scope = label.scope;
				labels[variable_id].type = label.type;
				labels[variable_id].lab_pointer += label.lab_pointer;
				labels[variable_id].value = label.value;
			}

			break;

		/* Specially handled because value3 is not assigned and writen to a destination. */
		case TEST:
		case CMP:
			break;

		case CALL:
			debug_print(DEBUG_MAIN, 1, "SSA CALL inst_log 0x%x\n", n);
			if (IND_DIRECT != instruction->dstA.indirect) {
				inst_log1->value3.indirect_value_id = variable_id;
			} else {
				inst_log1->value3.value_id = variable_id;
			}
			break;
		case IF:
		case BC:
		case RET:
		case JMP:
		case JMPT:
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "SSA1 failed for Inst:0x%x, OP 0x%x\n", n, instruction->opcode);
			return 1;
			break;
		}
		variable_id++;
	}

	for (n = 0x100; n < 0x130; n++) {
		struct label_s *label;
		tmp = label_redirect[n].redirect;
		label = &labels[tmp];
		printf("Label 0x%x:", n);
		tmp = output_label(label, stdout);
		printf("\n");
	}

	/* Assign labels to PHI instructions dst */

	for (n = 1; n <= nodes_size; n++) {
			printf("JCD: scanning node phi 0x%x\n", n);
		if (nodes[n].phi_size) {
			printf("JCD: phi insts found at node 0x%x\n", n);
			for (m = 0; m < nodes[n].phi_size; m++) {
				nodes[n].phi[m].value_id = variable_id;
				label_redirect[variable_id].redirect = variable_id;
				labels[variable_id].scope = 1;
				labels[variable_id].type = 1;
				labels[variable_id].lab_pointer = 0;
				labels[variable_id].value = variable_id;
				variable_id++;
			}
		}
	}

	/* TODO: add code to process the used_registers to identify registers
	 * that are assigned dst in a previous node or function param
	 */

	/* Fill in the reg dependency table */
	for (n = 1; n <= nodes_size; n++) {
		for (m = 0; m < MAX_REG; m++) {
			int value_id;
			if (1 == nodes[n].used_register[m].seen) {
				int node;
				int entry_point = 0;
				int found = 0;
				debug_print(DEBUG_MAIN, 1, "Node 0x%x: Reg Used src:0x%x\n", n, m);
				tmp = find_reg_in_phi_list(self, nodes, nodes_size, n, m, &value_id);
				if (!tmp) {
					nodes[n].used_register[m].src_first_value_id = value_id;
					nodes[n].used_register[m].src_first_node = n;
					nodes[n].used_register[m].src_first_label = 1;
					debug_print(DEBUG_MAIN, 1, "Found reg 0x%x in phi. value_id = 0x%x\n", m, value_id);
					continue;
				}
				/* Start searching previous nodes for used_register and phi */
				node = n;
				debug_print(DEBUG_MAIN, 1, "Previous size 0x%x\n", nodes[node].prev_size);
				if (nodes[node].prev_size > 0) {
					debug_print(DEBUG_MAIN, 1, "Previous node 0x%x\n", nodes[node].prev_node[0]);
				}
				while ((nodes[node].prev_size > 0) && (nodes[node].prev_node[0] != 0)) {
					node = nodes[node].prev_node[0];
					debug_print(DEBUG_MAIN, 1, "Previous nodes 0x%x\n", node);
					if (nodes[node].used_register[m].dst) {
						inst_log1 =  &inst_log_entry[nodes[node].used_register[m].dst];
						instruction =  &inst_log1->instruction;
						/* FIXME: Handle indirect */
						/* Indirect should never happen for registers */
						if ((instruction->dstA.store == STORE_REG) &&
							(instruction->dstA.indirect == IND_DIRECT)) {
							tmp = inst_log1->value3.value_id;
						} else {
							printf("BAD DST\n");
							exit(1);
						}
						nodes[n].used_register[m].src_first_value_id = tmp;
						nodes[n].used_register[m].src_first_node = node;
						nodes[n].used_register[m].src_first_label = 2;
						debug_print(DEBUG_MAIN, 1, "Reg DST found 0x%x\n", nodes[node].used_register[m].dst);
						debug_print(DEBUG_MAIN, 1, "node 0x%x, m 0x%x\n", node, m);
						debug_print(DEBUG_MAIN, 1, "value_id = 0x%x, node = 0x%x, label = 0x%x\n",
							nodes[n].used_register[m].src_first_value_id,
							nodes[n].used_register[m].src_first_node,
							nodes[n].used_register[m].src_first_label);

						found = 1;
						break;
					}
					tmp = find_reg_in_phi_list(self, nodes, nodes_size, node, m, &value_id);
					if (!tmp) {
						nodes[n].used_register[m].src_first_value_id = value_id;
						nodes[n].used_register[m].src_first_node = node;
						nodes[n].used_register[m].src_first_label = 1;
						debug_print(DEBUG_MAIN, 1, "Found reg 0x%x in previous 0x%x phi. value_id = 0x%x\n", m, node, value_id);
						debug_print(DEBUG_MAIN, 1, "value_id = 0x%x, node = 0x%x, label = 0x%x\n",
							nodes[n].used_register[m].src_first_value_id,
							nodes[n].used_register[m].src_first_node,
							nodes[n].used_register[m].src_first_label);
						found = 1;
						break;
					}
				}
					

				if (!found) {
					/* All other searches failed, must be a param */
					/* Build the param to label pointer tables, and use it to not duplicate param labels. */
					entry_point = nodes[n].entry_point;
					tmp = self->external_entry_points[entry_point].param_reg_label[m];
					if (0 == tmp) {
						nodes[n].used_register[m].src_first_value_id = variable_id;
						nodes[n].used_register[m].src_first_node = 0;
						nodes[n].used_register[m].src_first_label = 3;
						label_redirect[variable_id].redirect = variable_id;
						labels[variable_id].scope = 2;
						labels[variable_id].type = 1;
						labels[variable_id].lab_pointer = 1;
						labels[variable_id].value = m;
						self->external_entry_points[entry_point].param_reg_label[m] = variable_id;
						debug_print(DEBUG_MAIN, 1, "Found reg 0x%x in param, label_id = 0x%x\n", m, variable_id);
						debug_print(DEBUG_MAIN, 1, "value_id = 0x%x, node = 0x%x, label = 0x%x\n",
							nodes[n].used_register[m].src_first_value_id,
							nodes[n].used_register[m].src_first_node,
							nodes[n].used_register[m].src_first_label);
						variable_id++;
					} else {
						nodes[n].used_register[m].src_first_value_id = tmp;
						nodes[n].used_register[m].src_first_node = 0;
						nodes[n].used_register[m].src_first_label = 3;
						debug_print(DEBUG_MAIN, 1, "Found duplicate reg 0x%x in param, label_id = 0x%x\n", m, tmp);
						debug_print(DEBUG_MAIN, 1, "value_id = 0x%x, node = 0x%x, label = 0x%x\n",
							nodes[n].used_register[m].src_first_value_id,
							nodes[n].used_register[m].src_first_node,
							nodes[n].used_register[m].src_first_label);
					}
				}
			}
		}
	}

	for (n = 1; n <= nodes_size; n++) {
		for (m = 0; m < MAX_REG; m++) {
			if (nodes[n].used_register[m].seen) {
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].seen = 0x%x\n", n, m, 
					nodes[n].used_register[m].seen);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].size = 0x%x\n", n, m, 
					nodes[n].used_register[m].size);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].src = 0x%x\n", n, m, 
					nodes[n].used_register[m].src);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].dst = 0x%x\n", n, m, 
					nodes[n].used_register[m].dst);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].src_fist_value_id = 0x%x\n", n, m, 
					nodes[n].used_register[m].src_first_value_id);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].src_fist_node = 0x%x\n", n, m, 
					nodes[n].used_register[m].src_first_node);
				debug_print(DEBUG_MAIN, 1, "node[0x%x].user_register[0x%x].src_fist_label = 0x%x\n", n, m, 
					nodes[n].used_register[m].src_first_label);
			}
		}
	}
	/* Enter value id/label id of param into phi with src node 0. */
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		for (m = 0; m < MAX_REG; m++) {
			if (self->external_entry_points[l].param_reg_label[m]) {
				debug_print(DEBUG_MAIN, 1, "Entry Point 0x%x: Found reg 0x%x as param label 0x%x\n", l, m,
					self->external_entry_points[l].param_reg_label[m]);
			}
		}
	}
	/* Enter value id/label id of param into phi with src node 0. */
	/* TODO */

	/* Assign labels to instructions src */
	/* TODO: WIP: Work in progress */
	tmp = assign_labels_to_src(self, &variable_id);

	self->local_counter = variable_id;

	print_dis_instructions(self);
	for (n = 0x100; n < 0x130; n++) {
		struct label_s *label;
		tmp = label_redirect[n].redirect;
		label = &labels[tmp];
		printf("Label 0x%x:", n);
		tmp = output_label(label, stdout);
		printf("\n");
	}

	/************************************************************
	 * This section deals with correcting SSA for branches/joins.
	 * This bit creates the labels table, ready for the next step.
	 ************************************************************/
	debug_print(DEBUG_MAIN, 1, "Number of labels = 0x%x\n", self->local_counter);
	/* FIXME: +1 added as a result of running valgrind, but need a proper fix */
//	label_redirect = calloc(self->local_counter + 1, sizeof(struct label_redirect_s));
//	labels = calloc(self->local_counter + 1, sizeof(struct label_s));
//	debug_print(DEBUG_MAIN, 1, "JCD6: self->local_counter=%d\n", self->local_counter);
	labels[0].lab_pointer = 1; /* EIP */
	labels[1].lab_pointer = 1; /* ESP */
	labels[2].lab_pointer = 1; /* EBP */
#if 0	
	/* n <= inst_log verified to be correct limit */
	for (n = 1; n <= inst_log; n++) {
		struct label_s label;
		uint64_t value_id;
		uint64_t value_id2;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		debug_print(DEBUG_MAIN, 1, "value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64"\n",
				n,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value,
				inst_log1->value1.indirect_value_id);

		switch (instruction->opcode) {
		case MOV:
		case ADD:
		case ADC:
		case SUB:
		case SBB:
		case MUL:
		case IMUL:
		case OR:
		case XOR:
		case rAND:
		case NOT:
		case NEG:
		case SHL:
		case SHR:
		case SAL:
		case SAR:
		case SEX:
			if (IND_MEM == instruction->dstA.indirect) {
				value_id3 = inst_log1->value3.indirect_value_id;
			} else {
				value_id3 = inst_log1->value3.value_id;
			}
			if (value_id3 > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->dstA.store,
				instruction->dstA.indirect,
				instruction->dstA.index,
				instruction->dstA.relocated,
				inst_log1->value3.value_scope,
				inst_log1->value3.value_id,
				inst_log1->value3.indirect_offset_value,
				inst_log1->value3.indirect_value_id,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value3 unknown label %x\n", n);
			}
			if (!tmp && value_id3 > 0) {
				label_redirect[value_id3].redirect = value_id3;
				labels[value_id3].scope = label.scope;
				labels[value_id3].type = label.type;
				labels[value_id3].lab_pointer += label.lab_pointer;
				labels[value_id3].value = label.value;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			if (value_id > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->srcA.store,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value,
				inst_log1->value1.indirect_value_id,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value1 unknown label %x\n", n);
			}
			if (!tmp && value_id > 0) {
				label_redirect[value_id].redirect = value_id;
				labels[value_id].scope = label.scope;
				labels[value_id].type = label.type;
				labels[value_id].lab_pointer += label.lab_pointer;
				labels[value_id].value = label.value;
			}
			break;

		/* Specially handled because value3 is not assigned and writen to a destination. */
		case TEST:
		case CMP:
			if (IND_MEM == instruction->dstA.indirect) {
				value_id2 = inst_log1->value2.indirect_value_id;
			} else {
				value_id2 = inst_log1->value2.value_id;
			}
			if (value_id2 > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->dstA.store,
				instruction->dstA.indirect,
				instruction->dstA.index,
				instruction->dstA.relocated,
				inst_log1->value2.value_scope,
				inst_log1->value2.value_id,
				inst_log1->value2.indirect_offset_value,
				inst_log1->value2.indirect_value_id,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value3 unknown label %x\n", n);
			}
			if (!tmp && value_id2 > 0) {
				label_redirect[value_id2].redirect = value_id2;
				labels[value_id2].scope = label.scope;
				labels[value_id2].type = label.type;
				labels[value_id2].lab_pointer += label.lab_pointer;
				labels[value_id2].value = label.value;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}
			if (value_id > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->srcA.store,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value,
				inst_log1->value1.indirect_value_id,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value1 unknown label %x\n", n);
			}
			if (!tmp && value_id > 0) {
				label_redirect[value_id].redirect = value_id;
				labels[value_id].scope = label.scope;
				labels[value_id].type = label.type;
				labels[value_id].lab_pointer += label.lab_pointer;
				labels[value_id].value = label.value;
			}
			break;

		case CALL:
			debug_print(DEBUG_MAIN, 1, "SSA CALL inst_log 0x%x\n", n);
			if (IND_MEM == instruction->dstA.indirect) {
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			if (value_id > self->local_counter) {
				debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
				return 1;
			}
			memset(&label, 0, sizeof(struct label_s));
			tmp = log_to_label(instruction->dstA.store,
				instruction->dstA.indirect,
				instruction->dstA.index,
				instruction->dstA.relocated,
				inst_log1->value3.value_scope,
				inst_log1->value3.value_id,
				inst_log1->value3.indirect_offset_value,
				inst_log1->value3.indirect_value_id,
				&label);
			if (tmp) {
				debug_print(DEBUG_MAIN, 1, "Inst:0x, value3 unknown label %x\n", n);
			}
			if (!tmp && value_id > 0) {
				label_redirect[value_id].redirect = value_id;
				labels[value_id].scope = label.scope;
				labels[value_id].type = label.type;
				labels[value_id].lab_pointer += label.lab_pointer;
				labels[value_id].value = label.value;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				value_id = inst_log1->value1.indirect_value_id;
				if (value_id > self->local_counter) {
					debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
					return 1;
				}
				memset(&label, 0, sizeof(struct label_s));
				tmp = log_to_label(instruction->srcA.store,
					instruction->srcA.indirect,
					instruction->srcA.index,
					instruction->srcA.relocated,
					inst_log1->value1.value_scope,
					inst_log1->value1.value_id,
					inst_log1->value1.indirect_offset_value,
					inst_log1->value1.indirect_value_id,
					&label);
				if (tmp) {
					debug_print(DEBUG_MAIN, 1, "Inst:0x, value1 unknown label %x\n", n);
				}
				if (!tmp && value_id > 0) {
					label_redirect[value_id].redirect = value_id;
					labels[value_id].scope = label.scope;
					labels[value_id].type = label.type;
					labels[value_id].lab_pointer += label.lab_pointer;
					labels[value_id].value = label.value;
				}
			}
			break;
		case IF:
		case RET:
		case JMP:
		case JMPT:
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "SSA1 failed for Inst:0x%x, OP 0x%x\n", n, instruction->opcode);
			return 1;
			break;
		}
	}
	for (n = 0; n < self->local_counter; n++) {
		debug_print(DEBUG_MAIN, 1, "labels 0x%x: redirect=0x%"PRIx64", scope=0x%"PRIx64", type=0x%"PRIx64", lab_pointer=0x%"PRIx64", value=0x%"PRIx64"\n",
			n, label_redirect[n].redirect, labels[n].scope, labels[n].type, labels[n].lab_pointer, labels[n].value);
	}
	
	/************************************************************
	 * This section deals with correcting SSA for branches/joins.
	 * It build bi-directional links to instruction operands.
	 * This section does work for local_reg case. FIXME
	 ************************************************************/
	for (n = 1; n < inst_log; n++) {
		uint64_t value_id;
		uint64_t value_id1;
		uint64_t value_id2;
		uint64_t size;
		uint64_t *inst_list;
		uint64_t mid_start_size;
		struct mid_start_s *mid_start;

		size = 0;
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		value_id1 = inst_log1->value1.value_id;
		value_id2 = inst_log1->value2.value_id;
		switch (instruction->opcode) {
		case MOV:
		case ADD:
		case ADC:
		case MUL:
		case OR:
		case XOR:
		case rAND:
		case SHL:
		case SHR:
		case CMP:
		/* FIXME: TODO */
			value_id = label_redirect[value_id1].redirect;
			if ((1 == labels[value_id].scope) &&
				(1 == labels[value_id].type)) {
				debug_print(DEBUG_MAIN, 1, "Found local_reg Inst:0x%x:value_id:0x%"PRIx64"\n", n, value_id1);
				if (0 == inst_log1->prev_size) {
					debug_print(DEBUG_MAIN, 1, "search_back ended\n");
					return 1;
				}
				if (0 < inst_log1->prev_size) {
					mid_start = calloc(inst_log1->prev_size, sizeof(struct mid_start_s));
					mid_start_size = inst_log1->prev_size;
					for (l = 0; l < inst_log1->prev_size; l++) {
						mid_start[l].mid_start = inst_log1->prev[l];
						mid_start[l].valid = 1;
						debug_print(DEBUG_MAIN, 1, "mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[l].mid_start, l);
					}
					tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 1, inst_log1->instruction.srcA.index, 0, &size, self->search_back_seen, &inst_list);
					if (tmp) {
						debug_print(DEBUG_MAIN, 1, "SSA search_back Failed at inst_log 0x%x\n", n);
						return 1;
					}
				}
			}
			debug_print(DEBUG_MAIN, 1, "SSA inst:0x%x:size=0x%"PRIx64"\n", n, size);
			/* Renaming is only needed if there are more than one label present */
			if (size > 0) {
				uint64_t value_id_highest = value_id;
				inst_log1->value1.prev = calloc(size, sizeof(int *));
				inst_log1->value1.prev_size = size;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					inst_log1->value1.prev[l] = inst_list[l];
					inst_log_l->value3.next = realloc(inst_log_l->value3.next, (inst_log_l->value3.next_size + 1) * sizeof(inst_log_l->value3.next));
					inst_log_l->value3.next[inst_log_l->value3.next_size] =
						 inst_list[l];
					inst_log_l->value3.next_size++;
					if (label_redirect[inst_log_l->value3.value_id].redirect > value_id_highest) {
						value_id_highest = label_redirect[inst_log_l->value3.value_id].redirect;
					}
					debug_print(DEBUG_MAIN, 1, "rel inst:0x%"PRIx64"\n", inst_list[l]);
				}
				debug_print(DEBUG_MAIN, 1, "Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
					label_redirect[value_id1].redirect,
					value_id_highest);
				label_redirect[value_id1].redirect =
					value_id_highest;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					debug_print(DEBUG_MAIN, 1, "Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
						label_redirect[inst_log_l->value3.value_id].redirect,
						value_id_highest);
					label_redirect[inst_log_l->value3.value_id].redirect =
						value_id_highest;
				}
			}
			break;
		default:
			break;
		}
	}
	/************************************************************
	 * This section deals with correcting SSA for branches/joins.
	 * It build bi-directional links to instruction operands.
	 * This section does work for local_stack case.
	 ************************************************************/
	for (n = 1; n < inst_log; n++) {
		uint64_t value_id;
		uint64_t value_id1;
		uint64_t size;
		uint64_t *inst_list;
		uint64_t mid_start_size;
		struct mid_start_s *mid_start;

		size = 0;
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		value_id1 = inst_log1->value1.value_id;
		
		if (value_id1 > self->local_counter) {
			debug_print(DEBUG_MAIN, 1, "SSA Failed at inst_log 0x%x\n", n);
			return 1;
		}
		switch (instruction->opcode) {
		case MOV:
		case ADD:
		case ADC:
		case SUB:
		case SBB:
		case MUL:
		case IMUL:
		case OR:
		case XOR:
		case rAND:
		case NOT:
		case NEG:
		case SHL:
		case SHR:
		case SAL:
		case SAR:
		case CMP:
		case TEST:
		case SEX:
			value_id = label_redirect[value_id1].redirect;
			if ((1 == labels[value_id].scope) &&
				(2 == labels[value_id].type)) {
				debug_print(DEBUG_MAIN, 1, "Found local_stack Inst:0x%x:value_id:0x%"PRIx64"\n", n, value_id1);
				if (0 == inst_log1->prev_size) {
					debug_print(DEBUG_MAIN, 1, "search_back ended\n");
					return 1;
				}
				if (0 < inst_log1->prev_size) {
					mid_start = calloc(inst_log1->prev_size, sizeof(struct mid_start_s));
					mid_start_size = inst_log1->prev_size;
					for (l = 0; l < inst_log1->prev_size; l++) {
						mid_start[l].mid_start = inst_log1->prev[l];
						mid_start[l].valid = 1;
						debug_print(DEBUG_MAIN, 1, "mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[l].mid_start, l);
					}
					tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 2, inst_log1->value1.indirect_init_value, inst_log1->value1.indirect_offset_value, &size, self->search_back_seen, &inst_list);
					if (tmp) {
						debug_print(DEBUG_MAIN, 1, "SSA search_back Failed at inst_log 0x%x\n", n);
						return 1;
					}
				}
			}
			debug_print(DEBUG_MAIN, 1, "SSA inst:0x%x:size=0x%"PRIx64"\n", n, size);
			/* Renaming is only needed if there are more than one label present */
			if (size > 0) {
				uint64_t value_id_highest = value_id;
				inst_log1->value1.prev = calloc(size, sizeof(int *));
				inst_log1->value1.prev_size = size;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					inst_log1->value1.prev[l] = inst_list[l];
					inst_log_l->value3.next = realloc(inst_log_l->value3.next, (inst_log_l->value3.next_size + 1) * sizeof(inst_log_l->value3.next));
					inst_log_l->value3.next[inst_log_l->value3.next_size] =
						 inst_list[l];
					inst_log_l->value3.next_size++;
					if (label_redirect[inst_log_l->value3.value_id].redirect > value_id_highest) {
						value_id_highest = label_redirect[inst_log_l->value3.value_id].redirect;
					}
					debug_print(DEBUG_MAIN, 1, "rel inst:0x%"PRIx64"\n", inst_list[l]);
				}
				debug_print(DEBUG_MAIN, 1, "Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
					label_redirect[value_id1].redirect,
					value_id_highest);
				label_redirect[value_id1].redirect =
					value_id_highest;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					debug_print(DEBUG_MAIN, 1, "Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
						label_redirect[inst_log_l->value3.value_id].redirect,
						value_id_highest);
					label_redirect[inst_log_l->value3.value_id].redirect =
						value_id_highest;
				}
			}
			break;
		case IF:
		case RET:
		case JMP:
		case JMPT:
			break;
		case CALL:
			//debug_print(DEBUG_MAIN, 1, "SSA2 failed for inst:0x%x, CALL\n", n);
			//return 1;
			break;
		default:
			debug_print(DEBUG_MAIN, 1, "SSA2 failed for inst:0x%x, OP 0x%x\n", n, instruction->opcode);
			return 1;
			break;
		/* FIXME: TODO */
		}
	}
#endif
	/********************************************************
	 * This section filters out duplicate param_reg entries.
         * from the labels table: FIXME: THIS IS NOT NEEDED NOW
	 ********************************************************/
#if 0
	for (n = 0; n < (self->local_counter - 1); n++) {
		int tmp1;
		tmp1 = label_redirect[n].redirect;
		debug_print(DEBUG_MAIN, 1, "param_reg:scanning base label 0x%x\n", n);
		if ((tmp1 == n) &&
			(labels[tmp1].scope == 2) &&
			(labels[tmp1].type == 1)) {
			int tmp2;
			/* This is a param_stack */
			for (l = n + 1; l < self->local_counter; l++) {
				debug_print(DEBUG_MAIN, 1, "param_reg:scanning label 0x%x\n", l);
				tmp2 = label_redirect[l].redirect;
				if ((tmp2 == n) &&
					(labels[tmp2].scope == 2) &&
					(labels[tmp2].type == 1) &&
					(labels[tmp1].value == labels[tmp2].value) ) {
					debug_print(DEBUG_MAIN, 1, "param_stack:found duplicate\n");
					label_redirect[l].redirect = n;
				}
			}
		}
	}
#endif
	/***************************************************
	 * Register labels in order to print:
	 * 	Function params,
	 *	local vars.
	 ***************************************************/
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid &&
			external_entry_points[l].type == 1) {
		tmp = scan_for_labels_in_function_body(self, &external_entry_points[l],
				external_entry_points[l].inst_log,
				external_entry_points[l].inst_log_end,
				label_redirect,
				labels);
		if (tmp) {
			debug_print(DEBUG_MAIN, 1, "Unhandled scan instruction 0x%x\n", l);
			return 1;
		}

		/* Expected param order: %rdi, %rsi, %rdx, %rcx, %r08, %r09 
		                         0x40, 0x38, 0x18, 0x10, 0x50, 0x58, then stack */
		
		debug_print(DEBUG_MAIN, 1, "scanned: params = 0x%x, locals = 0x%x\n",
			external_entry_points[l].params_size,
			external_entry_points[l].locals_size);
		}
	}

	/***************************************************
	 * This section sorts the external entry point params to the correct order
	 ***************************************************/
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		for (m = 0; m < REG_PARAMS_ORDER_MAX; m++) {
			struct label_s *label;
			for (n = 0; n < external_entry_points[l].params_size; n++) {
				uint64_t tmp_param;
				tmp = external_entry_points[l].params[n];
				debug_print(DEBUG_MAIN, 1, "JCD5: labels 0x%x, params_size=%d\n", tmp, external_entry_points[l].params_size);
				if (tmp >= self->local_counter) {
					debug_print(DEBUG_MAIN, 1, "Invalid entry point 0x%x, l=%d, m=%d, n=%d, params_size=%d\n",
						tmp, l, m, n, external_entry_points[l].params_size);
					return 0;
				}
				label = &labels[tmp];
				debug_print(DEBUG_MAIN, 1, "JCD5: labels 0x%x\n", external_entry_points[l].params[n]);
				debug_print(DEBUG_MAIN, 1, "JCD5: label=%p, l=%d, m=%d, n=%d\n", label, l, m, n);
				debug_print(DEBUG_MAIN, 1, "reg_params_order = 0x%x,", reg_params_order[m]);
				debug_print(DEBUG_MAIN, 1, " label->value = 0x%"PRIx64"\n", label->value);
				if ((label->scope == 2) &&
					(label->type == 1) &&
					(label->value == reg_params_order[m])) {
					/* Swap params */
					/* FIXME: How to handle the case of params_size <= n or m */
					if (n != m) {
						debug_print(DEBUG_MAIN, 1, "JCD4: swapping n=0x%x and m=0x%x\n", n, m);
						tmp = external_entry_points[l].params_size;
						if ((m >= tmp || n >= tmp)) { 
							external_entry_points[l].params_size++;
							external_entry_points[l].params =
								realloc(external_entry_points[l].params, external_entry_points[l].params_size * sizeof(int));
							/* FIXME: Need to get label right */
							external_entry_points[l].params[external_entry_points[l].params_size - 1] =
								self->local_counter;
							self->local_counter++;
						}
						tmp_param = external_entry_points[l].params[n];
						external_entry_points[l].params[n] =
							external_entry_points[l].params[m];
						external_entry_points[l].params[m] = tmp_param;
					}
				}
			}
		}
	}




	/***************************************************
	 * This section, PARAM, deals with converting
	 * function params to reference locals.
	 * e.g. Change local0011 = function(param_reg0040);
	 *      to     local0011 = function(local0009);
	 ***************************************************/
// FIXME: Working on this
	for (n = 1; n < inst_log; n++) {
		struct label_s *label;
		uint64_t value_id1;
		uint64_t size;
		uint64_t *inst_list;
		struct extension_call_s *call;
		struct external_entry_point_s *external_entry_point;
		uint64_t mid_start_size;
		struct mid_start_s *mid_start;

		size = 0;
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		value_id1 = inst_log1->value1.value_id;

		if (value_id1 > self->local_counter) {
			debug_print(DEBUG_MAIN, 1, "PARAM Failed at inst_log 0x%x\n", n);
			return 1;
		}
		switch (instruction->opcode) {
		case CALL:
			debug_print(DEBUG_MAIN, 1, "PRINTING INST CALL\n");
			tmp = print_inst(self, instruction, n, labels);
			external_entry_point = &external_entry_points[instruction->srcA.index];
			inst_log1->extension = calloc(1, sizeof(struct extension_call_s));
			call = inst_log1->extension;
			call->params_size = external_entry_point->params_size;
			/* FIXME: use struct in sizeof bit here */
			call->params = calloc(call->params_size, sizeof(int *));
			if (!call) {
				debug_print(DEBUG_MAIN, 1, "PARAM failed for inst:0x%x, CALL. Out of memory\n", n);
				return 1;
			}
			debug_print(DEBUG_MAIN, 1, "PARAM:call size=%x\n", call->params_size);
			debug_print(DEBUG_MAIN, 1, "PARAM:params size=%x\n", external_entry_point->params_size);
			for (m = 0; m < external_entry_point->params_size; m++) {
				label = &labels[external_entry_point->params[m]];
				if (0 == inst_log1->prev_size) {
					debug_print(DEBUG_MAIN, 1, "search_back ended\n");
					return 1;
				}
				if (0 < inst_log1->prev_size) {
					mid_start = calloc(inst_log1->prev_size, sizeof(struct mid_start_s));
					mid_start_size = inst_log1->prev_size;
					for (l = 0; l < inst_log1->prev_size; l++) {
						mid_start[l].mid_start = inst_log1->prev[l];
						mid_start[l].valid = 1;
						debug_print(DEBUG_MAIN, 1, "mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[l].mid_start, l);
					}
				}
				/* param_regXXX */
				if ((2 == label->scope) &&
					(1 == label->type)) {
					debug_print(DEBUG_MAIN, 1, "PARAM: Searching for REG0x%"PRIx64":0x%"PRIx64" + label->value(0x%"PRIx64")\n", inst_log1->value1.init_value, inst_log1->value1.offset_value, label->value);
					tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 1, label->value, 0, &size, self->search_back_seen, &inst_list);
					debug_print(DEBUG_MAIN, 1, "search_backJCD1: tmp = %d\n", tmp);
				} else {
				/* param_stackXXX */
				/* SP value held in value1 */
					debug_print(DEBUG_MAIN, 1, "PARAM: Searching for SP(0x%"PRIx64":0x%"PRIx64") + label->value(0x%"PRIx64") - 8\n", inst_log1->value1.init_value, inst_log1->value1.offset_value, label->value);
					tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 2, inst_log1->value1.init_value, inst_log1->value1.offset_value + label->value - 8, &size, self->search_back_seen, &inst_list);
				/* FIXME: Some renaming of local vars will also be needed if size > 1 */
				}
				if (tmp) {
					debug_print(DEBUG_MAIN, 1, "PARAM search_back Failed at inst_log 0x%x\n", n);
					return 1;
				}
				tmp = output_label(label, stdout);
				tmp = fprintf(stdout, ");\n");
				tmp = fprintf(stdout, "PARAM size = 0x%"PRIx64"\n", size);
				if (size > 1) {
					debug_print(DEBUG_MAIN, 1, "number of param locals (0x%"PRIx64") found too big at instruction 0x%x\n", size, n);
//					return 1;
//					break;
				}
				if (size > 0) {
					for (l = 0; l < size; l++) {
						struct inst_log_entry_s *inst_log_l;
						inst_log_l = &inst_log_entry[inst_list[l]];
						call->params[m] = inst_log_l->value3.value_id;
						// FIXME: Check next line. Force value type to unknown.
						debug_print(DEBUG_MAIN, 1, "JCD3: Setting value_type to 0, was 0x%x\n", inst_log_l->value3.value_type);
						if (6 == inst_log_l->value3.value_type) {	
							inst_log_l->value1.value_type = 3;
							inst_log_l->value3.value_type = 3;
						}
						debug_print(DEBUG_MAIN, 1, "JCD1: Param = 0x%"PRIx64", inst_list[0x%x] = 0x%"PRIx64"\n",

							inst_log_l->value3.value_id,
							l,
							inst_list[l]);
						//tmp = label_redirect[inst_log_l->value3.value_id].redirect;
						//label = &labels[tmp];
						//tmp = output_label(label, stdout);
					}
				}
			}
			//debug_print(DEBUG_MAIN, 1, "SSA2 failed for inst:0x%x, CALL\n", n);
			//return 1;
			break;

		default:
			break;
		}
	}

	/**************************************************
	 * This section deals with variable types, scanning forwards
	 * FIXME: Need to make this a little more intelligent
	 * It might fall over with complex loops and program flow.
	 * Maybe iterate up and down until no more changes need doing.
	 * Problem with iterations, is that it could suffer from bistable flips
	 * causing the iteration to never exit.
	 **************************************************/
	for (n = 1; n < inst_log; n++) {
		uint64_t value_id;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		debug_print(DEBUG_MAIN, 1, "value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64"\n",
				n,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value,
				inst_log1->value1.indirect_value_id);

		switch (instruction->opcode) {
		case MOV:
			if (IND_MEM == instruction->dstA.indirect) {
				value_id3 = inst_log1->value3.indirect_value_id;
			} else {
				value_id3 = inst_log1->value3.value_id;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}

			if (labels[value_id3].lab_pointer != labels[value_id].lab_pointer) {
				labels[value_id3].lab_pointer += labels[value_id].lab_pointer;
				labels[value_id].lab_pointer = labels[value_id3].lab_pointer;
			}
			debug_print(DEBUG_MAIN, 1, "JCD4: value_id = 0x%"PRIx64", lab_pointer = 0x%"PRIx64", value_id3 = 0x%"PRIx64", lab_pointer = 0x%"PRIx64"\n",
				value_id, labels[value_id].lab_pointer, value_id3, labels[value_id3].lab_pointer);
			break;

		default:
			break;
		}
	}

	/**************************************************
	 * This section deals with variable types, scanning backwards
	 **************************************************/
	for (n = inst_log; n > 0; n--) {
		uint64_t value_id;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		debug_print(DEBUG_MAIN, 1, "value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64"\n",
				n,
				instruction->srcA.indirect,
				instruction->srcA.index,
				instruction->srcA.relocated,
				inst_log1->value1.value_scope,
				inst_log1->value1.value_id,
				inst_log1->value1.indirect_offset_value,
				inst_log1->value1.indirect_value_id);

		switch (instruction->opcode) {
		case MOV:
			if (IND_MEM == instruction->dstA.indirect) {
				value_id3 = inst_log1->value3.indirect_value_id;
			} else {
				value_id3 = inst_log1->value3.value_id;
			}

			if (IND_MEM == instruction->srcA.indirect) {
				value_id = inst_log1->value1.indirect_value_id;
			} else {
				value_id = inst_log1->value1.value_id;
			}

			if (labels[value_id3].lab_pointer != labels[value_id].lab_pointer) {
				labels[value_id3].lab_pointer += labels[value_id].lab_pointer;
				labels[value_id].lab_pointer = labels[value_id3].lab_pointer;
			}
			debug_print(DEBUG_MAIN, 1, "JCD4: value_id = 0x%"PRIx64", lab_pointer = 0x%"PRIx64", value_id3 = 0x%"PRIx64", lab_pointer = 0x%"PRIx64"\n",
				value_id, labels[value_id].lab_pointer, value_id3, labels[value_id3].lab_pointer);
			break;

		default:
			break;
		}
	}


	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid) {
			tmp = output_cfg_dot(self, nodes, nodes_size, label_redirect, labels, l);
		}
	}
	tmp = llvm_export(self);
	/***************************************************
	 * This section deals with outputting the .c file.
	 ***************************************************/
	filename = "test.c";
	fd = fopen(filename, "w");
	if (!fd) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%p\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".c fd=%p\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out to file\n");
	tmp = fprintf(fd, "#include <stdint.h>\n\n");
	debug_print(DEBUG_MAIN, 1, "PRINTING MEMORY_DATA\n");
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		struct process_state_s *process_state;
		if (external_entry_points[l].valid) {
			process_state = &external_entry_points[l].process_state;
			memory_data = process_state->memory_data;
			for (n = 0; n < 4; n++) {
				debug_print(DEBUG_MAIN, 1, "memory_data:0x%x: 0x%"PRIx64"\n", n, memory_data[n].valid);
				if (memory_data[n].valid) {
	
					tmp = bf_relocated_data(handle_void, memory_data[n].start_address, 4);
					if (tmp) {
						debug_print(DEBUG_MAIN, 1, "int *data%04"PRIx64" = &data%04"PRIx64"\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
						tmp = fprintf(fd, "int *data%04"PRIx64" = &data%04"PRIx64";\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
					} else {
						debug_print(DEBUG_MAIN, 1, "int data%04"PRIx64" = 0x%04"PRIx64"\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
						tmp = fprintf(fd, "int data%04"PRIx64" = 0x%"PRIx64";\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
					}
				}
			}
		}
	}
	tmp = fprintf(fd, "\n");
	debug_print(DEBUG_MAIN, 1, "\n");
#if 0
	for (n = 0; n < 100; n++) {
		param_present[n] = 0;
	}
		
	for (n = 0; n < 10; n++) {
		if (memory_stack[n].start_address > 0x10000) {
			uint64_t present_index;
			present_index = memory_stack[n].start_address - 0x10000;
			if (present_index >= 100) {
				debug_print(DEBUG_MAIN, 1, "param limit reached:memory_stack[%d].start_address == 0x%"PRIx64"\n",
					n, memory_stack[n].start_address);
				continue;
			}
			param_present[present_index] = 1;
			param_size[present_index] = memory_stack[n].length;
		}
	}
	for (n = 0; n < 100; n++) {
		if (param_present[n]) {
			debug_print(DEBUG_MAIN, 1, "param%04x\n", n);
			tmp = param_size[n];
			n += tmp;
		}
	}
#endif

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		/* FIXME: value == 0 for the first function in the .o file. */
		/*        We need to be able to handle more than
		          one function per .o file. */
		if (external_entry_points[l].valid) {
			debug_print(DEBUG_MAIN, 1, "%d:%s:start=%"PRIu64", end=%"PRIu64"\n", l,
					external_entry_points[l].name,
					external_entry_points[l].inst_log,
					external_entry_points[l].inst_log_end);
		}
		if (external_entry_points[l].valid &&
			external_entry_points[l].type == 1) {
			struct process_state_s *process_state;
			int tmp_state;
			
			process_state = &external_entry_points[l].process_state;

			tmp = fprintf(fd, "\n");
			output_function_name(fd, &external_entry_points[l]);
			tmp_state = 0;
			for (m = 0; m < REG_PARAMS_ORDER_MAX; m++) {
				struct label_s *label;
				for (n = 0; n < external_entry_points[l].params_size; n++) {
					label = &labels[external_entry_points[l].params[n]];
					debug_print(DEBUG_MAIN, 1, "reg_params_order = 0x%x, label->value = 0x%"PRIx64"\n", reg_params_order[m], label->value);
					if ((label->scope == 2) &&
						(label->type == 1) &&
						(label->value == reg_params_order[m])) {
						if (tmp_state > 0) {
							fprintf(fd, ", ");
						}
						fprintf(fd, "int%"PRId64"_t ",
							label->size_bits);
						if (label->lab_pointer) {
							fprintf(fd, "*");
						}
						tmp = output_label(label, fd);
						tmp_state++;
					}
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
					fprintf(fd, ", ");
				}
				fprintf(fd, "int%"PRId64"_t ",
					label->size_bits);
				if (label->lab_pointer) {
					fprintf(fd, "*");
				}
				tmp = output_label(label, fd);
				tmp_state++;
			}
			tmp = fprintf(fd, ")\n{\n");
			for (n = 0; n < external_entry_points[l].locals_size; n++) {
				struct label_s *label;
				label = &labels[external_entry_points[l].locals[n]];
				fprintf(fd, "\tint%"PRId64"_t ",
					label->size_bits);
				if (label->lab_pointer) {
					fprintf(fd, "*");
				}
				tmp = output_label(label, fd);
				fprintf(fd, ";\n");
			}
			fprintf(fd, "\n");
					
			tmp = output_function_body(self, process_state,
				fd,
				external_entry_points[l].inst_log,
				external_entry_points[l].inst_log_end,
				label_redirect,
				labels);
			if (tmp) {
				return 1;
			}
//   This code is not doing anything, so comment it out
//			for (n = external_entry_points[l].inst_log; n <= external_entry_points[l].inst_log_end; n++) {
//			}			
		}
	}

	fclose(fd);
	bf_test_close_file(handle_void);
	print_mem(memory_reg, 1);
	for (n = 0; n < inst_size; n++) {
		debug_print(DEBUG_MAIN, 1, "0x%04x: %d\n", n, memory_used[n]);
	}
	debug_print(DEBUG_MAIN, 1, "PRINTING MEMORY_DATA\n");
	for (n = 0; n < 4; n++) {
		print_mem(memory_data, n);
		debug_print(DEBUG_MAIN, 1, "\n");
	}
	debug_print(DEBUG_MAIN, 1, "PRINTING STACK_DATA\n");
	for (n = 0; n < 10; n++) {
		print_mem(memory_stack, n);
		debug_print(DEBUG_MAIN, 1, "\n");
	}
	for (n = 0; n < 100; n++) {
		param_present[n] = 0;
	}
		
	for (n = 0; n < 10; n++) {
		if (memory_stack[n].start_address >= tmp) {
			uint64_t present_index;
			present_index = memory_stack[n].start_address - 0x10000;
			if (present_index >= 100) {
				debug_print(DEBUG_MAIN, 1, "param limit reached:memory_stack[%d].start_address == 0x%"PRIx64"\n",
					n, memory_stack[n].start_address);
				continue;
			}
			param_present[present_index] = 1;
			param_size[present_index] = memory_stack[n].length;
		}
	}

	for (n = 0; n < 100; n++) {
		if (param_present[n]) {
			debug_print(DEBUG_MAIN, 1, "param%04x\n", n);
			tmp = param_size[n];
			n += tmp;
		}
	}
#endif
//end_main:
	debug_print(DEBUG_MAIN, 1, "END - FINISHED PROCESSING\n");
	return 0;
}

