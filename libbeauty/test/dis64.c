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
struct rev_eng *handle;
struct disassemble_info disasm_info;
char *dis_flags_table[] = { " ", "f" };
uint64_t inst_log = 1;	/* Pointer to the current free instruction log entry. */
struct self_s *self = NULL;

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

int disassemble(struct rev_eng *handle, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset) {
	return disassemble_amd64(handle, dis_instructions, base_address, offset);
}


int print_dis_instructions(struct self_s *self)
{
	int n;
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;

	printf("print_dis_instructions:\n");
	for (n = 1; n <= inst_log; n++) {
		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		if (print_inst(self, instruction, n, NULL))
			return 1;
		printf("start_address:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.start_address,
			inst_log1->value2.start_address,
			inst_log1->value3.start_address);
		printf("init:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.init_value,
			inst_log1->value2.init_value,
			inst_log1->value3.init_value);
		printf("offset:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.offset_value,
			inst_log1->value2.offset_value,
			inst_log1->value3.offset_value);
		printf("indirect init:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.indirect_init_value,
			inst_log1->value2.indirect_init_value,
			inst_log1->value3.indirect_init_value);
		printf("indirect offset:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.indirect_offset_value,
			inst_log1->value2.indirect_offset_value,
			inst_log1->value3.indirect_offset_value);
		printf("indirect value_id:%"PRIx64", %"PRIx64" -> %"PRIx64"\n",
			inst_log1->value1.indirect_value_id,
			inst_log1->value2.indirect_value_id,
			inst_log1->value3.indirect_value_id);
		printf("value_type:0x%x, 0x%x -> 0x%x\n",
			inst_log1->value1.value_type,
			inst_log1->value2.value_type,
			inst_log1->value3.value_type);
		printf("value_scope:0x%x, 0x%x -> 0x%x\n",
			inst_log1->value1.value_scope,
			inst_log1->value2.value_scope,
			inst_log1->value3.value_scope);
		printf("value_id:0x%"PRIx64", 0x%"PRIx64" -> 0x%"PRIx64"\n",
			inst_log1->value1.value_id,
			inst_log1->value2.value_id,
			inst_log1->value3.value_id);
		if (inst_log1->prev_size > 0) {
			int n;
			for (n = 0; n < inst_log1->prev_size; n++) {
				printf("inst_prev:%d:0x%04x\n",
					n,
					inst_log1->prev[n]);
			}
		}
		if (inst_log1->next_size > 0) {
			int n;
			for (n = 0; n < inst_log1->next_size; n++) {
				printf("inst_next:%d:0x%04x\n",
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
	printf("start_address:0x%"PRIx64"\n",
		memory[location].start_address);
	printf("length:0x%x\n",
		memory[location].length);
	printf("init_value_type:0x%x\n",
		memory[location].init_value_type);
	printf("init:0x%"PRIx64"\n",
		memory[location].init_value);
	printf("offset:0x%"PRIx64"\n",
		memory[location].offset_value);
	printf("indirect_init:0x%"PRIx64"\n",
		memory[location].indirect_init_value);
	printf("indirect_offset:0x%"PRIx64"\n",
		memory[location].indirect_offset_value);
	printf("value_type:0x%x\n",
		memory[location].value_type);
	printf("ref_memory:0x%"PRIx32"\n",
		memory[location].ref_memory);
	printf("ref_log:0x%"PRIx32"\n",
		memory[location].ref_log);
	printf("value_scope:0x%x\n",
		memory[location].value_scope);
	printf("value_id:0x%"PRIx64"\n",
		memory[location].value_id);
	printf("valid:0x%"PRIx64"\n",
		memory[location].valid);
	return 0;
}

int external_entry_points_init(struct external_entry_point_s *external_entry_points, struct rev_eng *handle)
{
	int n;
	int l;
	//struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	//int *memory_used;

	/* Print the symtab */
	printf("symtab_sz = %lu\n", handle->symtab_sz);
	if (handle->symtab_sz >= 100) {
		printf("symtab too big!!! EXITING\n");
		return 1;
	}
	n = 0;
	for (l = 0; l < handle->symtab_sz; l++) {
		size_t length;
		/* FIXME: value == 0 for the first function in the .o file. */
		/*        We need to be able to handle more than
		          one function per .o file. */
		printf("section_id = %d, section_index = %d, flags = 0x%04x, value = 0x%04"PRIx64"\n",
			handle->symtab[l]->section->id,
			handle->symtab[l]->section->index,
			handle->symtab[l]->flags,
			handle->symtab[l]->value);
		if ((handle->symtab[l]->flags & 0x8) ||
			(handle->symtab[l]->flags == 0)) {
			external_entry_points[n].valid = 1;
			/* 1: Public function entry point
			 * 2: Private function entry point
			 * 3: Private label entry point
			 */
			if (handle->symtab[l]->flags & 0x8) {
				external_entry_points[n].type = 1;
			} else {
				external_entry_points[n].type = 2;
			}
			external_entry_points[n].section_offset = l;
			external_entry_points[n].section_id = 
				handle->symtab[l]->section->id;
			external_entry_points[n].section_index = 
				handle->symtab[l]->section->index;
			external_entry_points[n].value = handle->symtab[l]->value;
			length = strlen(handle->symtab[l]->name);
			external_entry_points[n].name = malloc(length+1);
			strncpy(external_entry_points[n].name, handle->symtab[l]->name, length+1);
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

			n++;
		}

	}
	return 0;
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
		printf("ast_container->length = 0x%x\n", ast_container->length);
	}
	printf("parent = 0x%x, 0x%"PRIx64", 0x%x\n",
		ast_container->parent.type, ast_container->parent.index, ast_container->parent.offset);
	if (ast_container->object) {
		for (n = 0; n < ast_container->length; n++) {
			printf("0x%d:type = 0x%x, index = 0x%"PRIx64"\n",
				n,
				ast_container->object[n].type,
				ast_container->object[n].index);
		}
	} else if (ast_container->length > 0) {
		printf("print_ast_container invalid\n");
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
int cfg_to_ast(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, struct ast_s *ast, int start_node)
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
		printf("container_index too large 0\n");
		ret = 1;
		goto exit_cfg_to_ast;
	}
	ast->ast_container[container_index].start_node = start_node;
	container_index++;
	if (container_index >= AST_SIZE) { 
		printf("container_index too large 0\n");
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
		printf("BEFORE ast_entry entry = 0x%x\n", entry);
		printf("ast_type = 0x%x\n", ast_entry[entry].type);
		printf("ast_index = 0x%x\n", ast_entry[entry].index);
		printf("ast_sub_index = 0x%x\n", ast_entry[entry].sub_index);
		printf("ast_node = 0x%x\n", ast_entry[entry].node);
		printf("ast_node_end = 0x%x\n", ast_entry[entry].node_end);

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
		printf("new_node_end = 0x%x\n", node_end);
		printf("AST: Type = 0x%x\n", type);
		switch (type) {
		case AST_TYPE_IF_THEN_ELSE:
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				printf("failed type != 2\n");
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
				printf("Creating if_then container 0x%x\n", container_index);
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
					printf("container_index too large 1\n");
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
				printf("Creating if_else container 0x%x\n", container_index);
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
					printf("container_index too large 2\n");
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
				printf("if_then_else_index too large\n");
				ret = 1;
				goto exit_cfg_to_ast;
			}
			break;
		case AST_TYPE_IF_THEN_GOTO:
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				printf("AST_TYPE_IF_THEN_GOTO:failed type != 2\n");
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
				printf("FAILED: No is_exit entry in IF_THEN_GOTO\n");
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
				printf("Creating if_then container 0x%x\n", container_index);
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
					printf("container_index too large 3\n");
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
					printf("parent = 0x%x, 0x%"PRIx64", 0x%x\n",
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
				printf("if_then_goto_index too large\n");
				ret = 1;
				goto exit_cfg_to_ast;
			}
			break;
		case AST_TYPE_NODE:
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				printf("AST_TYPE_NODE failed type != 2\n");
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
			printf("AST_TYPE_LOOP type = 0x%x, node = 0x%x\n", type, node);
			index = ast_entry[entry].index;
			if (ast_entry[entry].type != AST_TYPE_CONTAINER) {
				printf("failed type != 2\n");
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
				printf("Creating loop container 0x%x\n", container_index);
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
					printf("container_index too large 4\n");
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			if (nodes[node].link_next[1].is_normal) {
				printf("Creating loop container 0x%x\n", container_index);
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
					printf("container_index too large 5 node = 0x%x, if_tail = 0x%x\n", node, nodes[node].if_tail);
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			ast_entry[entry].sub_index = ast_container[index].length;
			ast_entry[entry].node = nodes[node].if_tail;

			loop_index++;
			if (loop_index >= AST_SIZE) { 
				printf("loop_index too large\n");
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
				printf("failed type != 2\n");
				exit(1);
			}
			length = ast_container[index].length;
			if (0 == length) {
				ast_container[index].object = malloc(sizeof(struct ast_type_index_s));
				ast_container[index].length = 1;
				printf("Add object 0x%x to container 0x%x\n", ast_container[index].length - 1, index);
			} else {
				tmp = length + 1;
				ast_container[index].object = realloc(ast_container[index].object, tmp * sizeof(struct ast_type_index_s));
				ast_container[index].length = tmp;
				printf("Add object 0x%x to container 0x%x\n", ast_container[index].length - 1, index);
			}
			/* Create two containers. The loop_container, and inside the loop_container, the if_then_else */
			ast_container[index].object[length].type = AST_TYPE_CONTAINER;
			ast_container[index].object[length].index = container_index;
			printf("ast_container[0x%x].object[0x%x] set to AST_TYPE_CONTAINER and index = 0x%x\n",
				index, length, container_index);
			printf("JCD: container_index 0x%x, index 0x%x, length 0x%x  container_length 0x%x\n",
				container_index, index, length, ast_container[index].length);
			ast_container[index + 1].object = malloc(sizeof(struct ast_type_index_s));
			ast_container[index + 1].length = 1;
			printf("Add object 0x%x to container 0x%x\n", ast_container[index + 1].length - 1, index + 1);
			ast_container[index + 1].object[0].type = AST_TYPE_IF_THEN_ELSE;
			ast_container[index + 1].sub_type = 1;
			ast_container[index + 1].object[0].index = if_then_else_index;
			ast_container[index + 1].length = 1;
			ast_container[index + 1].start_node = node;
			ast_container[index + 1].parent.type = AST_TYPE_CONTAINER;
			ast_container[index + 1].parent.index = index;
			ast_container[index + 1].parent.offset = length; /* Point to the parent that points to us */
			printf("ast_container[0x%x].object[0x%x] set to AST_TYPE_IF_THEN_ELSE and index = 0x%x\n",
				index + 1, 0, if_then_else_index);
			printf("ast_container[0x%x].parent set to AST_TYPE_CONTAINER, 0x%x, 0x%x\n",
				index + 1, index, ast_container[index].length);
			container_index++;
			if (container_index >= AST_SIZE) { 
				printf("container_index too large 2\n");
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
				printf("Creating loop_then container 0x%x\n", container_index);
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
					printf("container_index too large 3\n");
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
				printf("Creating loop_else container 0x%x\n", container_index);
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
					printf("container_index too large 2\n");
					ret = 1;
					goto exit_cfg_to_ast;
				}
			}
			if (!is_member_of_loop(nodes, node, nodes[node].if_tail)) {
//			if (nodes[node].if_tail == ast_entry[entry].node_end) {
				printf("JCD: loop_container_node NOT 0x%x, 0x%x\n", node, nodes[node].if_tail);
				ast_entry[entry].type = AST_TYPE_EMPTY;
			} else {
				printf("JCD: loop_container_node = 0x%x\n", nodes[node].if_tail);
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
				printf("if_then_else_index too large\n");
				ret = 1;
				goto exit_cfg_to_ast;
			}
#if 0
			loop_container_index++;
			if (loop_container_index >= AST_SIZE) {
				printf("loop_container_index too large\n");
				exit(1);
			}
#endif
			break;
		case AST_TYPE_LOOP_CONTAINER:
			printf("UNHANDLED LOOP_CONTAINER = 0x%x\n", type);
			break;
		default:
			printf("UNHANDLED type = 0x%x\n", type);
			ast_entry[entry].type = AST_TYPE_EMPTY;
			break;
		}

		printf("AFTER ast_entry entry = 0x%x\n", entry);
		printf("ast_type = 0x%x\n", ast_entry[entry].type);
		printf("ast_index = 0x%x\n", ast_entry[entry].index);
		printf("ast_sub_index = 0x%x\n", ast_entry[entry].sub_index);
		printf("ast_node = 0x%x\n", ast_entry[entry].node);
		printf("ast_node_end = 0x%x\n", ast_entry[entry].node_end);

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

	printf("AST OUTPUT\n");
	for (m = 0; m < container_index; m++) {
		printf("ast_container[%d]", m);
		if (m >= AST_SIZE) {
			break;
		}
		print_ast_container(&ast_container[m]);
	}
	for (m = 0; m < if_then_else_index; m++) {
		int type;
		printf("parent = 0x%x, 0x%"PRIx64", 0x%x\n",
			ast_if_then_else[m].parent.type,
			ast_if_then_else[m].parent.index,
			ast_if_then_else[m].parent.offset);
		if (m >= AST_SIZE) {
			break;
		}
		type = ast_if_then_else[m].expression_node.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			printf("ast_if_then_else expression_node empty\n");
			break;
		case AST_TYPE_NODE:
			printf("ast_if_then_else[%d].expression_node.type = 0x%x\n", m, ast_if_then_else[m].expression_node.type);
			printf("ast_if_then_else[%d].expression_node.index = 0x%"PRIx64"\n", m, ast_if_then_else[m].expression_node.index);
			break;
		case AST_TYPE_CONTAINER:
			printf("ast_if_then_else[%d].expression_node\n", m);
			tmp = ast_if_then_else[m].expression_node.index;
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			printf("ast_if_then_else expression_node default\n");
			break;
		}
		type = ast_if_then_else[m].if_then.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			printf("ast_if_then_else if_then empty\n");
			break;
		case AST_TYPE_NODE:
			printf("ast_if_then_else[%d].if_then.type = 0x%x\n", m, ast_if_then_else[m].if_then.type);
			printf("ast_if_then_else[%d].if_then.index = 0x%"PRIx64"\n", m, ast_if_then_else[m].if_then.index);
			break;
		case AST_TYPE_CONTAINER:
			printf("ast_if_then_else[%d].if_then\n", m);
			tmp = ast_if_then_else[m].if_then.index;
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			printf("ast_if_then_else if_then default\n");
			break;
		}
		type = ast_if_then_else[m].if_else.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			printf("ast_if_then_else if_else empty\n");
			break;
		case AST_TYPE_NODE:
			printf("ast_if_then_else[%d].if_else.type = 0x%x\n", m, ast_if_then_else[m].if_else.type);
			printf("ast_if_then_else[%d].if_else.index = 0x%"PRIx64"\n", m, ast_if_then_else[m].if_else.index);
			break;
		case AST_TYPE_CONTAINER:
			printf("ast_if_then_else[%d].if_else\n", m);
			tmp = ast_if_then_else[m].if_else.index;
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			printf("ast_if_then_else if_else default\n");
			break;
		}
	}
	for (m = 0; m < if_then_goto_index; m++) {
		int type;
		printf("parent = 0x%x, 0x%"PRIx64", 0x%x\n",
			ast_if_then_goto[m].parent.type,
			ast_if_then_goto[m].parent.index,
			ast_if_then_goto[m].parent.offset);
		if (m >= AST_SIZE) {
			break;
		}
		type = ast_if_then_goto[m].expression_node.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			printf("ast_if_then_goto expression_node empty\n");
			break;
		case AST_TYPE_NODE:
			printf("ast_if_then_goto[%d].expression_node.type = 0x%x\n", m, ast_if_then_goto[m].expression_node.type);
			printf("ast_if_then_goto[%d].expression_node.index = 0x%"PRIx64"\n", m, ast_if_then_goto[m].expression_node.index);
			break;
		case AST_TYPE_CONTAINER:
			printf("ast_if_then_goto[%d].expression_node\n", m);
			tmp = ast_if_then_goto[m].expression_node.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			printf("ast_if_then_goto expression_node default\n");
			break;
		}
		type = ast_if_then_goto[m].if_then_goto.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			printf("ast_if_then_goto if_then empty\n");
			break;
		case AST_TYPE_NODE:
			printf("ast_if_then_goto[%d].if_then_goto.type = 0x%x\n", m, ast_if_then_goto[m].if_then_goto.type);
			printf("ast_if_then_goto[%d].if_then_goto.index = 0x%"PRIx64"\n", m, ast_if_then_goto[m].if_then_goto.index);
			break;
		case AST_TYPE_CONTAINER:
			printf("ast_if_then_goto[%d].if_then_goto\n", m);
			tmp = ast_if_then_goto[m].if_then_goto.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			printf("ast_if_then_goto if_then_goto default\n");
			break;
		}
	}
	for (m = 0; m < loop_index; m++) {
		printf("ast_loop[%d].body\n", m);
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
			printf("ast_loop_then_else expression_node empty\n");
			break;
		case AST_TYPE_NODE:
			printf("ast_loop_then_else[%d].expression_node.type = 0x%x\n", m, ast_loop_then_else[m].expression_node.type);
			printf("ast_loop_then_else[%d].expression_node.index = 0x%"PRIx64"\n", m, ast_loop_then_else[m].expression_node.index);
			break;
		case AST_TYPE_CONTAINER:
			printf("ast_loop_then_else[%d].expression_node\n", m);
			tmp = ast_loop_then_else[m].expression_node.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			printf("ast_loop_then_else expression_node default\n");
			break;
		}
		type = ast_loop_then_else[m].loop_then.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			printf("ast_loop_then_else loop_then empty\n");
			break;
		case AST_TYPE_NODE:
			printf("ast_loop_then_else[%d].loop_then.type = 0x%x\n", m, ast_loop_then_else[m].loop_then.type);
			printf("ast_loop_then_else[%d].loop_then.index = 0x%"PRIx64"\n", m, ast_loop_then_else[m].loop_then.index);
			break;
		case AST_TYPE_CONTAINER:
			printf("ast_loop_then_else[%d].loop_then\n", m);
			tmp = ast_loop_then_else[m].loop_then.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			printf("ast_loop_then_else loop_then default\n");
			break;
		}
		type = ast_loop_then_else[m].loop_else.type;
		switch (type) {
		case AST_TYPE_EMPTY:
			printf("ast_loop_then_else loop_else empty\n");
			break;
		case AST_TYPE_NODE:
			printf("ast_loop_then_else[%d].loop_else.type = 0x%x\n", m, ast_loop_then_else[m].loop_else.type);
			printf("ast_loop_then_else[%d].loop_else.index = 0x%"PRIx64"\n", m, ast_loop_then_else[m].loop_else.index);
			break;
		case AST_TYPE_CONTAINER:
			printf("ast_loop_then_else[%d].loop_else\n", m);
			tmp = ast_loop_then_else[m].loop_else.index;
			if (tmp >= AST_SIZE) {
				break;
			}
			print_ast_container(&ast_container[tmp]);
			break;
		default:
			printf("ast_loop_then_else loop_else default\n");
			break;
		}
	}
	return 0;
}

int output_cfg_dot(struct self_s *self, struct control_flow_node_s *nodes, int *node_size,
                         struct label_redirect_s *label_redirect, struct label_s *labels)
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
	const char *font = "graph.font";
	const char *color;
	const char *name;
	filename = "test.dot";

	fd = fopen(filename, "w");
	if (!fd) {
		printf("Failed to open file %s, error=%p\n", filename, fd);
		return 1;
	}
	printf(".dot fd=%p\n", fd);
	printf("writing out dot to file\n");
	tmp = fprintf(fd, "digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"%s\" fontsize=\"8\"];\n", font);
	for (node = 1; node <= *node_size; node++) {
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
		process_state = &external_entry_points[nodes[node].entry_point - 1].process_state;
		for (n = nodes[node].inst_start; n <= nodes[node].inst_end; n++) {
			inst_log1 =  &inst_log_entry[n];
			instruction =  &inst_log1->instruction;
			//tmp = write_inst(self, fd, instruction, n, NULL);
			//tmp = fprintf(fd, "\\l");
			tmp = output_inst_in_c(self, process_state, fd, n, label_redirect, labels, "\\l");
			//tmp = fprintf(fd, "\\l\n");
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
		printf("Failed to open file %s, error=%p\n", filename, fd);
		return 1;
	}
	printf(".dot fd=%p\n", fd);
	printf("writing out dot to file\n");
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
			printf("if_then_else:0x%x TYPE_NODE \n", n);
			tmp = fprintf(fd, "\"if_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "red";
			printf("if_then_else:0x%x TYPE_CONTAINER \n", n);
			tmp = fprintf(fd, "\"if_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			printf("if_then_else:0x%x TYPE 0x%x UNKNOWN \n", n, ast_if_then_else[n].if_else.type);
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
	size_t inst_size = 0;
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
	disassembler_ftype disassemble_fn;
	struct relocation_s *relocations;
	struct external_entry_point_s *external_entry_points;
	struct control_flow_node_s *nodes;
	int nodes_size;
	struct path_s *paths;
	int paths_size = 20000;
	struct loop_s *loops;
	int loops_size = 2000;
	struct ast_s *ast;
	int *section_number_mapping;

	if (argc != 2) {
		printf("Syntax error\n");
		printf("Usage: dis64 filename\n");
		printf("Where \"filename\" is the input .o file\n");
		exit(1);
	}
	file = argv[1];

	expression = malloc(1000); /* Buffer for if expressions */

	handle = bf_test_open_file(file);
	if (!handle) {
		printf("Failed to find or recognise file\n");
		return 1;
	}
	tmp = bf_get_arch_mach(handle, &arch, &mach);
	if ((arch != 9) ||
		(mach != 8)) {
		printf("File not the correct arch(0x%x) and mach(0x%"PRIx64")\n", arch, mach);
		return 1;
	}

	printf("symtab_size = %ld\n", handle->symtab_sz);
	for (l = 0; l < handle->symtab_sz; l++) {
		printf("%d\n", l);
		printf("type:0x%02x\n", handle->symtab[l]->flags);
		printf("name:%s\n", handle->symtab[l]->name);
		printf("value=0x%02"PRIx64"\n", handle->symtab[l]->value);
		printf("section=%p\n", handle->symtab[l]->section);
		printf("section name=%s\n", handle->symtab[l]->section->name);
		printf("section flags=0x%02x\n", handle->symtab[l]->section->flags);
		printf("section index=0x%02"PRIx32"\n", handle->symtab[l]->section->index);
		printf("section id=0x%02"PRIx32"\n", handle->symtab[l]->section->id);
	}

	section_number_mapping = calloc(handle->section_sz, sizeof(int));
	handle->section_number_mapping = section_number_mapping;
	for (l = 0; l < handle->section_sz; l++) {
			const char *name = handle->section[l]->name;
		if (!strncmp(".text", name, 5)) {
			section_number_mapping[l] = 1;
		}
		if (!strncmp(".rodata", name, 7)) {
			section_number_mapping[l] = 2;
		}
		if (!strncmp(".data", name, 5)) {
			section_number_mapping[l] = 3;
		}
	}

	printf("sectiontab_size = %ld\n", handle->section_sz);
	for (l = 0; l < handle->section_sz; l++) {
		printf("%d\n", l);
		printf("flags:0x%02x\n", handle->section[l]->flags);
		printf("name:%s\n", handle->section[l]->name);
		printf("index=0x%02"PRIx32"\n", handle->section[l]->index);
		printf("id=0x%02"PRIx32"\n", handle->section[l]->id);
		printf("sectio=%p\n", handle->section[l]);
		printf("section_number_mapping=0x%x\n", section_number_mapping[l]);
	}

	printf("Setup ok\n");
	inst_size = bf_get_code_size(handle);
	inst = malloc(inst_size);
	/* valgrind does not know about bf_copy_data_section */
	memset(inst, 0, inst_size);
	bf_copy_code_section(handle, inst, inst_size);
	printf("dis:.text Data at %p, size=0x%"PRIx64"\n", inst, inst_size);
	for (n = 0; n < inst_size; n++) {
		printf(" 0x%02x", inst[n]);
	}
	printf("\n");

	data_size = bf_get_data_size(handle);
	data = malloc(data_size);
	/* valgrind does not know about bf_copy_data_section */
	memset(data, 0, data_size);
	bf_copy_data_section(handle, data, data_size);
	printf("dis:.data Data at %p, size=0x%"PRIx64"\n", data, data_size);
	for (n = 0; n < data_size; n++) {
		printf(" 0x%02x", data[n]);
	}
	printf("\n");

	rodata_size = bf_get_rodata_size(handle);
	rodata = malloc(rodata_size);
	/* valgrind does not know about bf_copy_data_section */
	memset(rodata, 0, rodata_size);
	bf_copy_rodata_section(handle, rodata, rodata_size);
	printf("dis:.rodata Data at %p, size=0x%"PRIx64"\n", rodata, rodata_size);
	for (n = 0; n < rodata_size; n++) {
		printf(" 0x%02x", rodata[n]);
	}
	printf("\n");

	inst_log_entry = calloc(INST_LOG_ENTRY_SIZE, sizeof(struct inst_log_entry_s));
	relocations =  calloc(RELOCATION_SIZE, sizeof(struct relocation_s));
	external_entry_points = calloc(EXTERNAL_ENTRY_POINTS_MAX, sizeof(struct external_entry_point_s));
	self = malloc(sizeof *self);
	printf("sizeof struct self_s = 0x%"PRIx64"\n", sizeof *self);
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
	
	/* valgrind does not know about bf_copy_data_section */
	memset(data, 0, data_size);
	bf_copy_data_section(handle, data, data_size);
	printf("dis:.data Data at %p, size=0x%"PRIx64"\n", data, data_size);
	for (n = 0; n < data_size; n++) {
		printf(" 0x%02x", data[n]);
	}
	printf("\n");

	bf_get_reloc_table_code_section(handle);
	printf("reloc_table_code_sz=0x%"PRIx64"\n", handle->reloc_table_code_sz);
	for (n = 0; n < handle->reloc_table_code_sz; n++) {
		printf("reloc_table_code:addr = 0x%"PRIx64", size = 0x%"PRIx64", value = 0x%"PRIx64", section_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_code[n].address,
			handle->reloc_table_code[n].size,
			handle->reloc_table_code[n].value,
			handle->reloc_table_code[n].section_index,
			handle->reloc_table_code[n].section_name,
			handle->reloc_table_code[n].symbol_name);
	}

	bf_get_reloc_table_data_section(handle);
	for (n = 0; n < handle->reloc_table_data_sz; n++) {
		printf("reloc_table_data:addr = 0x%"PRIx64", size = 0x%"PRIx64", value = 0x%"PRIx64", section_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_data[n].address,
			handle->reloc_table_data[n].size,
			handle->reloc_table_data[n].value,
			handle->reloc_table_data[n].section_index,
			handle->reloc_table_data[n].section_name,
			handle->reloc_table_data[n].symbol_name);
	}
	bf_get_reloc_table_rodata_section(handle);
	for (n = 0; n < handle->reloc_table_rodata_sz; n++) {
		printf("reloc_table_rodata:addr = 0x%"PRIx64", size = 0x%"PRIx64", value = 0x%"PRIx64", section_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_rodata[n].address,
			handle->reloc_table_rodata[n].size,
			handle->reloc_table_rodata[n].value,
			handle->reloc_table_rodata[n].section_index,
			handle->reloc_table_rodata[n].section_name,
			handle->reloc_table_rodata[n].symbol_name);
	}
	
	printf("handle=%p\n", handle);
	
	printf("handle=%p\n", handle);
	init_disassemble_info(&disasm_info, stdout, (fprintf_ftype) fprintf);
	disasm_info.flavour = bfd_get_flavour(handle->bfd);
	disasm_info.arch = bfd_get_arch(handle->bfd);
	disasm_info.mach = bfd_get_mach(handle->bfd);
	disasm_info.disassembler_options = "intel";
	disasm_info.octets_per_byte = bfd_octets_per_byte(handle->bfd);
	disasm_info.skip_zeroes = 8;
	disasm_info.skip_zeroes_at_end = 3;
	disasm_info.disassembler_needs_relocs = 0;
	disasm_info.buffer_length = inst_size;
	disasm_info.buffer = inst;

	printf("disassemble_fn\n");
	disassemble_fn = disassembler(handle->bfd);
	self->disassemble_fn = disassemble_fn;
	printf("disassemble_fn done %p, %p\n", disassemble_fn, print_insn_i386);
	dis_instructions.bytes_used = 0;
	inst_exe = &inst_log_entry[0];

	tmp = external_entry_points_init(external_entry_points, handle);
	if (tmp) return 1;

	printf("Number of functions = %d\n", n);
	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if (external_entry_points[n].valid != 0) {
		printf("%d: type = %d, sect_offset = %d, sect_id = %d, sect_index = %d, &%s() = 0x%04"PRIx64"\n",
			n,
			external_entry_points[n].type,
			external_entry_points[n].section_offset,
			external_entry_points[n].section_id,
			external_entry_points[n].section_index,
			external_entry_points[n].name,
			external_entry_points[n].value);
		}
	}

	tmp = link_reloc_table_code_to_external_entry_point(handle, external_entry_points);
	if (tmp) return 1;

	for (n = 0; n < handle->reloc_table_code_sz; n++) {
		printf("reloc_table_code:addr = 0x%"PRIx64", size = 0x%"PRIx64", type = %d, function_index = 0x%"PRIx64", section_name=%s, symbol_name=%s\n",
			handle->reloc_table_code[n].address,
			handle->reloc_table_code[n].size,
			handle->reloc_table_code[n].type,
			handle->reloc_table_code[n].external_functions_index,
			handle->reloc_table_code[n].section_name,
			handle->reloc_table_code[n].symbol_name);
	}
			
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if ((external_entry_points[l].valid != 0) &&
			(external_entry_points[l].type == 1)) {  /* 1 == Implemented in this .o file */
			struct process_state_s *process_state;
			struct entry_point_s *entry_point = self->entry_point;
			
			printf("Start function block: %s:0x%"PRIx64"\n", external_entry_points[l].name, external_entry_points[l].value);	
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
			printf ("LOGS: inst_log = 0x%"PRIx64"\n", inst_log);
			do {
				not_finished = 0;
				for (n = 0; n < self->entry_point_list_length; n++ ) {
					/* EIP is a parameter for process_block */
					/* Update EIP */
					//printf("entry:%d\n",n);
					if (entry_point[n].used) {
						memory_reg[0].init_value = entry_point[n].esp_init_value;
						memory_reg[0].offset_value = entry_point[n].esp_offset_value;
						memory_reg[1].init_value = entry_point[n].ebp_init_value;
						memory_reg[1].offset_value = entry_point[n].ebp_offset_value;
						memory_reg[2].init_value = entry_point[n].eip_init_value;
						memory_reg[2].offset_value = entry_point[n].eip_offset_value;
						inst_log_prev = entry_point[n].previous_instuction;
						not_finished = 1;
						printf ("LOGS: EIPinit = 0x%"PRIx64"\n", memory_reg[2].init_value);
						printf ("LOGS: EIPoffset = 0x%"PRIx64"\n", memory_reg[2].offset_value);
						err = process_block(self, process_state, handle, inst_log_prev, inst_size);
						/* clear the entry after calling process_block */
						entry_point[n].used = 0;
						if (err) {
							printf("process_block failed\n");
							return err;
						}
					}
				}
			} while (not_finished);	
			external_entry_points[l].inst_log_end = inst_log - 1;
			printf ("LOGS: inst_log_end = 0x%"PRIx64"\n", inst_log);
		}
	}
/*
	if (entry_point_list_length > 0) {
		for (n = 0; n < entry_point_list_length; n++ ) {
			printf("eip = 0x%"PRIx64", prev_inst = 0x%"PRIx64"\n",
				entry_point[n].eip_offset_value,
				entry_point[n].previous_instuction);
		}
	}
*/
	//inst_log--;
	printf("Instructions=%"PRId64", entry_point_list_length=%"PRId64"\n",
		inst_log,
		self->entry_point_list_length);

	/* Correct inst_log to identify how many dis_instructions there have been */
	inst_log--;

	tmp = tidy_inst_log(self);
	tmp = build_control_flow_nodes(self, nodes, &nodes_size);
	tmp = print_control_flow_nodes(self, nodes, &nodes_size);
//	print_dis_instructions(self);
//	exit(1);

	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid) {
			tmp = find_node_from_inst(self, nodes, &nodes_size, external_entry_points[l].inst_log);
			external_entry_points[l].start_node = tmp;
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
			printf("Starting external entry point %d:%s\n", l, external_entry_points[l].name);
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

			tmp = build_control_flow_paths(self, nodes, &nodes_size,
				paths, &paths_size, &paths_used, external_entry_points[l].start_node);
			printf("tmp = %d, PATHS used = %d\n", tmp, paths_used);
			tmp = analyse_multi_ret(self, paths, &paths_size, &multi_ret_size, &multi_ret);
			if (multi_ret_size) {
				printf("tmp = %d, multi_ret_size = %d\n", tmp, multi_ret_size);
				for (m = 0; m < multi_ret_size; m++) {
					printf("multi_ret: node 0x%x\n", multi_ret[m]);
				}
				if (multi_ret_size == 2) {
					tmp = analyse_merge_nodes(self, nodes, &nodes_size, multi_ret[0], multi_ret[1]);
					tmp = build_control_flow_paths(self, nodes, &nodes_size,
						paths, &paths_size, &paths_used, external_entry_points[l].start_node);
				} else if (multi_ret_size > 2) {
					printf("multi_ret_size > 2 not yet handled\n");
					exit(1);
				}
			}
			//tmp = print_control_flow_paths(self, paths, &paths_size);

			tmp = build_control_flow_loops(self, paths, &paths_size, loops, &loops_size);
			tmp = build_control_flow_loops_node_members(self, nodes, &nodes_size, loops, &loops_size);
			tmp = build_node_paths(self, nodes, &nodes_size, paths, &paths_size, l + 1);

			external_entry_points[l].paths_size = paths_used;
			external_entry_points[l].paths = calloc(paths_used, sizeof(struct path_s));
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
			printf("loops_used = 0x%x\n", loops_used);
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
	/* Node specific processing */
	tmp = build_node_dominance(self, nodes, &nodes_size);
	tmp = analyse_control_flow_node_links(self, nodes, &nodes_size);
	tmp = build_node_type(self, nodes, &nodes_size);
	//tmp = build_control_flow_depth(self, nodes, &nodes_size,
	//		paths, &paths_size, &paths_used, external_entry_points[l].start_node);
	//printf("Merge: 0x%x\n", nodes_size);
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		if (external_entry_points[l].valid) {
			tmp = build_control_flow_loops_multi_exit(self, nodes, nodes_size,
				external_entry_points[l].loops, external_entry_points[l].loops_size);
		}
	}

	tmp = print_control_flow_nodes(self, nodes, &nodes_size);

	tmp = build_node_if_tail(self, nodes, &nodes_size);
	for (n = 0; n < nodes_size; n++) {
		if ((nodes[n].type == NODE_TYPE_IF_THEN_ELSE) &&
			(nodes[n].if_tail == 0)) {
			printf("FAILED: Node 0x%x with no if_tail\n", n);
		}
	}

#if 0
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
//	for (l = 21; l < 22; l++) {
//	for (l = 37; l < 38; l++) {
		if (external_entry_points[l].valid) {
			tmp = external_entry_points[l].start_node;
			printf("External entry point %d: type=%d, name=%s inst_log=0x%lx, start_node=0x%x\n", l, external_entry_points[l].type, external_entry_points[l].name, external_entry_points[l].inst_log, tmp);
			tmp = print_control_flow_paths(self, external_entry_points[l].paths, &(external_entry_points[l].paths_size));
			tmp = print_control_flow_loops(self, external_entry_points[l].loops, &(external_entry_points[l].loops_size));
		}
	}
#endif
	tmp = print_control_flow_nodes(self, nodes, &nodes_size);

//	Doing this after SSA now.
//	tmp = output_cfg_dot(self, nodes, &nodes_size);
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
//	for (l = 0; l < 21; l++) {
//	for (l = 21; l < 22; l++) {
//	for (l = 4; l < 5; l++) {
//		if (l == 21) continue;

		if (external_entry_points[l].valid && external_entry_points[l].type == 1) {
			/* Control flow graph to Abstract syntax tree */
			printf("cfg_to_ast. external entry point %d:%s\n", l, external_entry_points[l].name);
			external_entry_points[l].start_ast_container = ast->container_size;
			tmp = cfg_to_ast(self, nodes, &nodes_size, ast, external_entry_points[l].start_node);
			tmp = print_ast(self, ast);
		}
	}
	tmp = output_ast_dot(self, ast, nodes, &nodes_size);
	/* FIXME */
	//goto end_main;

#if 1

	print_dis_instructions(self);

	if (self->entry_point_list_length > 0) {
		for (n = 0; n < self->entry_point_list_length; n++ ) {
			struct entry_point_s *entry_point = self->entry_point;

			if (entry_point[n].used) {
				printf("%d, eip = 0x%"PRIx64", prev_inst = 0x%"PRIx64"\n",
					entry_point[n].used,
					entry_point[n].eip_offset_value,
					entry_point[n].previous_instuction);
			}
		}
	}
	/************************************************************
	 * This section deals with correcting SSA for branches/joins.
	 * This bit creates the labels table, ready for the next step.
	 ************************************************************/
	printf("Number of labels = 0x%x\n", self->local_counter);
	/* FIXME: +1 added as a result of running valgrind, but need a proper fix */
	label_redirect = calloc(self->local_counter + 1, sizeof(struct label_redirect_s));
	labels = calloc(self->local_counter + 1, sizeof(struct label_s));
	printf("JCD6: self->local_counter=%d\n", self->local_counter);
	labels[0].lab_pointer = 1; /* EIP */
	labels[1].lab_pointer = 1; /* ESP */
	labels[2].lab_pointer = 1; /* EBP */
	/* n <= inst_log verified to be correct limit */
	for (n = 1; n <= inst_log; n++) {
		struct label_s label;
		uint64_t value_id;
		uint64_t value_id2;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		printf("value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64"\n",
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
				printf("SSA Failed at inst_log 0x%x\n", n);
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
				printf("Inst:0x, value3 unknown label %x\n", n);
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
				printf("SSA Failed at inst_log 0x%x\n", n);
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
				printf("Inst:0x, value1 unknown label %x\n", n);
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
				printf("SSA Failed at inst_log 0x%x\n", n);
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
				printf("Inst:0x, value3 unknown label %x\n", n);
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
				printf("SSA Failed at inst_log 0x%x\n", n);
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
				printf("Inst:0x, value1 unknown label %x\n", n);
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
			printf("SSA CALL inst_log 0x%x\n", n);
			if (IND_MEM == instruction->dstA.indirect) {
				value_id = inst_log1->value3.indirect_value_id;
			} else {
				value_id = inst_log1->value3.value_id;
			}
			if (value_id > self->local_counter) {
				printf("SSA Failed at inst_log 0x%x\n", n);
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
				printf("Inst:0x, value3 unknown label %x\n", n);
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
					printf("SSA Failed at inst_log 0x%x\n", n);
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
					printf("Inst:0x, value1 unknown label %x\n", n);
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
			printf("SSA1 failed for Inst:0x%x, OP 0x%x\n", n, instruction->opcode);
			return 1;
			break;
		}
	}
	for (n = 0; n < self->local_counter; n++) {
		printf("labels 0x%x: redirect=0x%"PRIx64", scope=0x%"PRIx64", type=0x%"PRIx64", lab_pointer=0x%"PRIx64", value=0x%"PRIx64"\n",
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
				printf("Found local_reg Inst:0x%x:value_id:0x%"PRIx64"\n", n, value_id1);
				if (0 == inst_log1->prev_size) {
					printf("search_back ended\n");
					return 1;
				}
				if (0 < inst_log1->prev_size) {
					mid_start = calloc(inst_log1->prev_size, sizeof(struct mid_start_s));
					mid_start_size = inst_log1->prev_size;
					for (l = 0; l < inst_log1->prev_size; l++) {
						mid_start[l].mid_start = inst_log1->prev[l];
						mid_start[l].valid = 1;
						printf("mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[l].mid_start, l);
					}
				}
				tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 1, inst_log1->instruction.srcA.index, 0, &size, self->search_back_seen, &inst_list);
				if (tmp) {
					printf("SSA search_back Failed at inst_log 0x%x\n", n);
					return 1;
				}
			}
			printf("SSA inst:0x%x:size=0x%"PRIx64"\n", n, size);
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
					printf("rel inst:0x%"PRIx64"\n", inst_list[l]);
				}
				printf("Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
					label_redirect[value_id1].redirect,
					value_id_highest);
				label_redirect[value_id1].redirect =
					value_id_highest;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					printf("Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
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
			printf("SSA Failed at inst_log 0x%x\n", n);
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
				printf("Found local_stack Inst:0x%x:value_id:0x%"PRIx64"\n", n, value_id1);
				if (0 == inst_log1->prev_size) {
					printf("search_back ended\n");
					return 1;
				}
				if (0 < inst_log1->prev_size) {
					mid_start = calloc(inst_log1->prev_size, sizeof(struct mid_start_s));
					mid_start_size = inst_log1->prev_size;
					for (l = 0; l < inst_log1->prev_size; l++) {
						mid_start[l].mid_start = inst_log1->prev[l];
						mid_start[l].valid = 1;
						printf("mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[l].mid_start, l);
					}
				}
				tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 2, inst_log1->value1.indirect_init_value, inst_log1->value1.indirect_offset_value, &size, self->search_back_seen, &inst_list);
				if (tmp) {
					printf("SSA search_back Failed at inst_log 0x%x\n", n);
					return 1;
				}
			}
			printf("SSA inst:0x%x:size=0x%"PRIx64"\n", n, size);
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
					printf("rel inst:0x%"PRIx64"\n", inst_list[l]);
				}
				printf("Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
					label_redirect[value_id1].redirect,
					value_id_highest);
				label_redirect[value_id1].redirect =
					value_id_highest;
				for (l = 0; l < size; l++) {
					struct inst_log_entry_s *inst_log_l;
					inst_log_l = &inst_log_entry[inst_list[l]];
					printf("Renaming label 0x%"PRIx64" to 0x%"PRIx64"\n",
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
			//printf("SSA2 failed for inst:0x%x, CALL\n", n);
			//return 1;
			break;
		default:
			printf("SSA2 failed for inst:0x%x, OP 0x%x\n", n, instruction->opcode);
			return 1;
			break;
		/* FIXME: TODO */
		}
	}
	/********************************************************
	 * This section filters out duplicate param_reg entries.
         * from the labels table: FIXME: THIS IS NOT NEEDED NOW
	 ********************************************************/
#if 0
	for (n = 0; n < (self->local_counter - 1); n++) {
		int tmp1;
		tmp1 = label_redirect[n].redirect;
		printf("param_reg:scanning base label 0x%x\n", n);
		if ((tmp1 == n) &&
			(labels[tmp1].scope == 2) &&
			(labels[tmp1].type == 1)) {
			int tmp2;
			/* This is a param_stack */
			for (l = n + 1; l < self->local_counter; l++) {
				printf("param_reg:scanning label 0x%x\n", l);
				tmp2 = label_redirect[l].redirect;
				if ((tmp2 == n) &&
					(labels[tmp2].scope == 2) &&
					(labels[tmp2].type == 1) &&
					(labels[tmp1].value == labels[tmp2].value) ) {
					printf("param_stack:found duplicate\n");
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
			printf("Unhandled scan instruction 0x%x\n", l);
			return 1;
		}

		/* Expected param order: %rdi, %rsi, %rdx, %rcx, %r08, %r09 
		                         0x40, 0x38, 0x18, 0x10, 0x50, 0x58, then stack */
		
		printf("scanned: params = 0x%x, locals = 0x%x\n",
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
				printf("JCD5: labels 0x%x, params_size=%d\n", tmp, external_entry_points[l].params_size);
				if (tmp >= self->local_counter) {
					printf("Invalid entry point 0x%x, l=%d, m=%d, n=%d, params_size=%d\n",
						tmp, l, m, n, external_entry_points[l].params_size);
					return 0;
				}
				label = &labels[tmp];
				printf("JCD5: labels 0x%x\n", external_entry_points[l].params[n]);
				printf("JCD5: label=%p, l=%d, m=%d, n=%d\n", label, l, m, n);
				printf("reg_params_order = 0x%x,", reg_params_order[m]);
				printf(" label->value = 0x%"PRIx64"\n", label->value);
				if ((label->scope == 2) &&
					(label->type == 1) &&
					(label->value == reg_params_order[m])) {
					/* Swap params */
					/* FIXME: How to handle the case of params_size <= n or m */
					if (n != m) {
						printf("JCD4: swapping n=0x%x and m=0x%x\n", n, m);
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
		uint64_t value_id;
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
			printf("PARAM Failed at inst_log 0x%x\n", n);
			return 1;
		}
		switch (instruction->opcode) {
		case CALL:
			printf("PRINTING INST CALL\n");
			tmp = print_inst(self, instruction, n, labels);
			external_entry_point = &external_entry_points[instruction->srcA.index];
			inst_log1->extension = calloc(1, sizeof(struct extension_call_s));
			call = inst_log1->extension;
			call->params_size = external_entry_point->params_size;
			/* FIXME: use struct in sizeof bit here */
			call->params = calloc(call->params_size, sizeof(int *));
			if (!call) {
				printf("PARAM failed for inst:0x%x, CALL. Out of memory\n", n);
				return 1;
			}
			printf("PARAM:call size=%x\n", call->params_size);
			printf("PARAM:params size=%x\n", external_entry_point->params_size);
			for (m = 0; m < external_entry_point->params_size; m++) {
				label = &labels[external_entry_point->params[m]];
				if (0 == inst_log1->prev_size) {
					printf("search_back ended\n");
					return 1;
				}
				if (0 < inst_log1->prev_size) {
					mid_start = calloc(inst_log1->prev_size, sizeof(struct mid_start_s));
					mid_start_size = inst_log1->prev_size;
					for (l = 0; l < inst_log1->prev_size; l++) {
						mid_start[l].mid_start = inst_log1->prev[l];
						mid_start[l].valid = 1;
						printf("mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[l].mid_start, l);
					}
				}
				/* param_regXXX */
				if ((2 == label->scope) &&
					(1 == label->type)) {
					printf("PARAM: Searching for REG0x%"PRIx64":0x%"PRIx64" + label->value(0x%"PRIx64")\n", inst_log1->value1.init_value, inst_log1->value1.offset_value, label->value);
					tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 1, label->value, 0, &size, self->search_back_seen, &inst_list);
					printf("search_backJCD1: tmp = %d\n", tmp);
				} else {
				/* param_stackXXX */
				/* SP value held in value1 */
					printf("PARAM: Searching for SP(0x%"PRIx64":0x%"PRIx64") + label->value(0x%"PRIx64") - 8\n", inst_log1->value1.init_value, inst_log1->value1.offset_value, label->value);
					tmp = search_back_local_reg_stack(self, mid_start_size, mid_start, 2, inst_log1->value1.init_value, inst_log1->value1.offset_value + label->value - 8, &size, self->search_back_seen, &inst_list);
				/* FIXME: Some renaming of local vars will also be needed if size > 1 */
				}
				if (tmp) {
					printf("PARAM search_back Failed at inst_log 0x%x\n", n);
					return 1;
				}
				tmp = output_label(label, stdout);
				tmp = fprintf(stdout, ");\n");
				tmp = fprintf(stdout, "PARAM size = 0x%"PRIx64"\n", size);
				if (size > 1) {
					printf("number of param locals (0x%"PRIx64") found too big at instruction 0x%x\n", size, n);
//					return 1;
//					break;
				}
				if (size > 0) {
					for (l = 0; l < size; l++) {
						struct inst_log_entry_s *inst_log_l;
						inst_log_l = &inst_log_entry[inst_list[l]];
						call->params[m] = inst_log_l->value3.value_id;
						// FIXME: Check next line. Force value type to unknown.
						printf("JCD3: Setting value_type to 0, was 0x%x\n", inst_log_l->value3.value_type);
						if (6 == inst_log_l->value3.value_type) {	
							inst_log_l->value1.value_type = 3;
							inst_log_l->value3.value_type = 3;
						}
						printf("JCD1: Param = 0x%"PRIx64", inst_list[0x%x] = 0x%"PRIx64"\n",

							inst_log_l->value3.value_id,
							l,
							inst_list[l]);
						//tmp = label_redirect[inst_log_l->value3.value_id].redirect;
						//label = &labels[tmp];
						//tmp = output_label(label, stdout);
					}
				}
			}
			//printf("SSA2 failed for inst:0x%x, CALL\n", n);
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
	for (n = 1; n <= inst_log; n++) {
		struct label_s label;
		uint64_t value_id;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		printf("value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64"\n",
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
			printf("JCD4: value_id = 0x%"PRIx64", lab_pointer = 0x%"PRIx64", value_id3 = 0x%"PRIx64", lab_pointer = 0x%"PRIx64"\n",
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
		struct label_s label;
		uint64_t value_id;
		uint64_t value_id3;

		inst_log1 =  &inst_log_entry[n];
		instruction =  &inst_log1->instruction;
		printf("value to log_to_label:n = 0x%x: 0x%x, 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%"PRIx64"\n",
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
			printf("JCD4: value_id = 0x%"PRIx64", lab_pointer = 0x%"PRIx64", value_id3 = 0x%"PRIx64", lab_pointer = 0x%"PRIx64"\n",
				value_id, labels[value_id].lab_pointer, value_id3, labels[value_id3].lab_pointer);
			break;

		default:
			break;
		}
	}

	tmp = output_cfg_dot(self, nodes, &nodes_size, label_redirect, labels);
	/***************************************************
	 * This section deals with outputting the .c file.
	 ***************************************************/
	filename = "test.c";
	fd = fopen(filename, "w");
	if (!fd) {
		printf("Failed to open file %s, error=%p\n", filename, fd);
		return 1;
	}
	printf(".c fd=%p\n", fd);
	printf("writing out to file\n");
	tmp = fprintf(fd, "#include <stdint.h>\n\n");
	printf("\nPRINTING MEMORY_DATA\n");
	for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
		struct process_state_s *process_state;
		if (external_entry_points[l].valid) {
			process_state = &external_entry_points[l].process_state;
			memory_data = process_state->memory_data;
			for (n = 0; n < 4; n++) {
				printf("memory_data:0x%x: 0x%"PRIx64"\n", n, memory_data[n].valid);
				if (memory_data[n].valid) {
	
					tmp = relocated_data(handle, memory_data[n].start_address, 4);
					if (tmp) {
						printf("int *data%04"PRIx64" = &data%04"PRIx64"\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
						tmp = fprintf(fd, "int *data%04"PRIx64" = &data%04"PRIx64";\n",
							memory_data[n].start_address,
							memory_data[n].init_value);
					} else {
						printf("int data%04"PRIx64" = 0x%04"PRIx64"\n",
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
	printf("\n");
#if 0
	for (n = 0; n < 100; n++) {
		param_present[n] = 0;
	}
		
	for (n = 0; n < 10; n++) {
		if (memory_stack[n].start_address > 0x10000) {
			uint64_t present_index;
			present_index = memory_stack[n].start_address - 0x10000;
			if (present_index >= 100) {
				printf("param limit reached:memory_stack[%d].start_address == 0x%"PRIx64"\n",
					n, memory_stack[n].start_address);
				continue;
			}
			param_present[present_index] = 1;
			param_size[present_index] = memory_stack[n].length;
		}
	}
	for (n = 0; n < 100; n++) {
		if (param_present[n]) {
			printf("param%04x\n", n);
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
			printf("%d:%s:start=%"PRIu64", end=%"PRIu64"\n", l,
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
					printf("reg_params_order = 0x%x, label->value = 0x%"PRIx64"\n", reg_params_order[m], label->value);
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
	bf_test_close_file(handle);
	print_mem(memory_reg, 1);
	for (n = 0; n < inst_size; n++) {
		printf("0x%04x: %d\n", n, memory_used[n]);
	}
	printf("\nPRINTING MEMORY_DATA\n");
	for (n = 0; n < 4; n++) {
		print_mem(memory_data, n);
		printf("\n");
	}
	printf("\nPRINTING STACK_DATA\n");
	for (n = 0; n < 10; n++) {
		print_mem(memory_stack, n);
		printf("\n");
	}
	for (n = 0; n < 100; n++) {
		param_present[n] = 0;
	}
		
	for (n = 0; n < 10; n++) {
		if (memory_stack[n].start_address >= tmp) {
			uint64_t present_index;
			present_index = memory_stack[n].start_address - 0x10000;
			if (present_index >= 100) {
				printf("param limit reached:memory_stack[%d].start_address == 0x%"PRIx64"\n",
					n, memory_stack[n].start_address);
				continue;
			}
			param_present[present_index] = 1;
			param_size[present_index] = memory_stack[n].length;
		}
	}

	for (n = 0; n < 100; n++) {
		if (param_present[n]) {
			printf("param%04x\n", n);
			tmp = param_size[n];
			n += tmp;
		}
	}
#endif
end_main:
	printf("END - FINISHED PROCESSING\n");
	return 0;
}

