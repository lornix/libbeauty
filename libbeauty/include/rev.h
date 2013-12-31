/*
 *  Copyright (C) 2009 The libbeauty Team
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

#ifndef __REV__
#define __REV__

#include <inttypes.h>
#include <global_struct.h>
#include <opcodes.h>

#define DEBUG_MAIN 1
#define DEBUG_INPUT_BFD 2
#define DEBUG_INPUT_DIS 3
#define DEBUG_OUTPUT 4
#define DEBUG_EXE 5
#define DEBUG_ANALYSE 6
#define DEBUG_ANALYSE_PATHS 7
#define DEBUG_ANALYSE_PHI 8

void debug_print(int module, int level, const char *format, ...) __attribute__((__format__ (printf, 3, 4)));

#include <dis.h>
#include <exe.h>
#include <output.h>

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

#define REG_PARAMS_ORDER_MAX 6
/* RDI, RSI, RDX, RCX, R08, R09  */
extern int reg_params_order[];

struct extension_call_s {
	int params_size;
	int *params;
};

struct string_s {
	char string[1024];
	int len;
	int max;
};

/* Params order:
 * int test30(int64_t param_reg0040, int64_t param_reg0038, int64_t param_reg0018, int64_t param_reg0010, int64_t param_reg0050, int64_t param_reg0058, int64_t param_stack0008, int64_t param_stack0010)
 */

/* AST: Abstract syntax tree 
 * Structures to build an AST.
 * An AST provides extra data over the CFG: Control Flow Graph, NODES,
 * because it describes structure (if...then...else, and loops), and therefore closer to the 
 * final output in the programming language of choice.
 * It is used to group NODES together, and associate them with structure. e.g. Part of a for() loop.
 * This will make is easier to read the resulting source code because
 * before everything was if...then...else, but now a new construct of a for() loop can be
 * shown, as it is a special case of the if...then...else.
 * Also, the if...then...else can now contain lists of statements, instead of if...then goto...else goto.
 * Thus, reducing the amount of gotos in the resulting source code, making it easier to read.
 * FIXME: At first this is not a proper full AST of each program statement, but 
 * it is instead an AST at the NODE level.
 * FIXME: jump tables and call tables not taken into account yet.
 */

struct ast_entry_s {
	int type;
	int sub_type;
	int index;
	int sub_index;
	int node;
	int node_end; // Node to end at.
};

struct ast_type_parent_s {
	int type; /* Object type. e.g. If, for, while. */
	uint64_t index; /* index into the specific object table */
	int offset; /* Specific entry in the object list. Point to the object that points to us */
};
struct ast_container_s {
	struct ast_type_parent_s parent; /* So we can traverse the tree */
	int start_node;
	int sub_type; /* 0 = normal container, 1 = loop container */
	int length; /* Number of objects. */
	struct ast_type_index_s *object; /* Array of objects */
};

/* An IF is a special branch condition that does not result in a loop structure. */
struct ast_if_then_else_s {
/* FIXME: Must do a sanity check to ensure that a single node contains the BRANCH instruction,
 * 	  and also the associated instruction modifying flags. So the IF expression can be created.
 *	If not the case, throw an exception for now, but then think about what to do about it.
 *	Most likely solution would be trying to migrate the BRANCH up to the flags instruction.
 *	This would potentially duplicate the BRANCH instruction if is crossed a join point.
 */
	struct ast_type_parent_s parent; /* So we can traverse the tree */
	struct ast_type_index_s expression_node; /* Normally this would point to the node containing the if expression */
	struct ast_type_index_s if_then;  /* IF expression is true. The "then" path. */
	struct ast_type_index_s if_else; /* IF expression is false, The "else" path. */
};

/* An IF is a special branch condition that does not result in a loop structure. */
struct ast_if_then_goto_s {
/* FIXME: Must do a sanity check to ensure that a single node contains the BRANCH instruction,
 * 	  and also the associated instruction modifying flags. So the IF expression can be created.
 *	If not the case, throw an exception for now, but then think about what to do about it.
 *	Most likely solution would be trying to migrate the BRANCH up to the flags instruction.
 *	This would potentially duplicate the BRANCH instruction if is crossed a join point.
 */
	struct ast_type_parent_s parent; /* So we can traverse the tree */
	struct ast_type_index_s expression_node; /* Normally this would point to the node containing the if expression */
	struct ast_type_index_s if_then_goto;  /* IF expression is true. The "then" path, ending in a goto . */
};


/* A LOOP is a special branch condition that does result in a loop structure. */
/* This will later be broken out into whether it is a for() or a while() */
struct ast_loop_s {
	struct ast_type_parent_s parent; /* So we can traverse the tree */
	struct ast_type_index_s first_node; /* Normally this would point to the first node of the body. */
	struct ast_type_index_s body; /* The rest of the loop body. */
};

/* A LOOP that starts with an IF is a special branch condition that does not result in a loop structure. */
/* Also can be applied to loops where the first block is a normal block with one next edge. */
/* The only real difference between a loop_container and a normal container is the way
 * we decide the scope of it.
 * The "loop_container" uses the member_of_loop[] to decide.
 * The "container" uses the tail node to decide.
 */
struct ast_loop_container_s {
	struct ast_type_parent_s parent; /* So we can traverse the tree */
	int start_node;
	int length; /* Number of objects. */
	struct ast_type_index_s *object; /* Array of objects */
};

struct ast_loop_then_else_s {
/* FIXME: Must do a sanity check to ensure that a single node contains the BRANCH instruction,
 * 	  and also the associated instruction modifying flags. So the IF expression can be created.
 *	If not the case, throw an exception for now, but then think about what to do about it.
 *	Most likely solution would be trying to migrate the BRANCH up to the flags instruction.
 *	This would potentially duplicate the BRANCH instruction if is crossed a join point.
 */
	struct ast_type_parent_s parent; /* So we can traverse the tree */
	struct ast_type_index_s expression_node; /* Normally this would point to the node containing the if expression */
	struct ast_type_index_s loop_then;  /* IF expression is true. The "then" path. */
	struct ast_type_index_s loop_else; /* IF expression is false, The "else" path. */
};

struct ast_s {
	struct ast_container_s *ast_container;
	struct ast_if_then_else_s *ast_if_then_else;
	struct ast_if_then_goto_s *ast_if_then_goto;
	struct ast_loop_s *ast_loop;
	struct ast_loop_container_s *ast_loop_container;
	struct ast_loop_then_else_s *ast_loop_then_else;
	struct ast_entry_s *ast_entry;
	int container_size;
	int if_then_else_size;
	int if_then_goto_size;
	int loop_size;
	int loop_container_size;
	int loop_then_else_size;
	int entry_size;
};

extern int execute_instruction(struct self_s *self, struct process_state_s *process_state, struct inst_log_entry_s *inst);
extern int process_block(struct self_s *self, struct process_state_s *process_state, uint64_t inst_log_prev, uint64_t eip_offset_limit);
int output_function_body(struct self_s *self, struct process_state_s *process_state,
			 int fd, int start, int end, struct label_redirect_s *label_redirect, struct label_s *labels);
uint32_t output_function_name(int fd,
		struct external_entry_point_s *external_entry_point);
int output_inst_in_c(struct self_s *self, struct process_state_s *process_state,
			 int fd, int inst_number, struct label_redirect_s *label_redirect, struct label_s *labels, const char *cr);
uint32_t relocated_data(void *handle, uint64_t offset, uint64_t size);
extern int print_inst(struct self_s *self, struct instruction_s *instruction, int instruction_number, struct label_s *labels);
extern int write_inst(struct self_s *self, struct string_s *string, struct instruction_s *instruction, int instruction_number, struct label_s *labels);
extern int print_inst_short(struct self_s *self, struct instruction_s *instruction);
extern int disassemble(struct self_s *self, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t buffer_size, uint64_t offset);
extern void disassemble_callback_start(struct self_s *self);
extern void disassemble_callback_end(struct self_s *self);

#include <bfl.h>
#include <analyse.h>
#include <llvm.h>
#include <output.h>

#endif /* __REV__ */
