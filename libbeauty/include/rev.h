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

#include <bfd.h>
#include <bfl.h>
#include <inttypes.h>
#include <dis-asm.h>
#include <opcodes.h>

struct reloc_table {
	int		type;
	uint64_t	address;
	uint64_t	size;
	uint64_t	value;
	uint64_t	external_functions_index;
	uint64_t	section_index;
	const char	*section_name;
	const char	*symbol_name;
};

struct rev_eng {
	bfd		*bfd;		/* libbfd structure */
	asection	**section;	/* sections */
	long		section_sz;
	asymbol		**symtab;	/* symbols (sorted) */
	long		symtab_sz;
	asymbol		**dynsymtab; 	/* dynamic symbols (sorted) */
	long		dynsymtab_sz;
	arelent		**dynreloc;	/* dynamic relocations (sorted) */
	long		dynreloc_sz;
	struct reloc_table	*reloc_table_code;   /* relocation table */
	uint64_t	reloc_table_code_sz;
	struct reloc_table	*reloc_table_data;   /* relocation table */
	uint64_t	reloc_table_data_sz;
};

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

/* Params order:
 * int test30(int64_t param_reg0040, int64_t param_reg0038, int64_t param_reg0018, int64_t param_reg0010, int64_t param_reg0050, int64_t param_reg0058, int64_t param_stack0008, int64_t param_stack0010)
 */

struct process_state_s {
	struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	int *memory_used;
};

struct loop_s {
	int head; /* The associated loop_head node */
	int size;
	int *list;
};

struct path_s {
	int used;
	int path_prev;
	int path_prev_index;
	int path_size;
	int type; /* 0 = Unknown, 1 = Loop */
	int loop_head; /* Index to the node that is the loop head for this path. */
	int *path;
};

struct node_mid_start_s {
	int path_prev;
	int path_prev_index;
	int node;
};

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

struct ast_type_index_s {
/* Types:
 * 0 = Not used. // This entry has not been used yet or it is not used any more.
 * 1 = Node.  // This points to the existing Node table.
 * 2 = Container. // This points to the "container" table.
 * 3 = IF. // This points to the "if" table.
 * 4 = LOOP. // This points to the "loop" table.
 */
/* Parent data will not be stored here.
 * The only case not handled is if the type is 1 for Node.
 * We will store the parent data in the Node table instead of here.
 */
	int type; /* Object type. e.g. If, for, while. */
	uint64_t index; /* index into the specific object table */
};
struct ast_container_s {
	struct ast_type_index_s parent; /* So we can traverse the tree */
	int length; /* Number of objects. */
	struct ast_type_index_s *object; /* Array of objects */
};

/* An IF is a special branch condition that does not result in a loop structure. */
struct ast_if_s {
/* FIXME: Must do a sanity check to ensure that a single node contains the BRANCH instruction,
 * 	  and also the associated instruction modifying flags. So the IF expression can be created.
 *	If not the case, throw an exception for now, but then think about what to do about it.
 *	Most likely solution would be trying to migrate the BRANCH up to the flags instruction.
 *	This would potentially duplicate the BRANCH instruction if is crossed a join point.
 */
	struct ast_type_index_s parent; /* So we can traverse the tree */
	struct ast_type_index_s expression_node; /* Normally this would point to the node containing the if expression */
	struct ast_type_index_s if_then;  /* IF expression is true. The "then" path. */
	struct ast_type_index_s if_else; /* IF expression is false, The "else" path. */
};

/* A LOOP is a special branch condition that does result in a loop structure. */
/* This will later be broken out into whether it is a for() or a while() */
struct ast_loop_s {
	struct ast_type_index_s parent; /* So we can traverse the tree */
	struct ast_type_index_s first_node; /* Normally this would point to the first node of the body. */
	struct ast_type_index_s body; /* The rest of the loop body. */
};

struct control_flow_node_s {
	int inst_start;
	int inst_end;
	int prev_size;
	int *prev_node;
	int *prev_type; /* Is previous a loop edge? 1 = Normal, 2 =  loop_edge */
	int next_size;
	int *next_node;
	int *next_type; /* Is next a loop exit? 1 = Normal, 2 = loop_edge, 3 = loop_exit */
	int dominator; /* Node that dominates this node */
	int type; /* 0 =  Normal, 1 =  Part of a loop */
	int loop_head; /* 0 = Normal, 1 = Loop head */
	int if_tail; /* 0 = no tail, > 0 points to the tail of the if...then...else */
	int path_size; /* Number of path entries in the list */
	int *path; /* The list of paths that touch this node */
	int looped_path_size; /* Number of path entries in the list */
	int *looped_path; /* The list of paths that touch this node */
	struct ast_type_index_s parent; /* This is filled in once the AST is being built */
};

struct external_entry_point_s {
	int valid;
	int type; /* 1: Internal, 2: External */
	int section_offset;
	int section_id;
	int section_index;
	uint64_t value; /* pointer to original .text entry point */
	uint64_t inst_log; /* Where the function starts in the inst_log */
	uint64_t inst_log_end; /* Where the function ends in inst_log */
	struct process_state_s process_state;
	char *name;
	/* FIXME: Handle variable amount of params */
	int params_size;
	int *params;
	int *params_order;
	int locals_size;
	int *locals;
	int *locals_order;
	int start_node;
	int paths_size;
	struct path_s *paths;
	int loops_size;
	struct loop_s *loops;
	/* FIXME: add function return type and param types */
};

struct self_s {
	size_t data_size;
	uint8_t *data;
	struct inst_log_entry_s *inst_log_entry;
	disassembler_ftype disassemble_fn;
	struct external_entry_point_s *external_entry_points;
	struct relocation_s *relocations;
	struct entry_point_s *entry_point; /* This is used to hold return values from process block */
	uint64_t entry_point_list_length;  /* Number of entry_point entries allocated */
};

extern int execute_instruction(void *self, struct process_state_s *process_state, struct inst_log_entry_s *inst);
extern int process_block(struct self_s *self, struct process_state_s *process_state, struct rev_eng *handle, uint64_t inst_log_prev, uint64_t eip_offset_limit);
extern int output_label(struct label_s *label, FILE *fd);
extern int print_inst(struct self_s *self, struct instruction_s *instruction, int instruction_number, struct label_s *labels);
extern int write_inst(struct self_s *self, FILE *fd, struct instruction_s *instruction, int instruction_number, struct label_s *labels);
#endif /* __REV__ */
