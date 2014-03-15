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

#ifndef GLOBAL_STRUCT_H
#define GLOBAL_STRUCT_H

#include <inttypes.h>
#include <stdlib.h>

#define MAX_REG 0x1c0
#define EXTERNAL_ENTRY_POINTS_MAX 1000

struct reloc_table_s {
	int		type;
	uint64_t	address;
	uint64_t	size;
	uint64_t	addend;
	uint64_t	external_functions_index;
	uint64_t	section_index;
	uint64_t	relocated_area;
	uint64_t	symbol_value;
	const char	*section_name;
	const char	*symbol_name;
};

struct process_state_s {
	struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	int *memory_used;
};

struct loop_s {
	int head; /* The associated loop_head node */
	int nest;
	int multi_exit; /* 0 = unknown amount of exits, 1 = single exit, 2 = multi-exit loop */
	int size;
	int *list;
};

#define PATH_TYPE_UNKNOWN 0
#define PATH_TYPE_LOOP 1

struct path_s {
	int used;
	int path_prev;
	int path_prev_index;
	int path_size;
	int type; /* 0 = Unknown, 1 = Loop */
	int loop_head; /* Index to the node that is the loop head for this path. */
	int *path; /* The node within the path, FIXME: rename this to node */
};

struct node_mid_start_s {
	int path_prev;
	int path_prev_index;
	int node;
};

/*	FIXME: the concept of link length. If you were looking at the .dot graph,
 *	would the link be a long line or a short one. This could have some baring
 *      in whether the link should be turned into a goto.
 *	It could also hold information regarding link elasticity.
 *	Link elasticity is the property whereby if you look at the .dot graph, there is room to increase
 *	the link lenght to the previous node, at the expense of decreasing the length of the link to
 *	the next node.
 */
struct node_link_s {
	int node;
	int is_normal;
	int is_loop_edge;
	int is_loop_exit;
	int is_loop_entry;
	int length;
	int elasticity;
};

struct node_used_register_s {
	/* If SRC and DST in same instruction, set SRC first in seen. */
	int seen; /* 0 = Not seen, 1 = SRC first, 2 = DST first */
	int size; /* The size of the register seen */
	/* Points to last src in the block */
	int src;  /* Set when the register is used by the node. Points to instruction */
	/* Points to last dst in the block */
	int dst;  /* Set when the register is modified by the node. Points to instruction */
	/* Points to the first src in the block */
	int src_first;
	/* If seen == 1, then label depends on phi, previous nodes, or a param. */
	int src_first_value_id;
	/* Node where this label is defined */
	int src_first_node;
	/* 0 = not found yet.
	   1 = phi.
	   2 = previous node.
	   3 = param.
	 */
	int src_first_label;
};

struct path_node_s {
	int path;
	int first_prev_node;
	int node;
	int value_id; /* The SSA ID of the label attached to this phi instruction src. */
};

struct phi_node_s {
	int first_prev_node;
	int node;
	int path_count;
	int value_id; /* The SSA ID of the label attached to this phi instruction src. */
};

struct phi_s {
	int reg; /* The CPU RTL register that this phi instruction refers to. */
	int value_id; /* The SSA ID of the label attached to this phi instruction dst. */
	int path_node_size;
	struct path_node_s *path_node;
	int looped_path_node_size;
	struct path_node_s *looped_path_node;
	int phi_node_size;
	struct phi_node_s *phi_node;
};

/* Types: */
#define AST_TYPE_EMPTY 0	// This entry has not been used yet or it is not used any more.
#define AST_TYPE_NODE 1		// This points to the existing Node table.
#define AST_TYPE_CONTAINER 2	// This points to the "container" table.
#define AST_TYPE_IF_THEN_ELSE 3	// This points to the "if else" table.
#define AST_TYPE_IF_THEN_GOTO 4	// This points to the "if goto" table.
#define AST_TYPE_LOOP 5		// This points to the "loop" table.
#define AST_TYPE_LOOP_THEN_ELSE 6	// This points to the "loop_then_else" table.
#define AST_TYPE_LOOP_CONTAINER 7	// This points to the "loop_container" table.

struct ast_type_index_s {
/* Parent data will not be stored here.
 * The only case not handled is if the type is 1 for Node.
 * We will store the parent data in the Node table instead of here.
 */
	int type; /* Object type. e.g. If, for, while. */
	uint64_t index; /* index into the specific object table */
};

struct tip_s {
	int valid;  /* Is this entry valid? More use for when we need to delete individual entries */
	int inst_number; /* Number of the inst_log entry */
	int operand; /* Which operand of the instruction? 1 = srcA/value1, 2 = srcB/value2, 3 = dstA/value3 */
	int lab_pointer_first;  /* Is this a pointer. Determined from the LOAD or STORE command */
	int lab_pointer_inferred;
	int size_bits_first;
	int size_bits_inferred;
	int lab_pointer_size_first;
	int lab_pointer_size_inferred;
};

/* redirect is used for SSA correction, when one needs to rename a variable */
/* renaming the variable within the log entries would take too long. */
/* so use log entry value_id -> redirect -> label_s */
struct label_redirect_s {
	uint64_t redirect;
};

struct label_s {
	/* local = 1, param = 2, data = 3, mem = 4, sp_bp = 5 */
	uint64_t scope;
	/* For local or param: reg = 1, stack = 2 */
	/* For data: data = 1, &data = 2, value = 3 */
	uint64_t type;
	/* value */
	uint64_t value;
	/* size in bits */
	uint64_t size_bits;
	/* pointer type size in bits */
	uint64_t pointer_type_size_bits;
	/* is it a pointer */
	uint64_t lab_pointer;
	/* is it a signed */
	uint64_t lab_signed;
	/* is it a unsigned */
	uint64_t lab_unsigned;
	/* Type Inference Propagation */
	struct tip_s *tip;
	/* human readable name */
	char *name;
};

#define NODE_TYPE_UNKNOWN 0
#define NODE_TYPE_LOOP 1
#define NODE_TYPE_IF_THEN_ELSE 2
#define NODE_TYPE_IF_THEN_GOTO 3
#define NODE_TYPE_NORMAL 4
#define NODE_TYPE_LOOP_THEN_ELSE 5
#define NODE_TYPE_JMPT 6

struct control_flow_node_s {
	int valid; /* 0 == invalid/un-used, 1 == valid/used */
	int entry_point; /* Can use this to find the name on the node. */
	int inst_start;
	int inst_end;
	int prev_size;
	int *prev_node;
	int *prev_link_index;
	int next_size;
	struct node_link_s *link_next;
	int dominator; /* Node that dominates this node */
	int type; /* 0 =  Normal, 1 =  Part of a loop, 2 = normal if statement */
	int loop_head; /* 0 = Normal, 1 = Loop head */
	int if_tail; /* 0 = no tail, > 0 points to the tail of the if...then...else */
	int path_size; /* Number of path entries in the list */
	int *path; /* The list of paths that touch this node */
	int looped_path_size; /* Number of path entries in the list */
	int *looped_path; /* The list of paths that touch this node */
	int member_of_loop_size; /* Number of member_of_loop entries in the list */
	int *member_of_loop; /* The list of member_of_loop entries. One entry for each loop this node belongs to */
	struct ast_type_index_s parent; /* This is filled in once the AST is being built */
	int depth; /* Where abouts in a graph does it go. 1 = Top of graph, 10 = 10th step down */
	int multi_exit; /* 0 = unknown amount of exits, 1 = single exit, 2 = multi-exit loop */
	struct node_used_register_s *used_register;
	int phi_size;
	struct phi_s *phi;
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
	int param_reg_label[MAX_REG];
	int locals_size;
	int *locals;
	int *locals_order;
	int start_node;
	int paths_size;
	struct path_s *paths;
	int loops_size;
	struct loop_s *loops;
	int nodes_size;
	struct control_flow_node_s *nodes;
	int member_nodes_size; 
	/* A list of all the global nodes that are part of this function */
	/* Provides a mapping between the global nodes list and the function nodes list. */
	int *member_nodes;
	int start_ast_container;
	/* FIXME: add function return type and param types */
	struct label_redirect_s *label_redirect;
	struct label_s *labels;
	int variable_id;
	int *search_back_seen;
};

/* Memory and Registers are a list of accessed stores. */
/* A record is only valid when it has been accessed. */
/* Initially the search algorithm will be slow,
 * but if the method works, fast algorithms will be used. */

struct memory_s {
	/* Start address of multibyte access. */
	uint64_t start_address;
	/* Number of bytes accessed at one time */
	int length;
	/* 0 - Unknown, 1 - Known */
	int init_value_type;
	/* Initial value when first accessed */
	uint64_t init_value;
	/* init_value + offset_value = absolute value to be used */
	uint64_t offset_value;
	/* Indirect value */
	/* E.g. MOV %rax, [%rsp]    The indirect_offset_value will be the value of %rsp, the 
	 * value_id will be the stack label.
	 * the init_value and offset_value will be %rax that fills [%rsp].
	 */
	uint64_t indirect_init_value;
	/* Indirect offset */
	uint64_t indirect_offset_value;
	/* 0 - unknown,
	 * 1 - unsigned,
	 * 2 - signed,
	 * 3 - pointer,
	 * 4 - Instruction,
	 * 5 - Instruction pointer(EIP),
	 * 6 - Stack pointer.
	 */
	int	value_type;
	/* Moving to: */
	/* 0 - Unlikely
	 * 1 or above - more likely
	 */
	int	value_unsigned;
	int	value_signed;
	int	value_instruction;
	int	value_pointer;
	int	value_normal;
	/* Index into the various structure tables */
	int	value_struct;
	/* last_accessed_from_instruction_at_memory_location */
	uint32_t ref_memory;
	/* last_accessed_from_instruction_log_at_location */
	uint32_t ref_log;
	/* value_scope: 0 - unknown, 1 - Param, 2 - Local, 3 - Global */
	int value_scope;
	/* Each time a new value is assigned, this value_id increases */
	uint64_t value_id;
	/* valid: 0 - Entry Not used yet, 1 - Entry Used */
	uint64_t valid;
	/* The instruction that assigned the value within SSA scope */
	/* If size > 1 there is more than one path between there and here */
	int prev_size;
	int *prev;
	/* The instruction that uses the value within SSA scope */
	/* If size > 1 there is more than one path between there and here */
	int next_size;
	int *next;
};

struct entry_point_s {
	int used;
	/* FIXME: Is this enough, or will full register backup be required */
	uint64_t esp_init_value;
	uint64_t esp_offset_value;
	uint64_t ebp_init_value;
	uint64_t ebp_offset_value;
	uint64_t eip_init_value;
	uint64_t eip_offset_value;
	uint64_t previous_instuction;
};

struct operand_s {
	/* 0 = immeadiate value. ( e.g. MOV AX,0x0),
	 * 1 = register value. (e.g. MOV AX,BX),
	 * 2 = immeadiate pointer. (if the immeadiate value is in the relocation table) 
	 */
	int store;
	/* 0 = not relocated.
	 * 1 = relocated. (if the immeadiate value is in the relocation table)
	 */
	int relocated;
	/* The section to point to. e.g. .rodata
	 * 0 = NULL
	 * 1 = code
	 * 2 = rodata
	 * 3 = data
	 * >3 is malloc sections
	 */
	int relocated_area;
	/* The offset withing the section of point to */
	int relocated_index;
	/* 0 = direct, 1 = data_memory, 2 = stack_memory, 3 = in-out port */

	/* For IF instruction, the value "indirect" contains
         * 0 = relative
         * 1 = absolute
         */
	int indirect;
	/* number of bits in the indirect value. */
	int indirect_size;
	/* value depends on store */
	/* For IF srcA, this is the condition statement */
	/* For IF dstA, this is the IP memory index. */
	uint64_t index;
	/* value depends on store */
	/* For IF dstA, this is within this group's RTL index. */
	uint64_t value;
	/* number of bits in value. */
	/* For IF dstA, this will be a 32 bits. */
	int value_size;
} ;

/* A single RTL instruction */
/* E.g. A = B + C. See below to operands assignment ordering. */
struct instruction_s {
	int opcode;
	/* Set to 1 if this instruction should effect flags. */
	int flags;
	int predicate;
	struct operand_s srcA; /* E.g. B */
	struct operand_s srcB; /* E.g. C */
	struct operand_s dstA; /* E.g. A */
} ;

struct inst_log_entry_s {
	struct instruction_s instruction;	/* The instruction */
	int prev_size;
	int *prev;
	int next_size;
	int *next;
	struct memory_s value1;		/* First input value */
	struct memory_s value2;		/* Second input value */
	struct memory_s value3;		/* Result */
	int node_start;			/* Is this instruction the start of a node 0 == No, 1 == Yes */
	int node_member;		/* The node this instrustion is a member off */
	int node_end;			/* Is this instruction the end of a node 0 == No, 1 == Yes */
	void *extension;		/* Instruction specific extention */
};

struct self_s {
	int *section_number_mapping;
	void *handle_void;
	void *ll_inst;
	void *decode_asm;
	size_t data_size;
	uint8_t *data;
	size_t rodata_size;
	uint8_t *rodata;
	struct inst_log_entry_s *inst_log_entry;
	struct external_entry_point_s *external_entry_points;
	struct relocation_s *relocations;
	struct entry_point_s *entry_point; /* This is used to hold return values from process block */
	uint64_t entry_point_list_length;  /* Number of entry_point entries allocated */
	int nodes_size;
	struct control_flow_node_s *nodes;
	int flag_dependency_size;
	int *flag_dependency;
	int *flag_dependency_opcode;
	int *flag_result_users;
};

#endif /* GLOBAL_STRUCT_H */
