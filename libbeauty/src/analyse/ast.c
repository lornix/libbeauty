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

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <rev.h>

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

