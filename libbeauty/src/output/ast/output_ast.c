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

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <rev.h>

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
	int fd;
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

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%d\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".dot fd=%d\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out dot to file\n");
	tmp = dprintf(fd, "digraph code {\n"
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
		tmp = dprintf(fd, " \"Container:0x%08x\" ["
                                        "URL=\"Container:0x%08x\" color=\"%s\", label=\"Container:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = dprintf(fd, "\"]\n");
		name = "";
		for (m = 0; m < ast_container[n].length; m++) {
			index = ast_container[n].object[m].index;
			switch (ast_container[n].object[m].type) {
			case AST_TYPE_NODE:
				tmp = dprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        index,
					index, "lightgray", index, name);
				tmp = dprintf(fd, "\"]\n");
				color = "red";
				tmp = dprintf(fd, "\"Container:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_CONTAINER:
				color = "blue";
				tmp = dprintf(fd, "\"Container:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP_CONTAINER:
				color = "blue";
				tmp = dprintf(fd, "\"Container:0x%08x\" -> \"Loop_Container:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_IF_THEN_ELSE:
				color = "blue";
				tmp = dprintf(fd, "\"Container:0x%08x\" -> \"if_then_else:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_IF_THEN_GOTO:
				color = "blue";
				tmp = dprintf(fd, "\"Container:0x%08x\" -> \"if_then_goto:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP:
				color = "blue";
				tmp = dprintf(fd, "\"Container:0x%08x\" -> \"loop:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP_THEN_ELSE:
				color = "blue";
				tmp = dprintf(fd, "\"Container:0x%08x\" -> \"loop_then_else:0x%08x\" [color=\"%s\"];\n",
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
		tmp = dprintf(fd, " \"Loop_Container:0x%08x\" ["
                                        "URL=\"Loop_Container:0x%08x\" color=\"%s\", label=\"Loop_Container:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = dprintf(fd, "\"]\n");
		name = "";
		for (m = 0; m < ast_loop_container[n].length; m++) {
			index = ast_loop_container[n].object[m].index;
			switch (ast_loop_container[n].object[m].type) {
			case AST_TYPE_NODE:
				tmp = dprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        index,
					index, "lightgray", index, name);
				tmp = dprintf(fd, "\"]\n");
				color = "red";
				tmp = dprintf(fd, "\"Loop_Container:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_CONTAINER:
				break;
			case AST_TYPE_LOOP_CONTAINER:
				color = "blue";
				tmp = dprintf(fd, "\"Loop_Container:0x%08x\" -> \"Loop_container:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_IF_THEN_ELSE:
				color = "blue";
				tmp = dprintf(fd, "\"Loop_Container:0x%08x\" -> \"if_then_else:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_IF_THEN_GOTO:
				color = "blue";
				tmp = dprintf(fd, "\"Loop_Container:0x%08x\" -> \"if_then_goto:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP:
				color = "blue";
				tmp = dprintf(fd, "\"Loop_Container:0x%08x\" -> \"loop:0x%08x\" [color=\"%s\"];\n",
					n, index, color);
				break;
			case AST_TYPE_LOOP_THEN_ELSE:
				color = "blue";
				tmp = dprintf(fd, "\"Loop_Container:0x%08x\" -> \"loop_then_else:0x%08x\" [color=\"%s\"];\n",
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
		tmp = dprintf(fd, " \"if_then_else:0x%08x\" ["
                                        "URL=\"if_then_else:0x%08x\" color=\"%s\", label=\"if_then_else:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = dprintf(fd, "\"]\n");
		index = ast_if_then_else[n].expression_node.index;
		switch (ast_if_then_else[n].expression_node.type) {
		case AST_TYPE_NODE:
			color = "gold";
			tmp = dprintf(fd, "\"if_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "gold";
			tmp = dprintf(fd, "\"if_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_if_then_else[n].if_then.index;
		switch (ast_if_then_else[n].if_then.type) {
		case AST_TYPE_NODE:
			color = "green";
			tmp = dprintf(fd, "\"if_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "green";
			tmp = dprintf(fd, "\"if_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
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
			tmp = dprintf(fd, "\"if_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "red";
			debug_print(DEBUG_MAIN, 1, "if_then_else:0x%x TYPE_CONTAINER \n", n);
			tmp = dprintf(fd, "\"if_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
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
		tmp = dprintf(fd, " \"if_then_goto:0x%08x\" ["
                                        "URL=\"if_then_goto:0x%08x\" color=\"%s\", label=\"if_then_goto:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = dprintf(fd, "\"]\n");
		index = ast_if_then_goto[n].expression_node.index;
		switch (ast_if_then_goto[n].expression_node.type) {
		case AST_TYPE_NODE:
			color = "gold";
			tmp = dprintf(fd, "\"if_then_goto:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "gold";
			tmp = dprintf(fd, "\"if_then_goto:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_if_then_goto[n].if_then_goto.index;
		switch (ast_if_then_goto[n].if_then_goto.type) {
		case AST_TYPE_NODE:
			color = "green";
			tmp = dprintf(fd, "\"if_then_goto:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "green";
			tmp = dprintf(fd, "\"if_then_goto:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
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
		tmp = dprintf(fd, " \"loop:0x%08x\" ["
                                        "URL=\"loop:0x%08x\" color=\"%s\", label=\"loop:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = dprintf(fd, "\"]\n");
		index = ast_loop[n].first_node.index;
		tmp = dprintf(fd, " \"Node:0x%08x\" ["
			"URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
			index,
			index, "lightgray", index, name);
		tmp = dprintf(fd, "\"]\n");
		color = "gold";
		tmp = dprintf(fd, "\"loop:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
			n, index, color);
		index = ast_loop[n].body.index;
		switch (ast_loop[n].body.type) {
		case AST_TYPE_NODE:
			color = "red";
			tmp = dprintf(fd, "\"loop:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "red";
			tmp = dprintf(fd, "\"loop:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_IF_THEN_ELSE:
			color = "blue";
			tmp = dprintf(fd, "\"loop:0x%08x\" -> \"if_then_else:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_LOOP:
			color = "blue";
			tmp = dprintf(fd, "\"loop:0x%08x\" -> \"loop:0x%08x\" [color=\"%s\"];\n",
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
		tmp = dprintf(fd, " \"loop_then_else:0x%08x\" ["
                                        "URL=\"loop_then_else:0x%08x\" color=\"%s\", label=\"loop_then_else:0x%08x:%s\\l",
                                        n,
					n, "lightgray", n, name);
		tmp = dprintf(fd, "\"]\n");
		index = ast_loop_then_else[n].expression_node.index;
		switch (ast_loop_then_else[n].expression_node.type) {
		case AST_TYPE_NODE:
			color = "gold";
			tmp = dprintf(fd, "\"loop_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "gold";
			tmp = dprintf(fd, "\"loop_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_loop_then_else[n].loop_then.index;
		switch (ast_loop_then_else[n].loop_then.type) {
		case AST_TYPE_NODE:
			color = "green";
			tmp = dprintf(fd, "\"loop_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "green";
			tmp = dprintf(fd, "\"loop_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
		index = ast_loop_then_else[n].loop_else.index;
		switch (ast_loop_then_else[n].loop_else.type) {
		case AST_TYPE_NODE:
			color = "red";
			tmp = dprintf(fd, "\"loop_then_else:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		case AST_TYPE_CONTAINER:
			color = "red";
			tmp = dprintf(fd, "\"loop_then_else:0x%08x\" -> \"Container:0x%08x\" [color=\"%s\"];\n",
				n, index, color);
			break;
		default:
			break;
		}
	}
#if 0
	for (n = 0; n < nodes[node].next_size; n++) {
		color = "blue";
		tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
			node, nodes[node].link_next[n].node, color);
	}
#endif
	tmp = dprintf(fd, "}\n");
	close(fd);
	return 0;
}

