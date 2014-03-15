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

int output_cfg_dot(struct self_s *self,
                         struct label_redirect_s *label_redirect, struct label_s *labels, int entry_point)
{
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct process_state_s *process_state = &external_entry_points[entry_point].process_state;
	struct control_flow_node_s *nodes = external_entry_points[entry_point].nodes;
	int nodes_size = external_entry_points[entry_point].nodes_size;
	char *filename;
	int fd;
	int node;
	int tmp;
	int n;
	int m;
	int block_end;
	int node_size_limited;
	const char *font = "graph.font";
	const char *color;
	const char *name;
	int value_id;

	if (nodes_size == 0) {
		debug_print(DEBUG_MAIN, 1, "external_entry_point 0x%x empty\n", entry_point);
		return 1;
	}
	filename = calloc(1024, sizeof(char));
	tmp = snprintf(filename, 1024, "./cfg/test-0x%04x-%s.dot", entry_point, external_entry_points[entry_point].name);

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
	node_size_limited = nodes_size;
#if 0
	if (node_size_limited > 50) {
		node_size_limited = 50;
	}
#endif
	for (node = 1; node < nodes_size; node++) {
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
		if (node == 1) {
			name = external_entry_points[entry_point].name;
		} else {
			name = "";
		}
		tmp = dprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s",
                                        node,
					node, "lightgray", node, name);
		if (external_entry_points[entry_point].params_size > 0) {
			char buffer[1024];
			tmp = dprintf(fd, "(");
			for (n = 0; n < external_entry_points[entry_point].params_size; n++) {
				int label_index;
				label_index = external_entry_points[entry_point].params[n];
				tmp = label_to_string(&external_entry_points[entry_point].labels[label_index], buffer, 1023);
				dprintf(fd, "%s", buffer);
				if (n + 1 < external_entry_points[entry_point].params_size) {
					tmp = dprintf(fd, ", ");
				}
			}
			tmp = dprintf(fd, ")");
		}
		tmp = dprintf(fd, "\\l");
		tmp = dprintf(fd, "type = 0x%x\\l",
				nodes[node].type);
		if (nodes[node].if_tail) {
			tmp = dprintf(fd, "if_tail = 0x%x\\l",
				nodes[node].if_tail);
		}
		if (nodes[node].phi_size) {
			for (n = 0; n < nodes[node].phi_size; n++) {
				tmp = dprintf(fd, "phi[%d] = REG0x%x:0x%x ",
					n, nodes[node].phi[n].reg, nodes[node].phi[n].value_id);
				for (m = 0; m < nodes[node].phi[n].phi_node_size; m++) {
					//tmp = get_value_id_from_node_reg(self, nodes[node].entry_point, nodes[node].phi[n].phi_node[m].node, nodes[node].phi[n].reg, &value_id);
					tmp = dprintf(fd, "FPN:0x%x:SN:0x%x:L:0x%x, ",
						nodes[node].phi[n].phi_node[m].first_prev_node,
						nodes[node].phi[n].phi_node[m].node,
						nodes[node].phi[n].phi_node[m].value_id);
				}
#if 0
				for (m = 0; m < nodes[node].path_size; m++) {
					tmp = dprintf(fd, "P0x%x:FPN:0x%x:SN:0x%x, ",
						nodes[node].phi[n].path_node[m].path,
						nodes[node].phi[n].path_node[m].first_prev_node,
						nodes[node].phi[n].path_node[m].node);
				}
				for (m = 0; m < nodes[node].looped_path_size; m++) {
					tmp = dprintf(fd, "LP0x%x:FPN:0x%x:SN:0x%x, ",
						nodes[node].phi[n].looped_path_node[m].path,
						nodes[node].phi[n].looped_path_node[m].first_prev_node,
						nodes[node].phi[n].looped_path_node[m].node);
				}
#endif
				tmp = dprintf(fd, "\\l");
			}
		}
		n = nodes[node].inst_start;
		block_end = 0;
		do {
			inst_log1 =  &inst_log_entry[n];
			instruction =  &inst_log1->instruction;
			//tmp = write_inst(self, fd, instruction, n, NULL);
			//tmp = dprintf(fd, "\\l");
			printf("output_cfg:Inst 0x%x: label1 = 0x%"PRIx64", label2 = 0x%"PRIx64", label3 = 0x%"PRIx64"\n",
				n,
				inst_log1->value1.value_id,
				inst_log1->value2.value_id,
				inst_log1->value3.value_id);
			tmp = output_inst_in_c(self, process_state, fd, n, label_redirect, labels, "\\l");
			//tmp = dprintf(fd, "\\l\n");
			if (inst_log1->node_end || !(inst_log1->next_size)) {
				block_end = 1;
			} else {
				n = inst_log1->next[0];
			}
		} while (!block_end);
		tmp = dprintf(fd, "\"];\n");
		for (n = 0; n < nodes[node].next_size; n++) {
			char *label;
			if (nodes[node].next_size < 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else {
					color = "blue";
				}
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
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
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color, label);
			} else {
				/* next_size > 2 */
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"0x%x\"];\n",
					node, nodes[node].link_next[n].node, color, n);
			}
		}
	}
	tmp = dprintf(fd, "}\n");
	close(fd);
	return 0;
}

int output_cfg_dot_basic(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size)
{
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	char *filename;
	int fd;
	int node;
	int tmp;
	int n;
	int node_size_limited;
	const char *font = "graph.font";
	const char *color;
	const char *name;

	filename = calloc(1024, sizeof(char));
	tmp = snprintf(filename, 1024, "./cfg/basic.dot");

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (!fd) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%d\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".dot fd=%d\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out dot to file\n");
	tmp = dprintf(fd, "digraph code {\n"
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
		tmp = dprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        node,
					node, "lightgray", node, name);
		tmp = dprintf(fd, "type = 0x%x\\l",
				nodes[node].type);
		if (nodes[node].if_tail) {
			tmp = dprintf(fd, "if_tail = 0x%x\\l",
				nodes[node].if_tail);
		}
		tmp = dprintf(fd, "\"];\n");

		for (n = 0; n < nodes[node].next_size; n++) {
			char *label;
			if (nodes[node].next_size < 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else {
					color = "blue";
				}
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
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
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color, label);
			} else {
				/* next_size > 2 */
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"0x%x\"];\n",
					node, nodes[node].link_next[n].node, color, n);
			}
		}
	}
	tmp = dprintf(fd, "}\n");
	close(fd);
	return 0;
}

int output_cfg_dot_basic2(struct self_s *self, struct external_entry_point_s *external_entry_point)
{
	char *filename;
	int fd;
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

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (!fd) {
		debug_print(DEBUG_MAIN, 1, "Failed to open file %s, error=%d\n", filename, fd);
		return 1;
	}
	debug_print(DEBUG_MAIN, 1, ".dot fd=%d\n", fd);
	debug_print(DEBUG_MAIN, 1, "writing out dot to file\n");
	tmp = dprintf(fd, "digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"%s\" fontsize=\"8\"];\n", font);
	node_size_limited = nodes_size;

	for (node = 1; node < nodes_size; node++) {
		if (!nodes[node].valid) {
			/* Only output nodes that are valid */
			continue;
		}
		if (node == 1) {
			name = external_entry_point->name;
		} else {
			name = "";
		}
		tmp = dprintf(fd, " \"Node:0x%08x\" ["
                                        "URL=\"Node:0x%08x\" color=\"%s\", label=\"Node:0x%08x:%s\\l",
                                        node,
					node, "lightgray", node, name);
		tmp = dprintf(fd, "type = 0x%x\\l",
				external_entry_point->nodes[node].type);
		if (external_entry_point->nodes[node].if_tail) {
			tmp = dprintf(fd, "if_tail = 0x%x\\l",
				external_entry_point->nodes[node].if_tail);
		}
		tmp = dprintf(fd, "\"];\n");

		for (n = 0; n < external_entry_point->nodes[node].next_size; n++) {
			char *label;
			if (nodes[node].next_size < 2) {
				if (1 == nodes[node].link_next[n].is_loop_edge) {
					color = "gold";
				} else {
					color = "blue";
				}
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\"];\n",
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
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"%s\"];\n",
					node, nodes[node].link_next[n].node, color, label);
			} else {
				/* next_size > 2 */
				tmp = dprintf(fd, "\"Node:0x%08x\" -> \"Node:0x%08x\" [color=\"%s\" label=\"0x%x\"];\n",
					node, nodes[node].link_next[n].node, color, n);
			}
		}
	}
	tmp = dprintf(fd, "}\n");
	close(fd);
	return 0;
}

