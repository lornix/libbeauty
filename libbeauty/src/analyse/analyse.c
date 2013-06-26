/*
 *  Copyright (C) 2004-2012 The libbeauty Team
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
 * 26-10-2012 Initial work.
 *   Copyright (C) 2004 James Courtier-Dutton James@superbug.co.uk
 *
 */


#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <rev.h>

/* This scans for duplicates in the inst_log1->next[] and inst_log1->prev[n] lists. */
int tidy_inst_log(struct self_s *self)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	int l,m,n;

	for (n = 1; n < inst_log; n++) {
		inst_log1 =  &inst_log_entry[n];
		if (inst_log1->next_size > 1) {
			if (inst_log1->next_size > 2) {
				debug_print(DEBUG_ANALYSE, 1, "next: over:before inst 0x%x\n", n);
				for (m = 0; m < inst_log1->next_size; m++) {
					debug_print(DEBUG_ANALYSE, 1, "next: 0x%x: next[0x%x] = 0x%x\n", n, m, inst_log1->next[m]);
				}
			}
			for (m = 0; m < (inst_log1->next_size - 1); m++) {
				for (l = m + 1; l < inst_log1->next_size; l++) {
					debug_print(DEBUG_ANALYSE, 1, "next: 0x%x: m=0x%x, l=0x%x\n", n, inst_log1->next[m],inst_log1->next[l]);
					if (inst_log1->next[m] == inst_log1->next[l]) {
						inst_log1->next[m] = 0;
						debug_print(DEBUG_ANALYSE, 1, "next: post: 0x%x: m=0x%x, l=0x%x\n", n, inst_log1->next[m],inst_log1->next[l]);
					}
				}
			}
			for (m = 0; m < (inst_log1->next_size - 1); m++) {
				if (inst_log1->next[m] == 0) {
					for (l = m + 1; l < (inst_log1->next_size); l++) {
						inst_log1->next[l - 1] = inst_log1->next[l];
					}
					inst_log1->next_size--;
					inst_log1->next = realloc(inst_log1->next, inst_log1->next_size * sizeof(int));
				}
			}
			if (inst_log1->next_size > 2) {
				debug_print(DEBUG_ANALYSE, 1, "next: over:after inst 0x%x\n", n);
				for (m = 0; m < inst_log1->next_size; m++) {
					debug_print(DEBUG_ANALYSE, 1, "next: 0x%x: next[0x%x] = 0x%x\n", n, m, inst_log1->next[m]);
				}
			}
		}
		if (inst_log1->prev_size > 1) {
			for (m = 0; m < (inst_log1->prev_size - 1); m++) {
				for (l = m + 1; l < inst_log1->prev_size; l++) {
					debug_print(DEBUG_ANALYSE, 1, "prev: 0x%x: m=0x%x, l=0x%x\n", n, inst_log1->prev[m],inst_log1->prev[l]);
					if (inst_log1->prev[m] == inst_log1->prev[l]) {
						inst_log1->prev[m] = 0;
					}
				}
			}
			for (m = 0; m < (inst_log1->prev_size - 1); m++) {
				if (inst_log1->prev[m] == 0) {
					for (l = m + 1; l < (inst_log1->prev_size); l++) {
						inst_log1->prev[l - 1] = inst_log1->prev[l];
					}
					inst_log1->prev_size--;
					inst_log1->prev = realloc(inst_log1->prev, inst_log1->prev_size * sizeof(int));
				}
			}
		}
		if ((1 == inst_log1->prev_size) && (0 == inst_log1->prev[0])) {
			inst_log1->prev_size = 0;
			free(inst_log1->prev);
			inst_log1->prev = 0;
		}
	}
	return 0;
}

int find_node_from_inst(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, int inst)
{
/* FIXME: this needs fixing to use next and prev instructions, instead of linear n */
	int n;
	int found = 0;
	for (n = 1; n <= *node_size; n++) {
		if ((nodes[n].inst_start <= inst) &&
			(nodes[n].inst_end >= inst)) {
			found = n;
			break;
		}
	}
	return found;
}

int node_mid_start_add(struct control_flow_node_s *node, struct node_mid_start_s *node_mid_start, int path, int step)
{
	int n;
	int limit = node->next_size;
	int index = 1;

	for (n = 0; n < 1000; n++) {
		if (node_mid_start[n].node == 0) {
			node_mid_start[n].node = node->link_next[index].node;
			node_mid_start[n].path_prev = path;
			node_mid_start[n].path_prev_index = step;
			index++;
			if (index >= limit) {
				break;
			}
		}
	}
	return 0;
}

int path_loop_check(struct path_s *paths, int path, int step, int node, int limit)
{
	int tmp;
	int path1 = path;

	int n = 0;

	debug_print(DEBUG_ANALYSE, 1, "path_loop_check: path = 0x%x, step = 0x%x, node = 0x%x, loop_head = 0x%x\n", path, step, node, paths[path].loop_head);

	while (n < limit) {
		n++;
		step--;
		if (step < 0) {
			//debug_print(DEBUG_ANALYSE, 1, "step < 0: 0x%x, 0x%x\n", paths[path].path_prev, paths[path].path_prev_index);
			if (paths[path].path_prev != path) {
				tmp = paths[path].path_prev;
				step = paths[path].path_prev_index;
				path = tmp;
			} else {
			// debug_print(DEBUG_ANALYSE, 1, "No loop\n");
				return 0;
			}
		}
		//debug_print(DEBUG_ANALYSE, 1, "loop_check: path=0x%x, step=0x%x, path_step=0x%x, node=0x%x\n",
		//	path, step, paths[path].path[step], node);
		if (paths[path].path[step] ==  node) {
			// debug_print(DEBUG_ANALYSE, 1, "Loop found\n");
			paths[path1].type = PATH_TYPE_LOOP;
			return 1;
		}
	};
	if (n >= limit) {
		/* The maximum lenght of a path is the number of nodes */
		debug_print(DEBUG_ANALYSE, 1, "loop check limit reached\n");
		return 2;
	}
	return 0;
}


int merge_path_into_loop(struct path_s *paths, struct loop_s *loop, int path)
{
	int step;
	int tmp;
	int found;
	int n;
	int *list = loop->list;

	debug_print(DEBUG_ANALYSE, 1, "trying to merge path %d into loop\n", path);

	loop->head = paths[path].loop_head;
	step = paths[path].path_size - 1; /* convert size to index */
	if (paths[path].path[step] != loop->head) {
		debug_print(DEBUG_ANALYSE, 1, "merge_path failed path 0x%x != head 0x%x\n", paths[path].path[step], loop->head);
		exit(1);
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
				debug_print(DEBUG_ANALYSE, 1, "No loop\n");
				return 0;
			}
		}
		found = 0;
		for (n = 0; n  < loop->size; n++) {
			if (list[n] == paths[path].path[step]) {
				found = 1;
				break;	
			}
		}
		if (!found) {
			debug_print(DEBUG_ANALYSE, 1, "Merge: adding 0x%x\n",  paths[path].path[step]);
			tmp = paths[path].path[step];
			list[loop->size] = tmp;
			loop->size++;
		}

		if (paths[path].path[step] == loop->head) {
			debug_print(DEBUG_ANALYSE, 1, "Start of merge Loop found\n");
			break;
		}
	}
	debug_print(DEBUG_ANALYSE, 1, "merged head = 0x%x, size = 0x%x\n", loop->head, loop->size);
	return 0;
}


/* This is used to merge all the nodes of a loop with a particular loop_head */
/* It is then used to detect which node prev/next links exit the loop */
/* Work then then be done to scan the loops, and if only one loop_head exists in the loop, it is a single loop. */
/* If more than one loop_head exists in the loop, then it is a nested loop, or a disjointed loop */

int build_control_flow_loops(struct self_s *self, struct path_s *paths, int *paths_size, struct loop_s *loops, int *loop_size)
{
	int n;
	int m;
	int found;
	struct loop_s *loop;
	int tmp;

	/* Build loops table */
	for (n = 0; n < *paths_size; n++) {
		if (paths[n].loop_head != 0) {
			found = -1;
			for(m = 0; m < *loop_size; m++) {
				if (loops[m].head == paths[n].loop_head) {
					found = m;
					debug_print(DEBUG_ANALYSE, 1, "flow_loops found = %d\n", found);
					break;
				}
			}
			if (found == -1) {
				for(m = 0; m < *loop_size; m++) {
					if (loops[m].head == 0) {
						found = m;
						debug_print(DEBUG_ANALYSE, 1, "flow_loops2 found = %d\n", found);
						break;
					}
				}
			}
			if (found == -1) {
				debug_print(DEBUG_ANALYSE, 1, "build_control_flow_loops problem\n");
				exit(1);
			}
			if (found >= *loop_size) {
				debug_print(DEBUG_ANALYSE, 1, "build_control_flow_loops problem2\n");
				exit(1);
			}
			loop = &loops[found];
			merge_path_into_loop(paths, loop, n);
		}
	}
	/* Add nesting information to loops */
	for (n = 0; n < *paths_size; n++) {
		if (paths[n].loop_head != 0) {
			found = -1;
			for(m = 0; m < *loop_size; m++) {
				if (loops[m].head == paths[n].loop_head) {
					found = m;
					debug_print(DEBUG_ANALYSE, 1, "flow_loops2 found = %d\n", found);
					break;
				}
			}
			if (found == -1) {
				debug_print(DEBUG_ANALYSE, 1, "loop nesting failed\n");
				return 1;
			}
			tmp = paths[n].path_prev;
			if (paths[tmp].loop_head != 0) {
				debug_print(DEBUG_ANALYSE, 1, "flow_loops2 path %d nesting %d in %d:%d\n", n, m, tmp, paths[tmp].loop_head);
				loops[m].nest = paths[tmp].loop_head;
			}
		}
	}
#if 0
	for(m = 0; m < *loop_size; m++) {
		if (loops[m].size) {
			debug_print(DEBUG_ANALYSE, 1, "flow_loops2 loop:%d head=%d nest=%d size=%d\n", m, loops[m].head, loops[m].nest, loops[m].size);
		}
	}
#endif
	return 0;
}

int build_control_flow_loops_multi_exit(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size, struct loop_s *loops, int loops_size)
{
	int l;
	int n;
	int m;
	int multi_exit;
	int node;
	/* Detect multi_exit loops */
	for (m = 0; m < loops_size; m++) {
		multi_exit = 0;
		if (loops[m].size > 0) {
			for (n = 0; n < loops[m].size; n++) {
				node = loops[m].list[n];
				debug_print(DEBUG_ANALYSE, 1, "multi_exit: node=0x%x\n", node);
				for (l = 0; l < nodes[node].next_size; l++) {
					if (nodes[node].link_next[l].is_loop_exit) {
						debug_print(DEBUG_ANALYSE, 1, "multi_exit: exit found\n");
						multi_exit++;
					}
				}
			}
		}
		loops[m].multi_exit = multi_exit;
		nodes[loops[m].head].multi_exit = multi_exit;
	}
	return 0;
}

int build_control_flow_loops_node_members(struct self_s *self,
	struct control_flow_node_s *nodes, int *nodes_size,
	struct loop_s *loops, int *loops_size)
{
	int n, m;
	int node;
	int head;
	int size;

	for (m = 0; m < *loops_size; m++) {
		if (loops[m].size > 0) {
			for (n = 0; n < loops[m].size; n++) {
				node = loops[m].list[n];
				head = loops[m].head;
				size = nodes[node].member_of_loop_size;
				size++;
				nodes[node].member_of_loop = realloc(nodes[node].member_of_loop, size * sizeof(int));
				nodes[node].member_of_loop[size - 1] = head;
				nodes[node].member_of_loop_size = size;
			}
		}
	}
	return 0;
}

int print_control_flow_loops(struct self_s *self, struct loop_s *loops, int *loops_size)
{
	int n, m;

	debug_print(DEBUG_ANALYSE, 1, "Printing loops size = %d\n", *loops_size);
	for (m = 0; m < *loops_size; m++) {
		if (loops[m].size > 0) {
			debug_print(DEBUG_ANALYSE, 1, "Loop %d: loop_head=%d, nest=%d, multi_exit=%d\n", m, loops[m].head, loops[m].nest, loops[m].multi_exit);
			for (n = 0; n < loops[m].size; n++) {
				debug_print(DEBUG_ANALYSE, 1, "Loop %d=0x%x\n", m, loops[m].list[n]);
			}
		}
	}
	return 0;
}

int add_path_to_node(struct control_flow_node_s *node, int path)
{
	int size;
	int n;

	size = node->path_size;
	/* Don't add path twice */
	if (size > 0) {
		for (n = 0; n < size; n++) {
			if (node->path[n] == path) {
				return 1;
			}
		}
	}

	size++;
	node->path = realloc(node->path, size * sizeof(int));
	node->path[size - 1] = path;
	node->path_size = size;

	return 0;
}

int add_looped_path_to_node(struct control_flow_node_s *node, int path)
{
	int size;
	int n;

	size = node->looped_path_size;
	/* Don't add path twice */
	if (size > 0) {
		for (n = 0; n < size; n++) {
			if (node->looped_path[n] == path) {
				return 1;
			}
		}
	}

	size++;
	node->looped_path = realloc(node->looped_path, size * sizeof(int));
	node->looped_path[size - 1] = path;
	node->looped_path_size = size;

	return 0;
}


/* Is "a" a subset of "b" */
/* Are all the elements of "a" contained in "b" ? */
/* 0 = No */
/* 1 = Exact */
/* 2 = subset */
int is_subset(int size_a, int *a, int size_b, int *b)
{
	int tmp;
	int result = 0;
	int n,m;
	int found = 0;

	/* Optimisation 1 */
	if (size_b < size_a) {
		goto is_subset_exit;
	}
	/* Optimisation 2 */
	if (size_b == size_a) {
		tmp = memcmp(a , b, size_a * sizeof(int));
		if (!tmp) {
			result = 1;
			goto is_subset_exit;
		}
	}
	/* Handle the case of size_b > size_a */
	for (n = 0; n < size_a; n++) {
		found = 0;
		for (m = n; m < size_b; m++) {
			if (a[n] == b[m]) {
				found = 1;
				break;
			}
		}
		if (!found) {
			goto is_subset_exit;
		}
	}
	result = 2;

is_subset_exit:
	return result;
}

int build_node_dominance(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size)
{
	int n,m;
	int node_b = 1;
	int tmp;
	//int type;

	for(n = 1; n <= *nodes_size; n++) {
		node_b = n;
		while (node_b != 0) {
			tmp = 0;
			/* avoid following loop edge ones */
			for (m = 0; m < nodes[node_b].prev_size; m++) {
				int prev_node;
				int prev_link_index;

				prev_node = nodes[node_b].prev_node[m];
				if (!prev_node) {
					continue;
				}
				prev_link_index = nodes[node_b].prev_link_index[m];
				//debug_print(DEBUG_ANALYSE, 1, "dom: prev_node = 0x%x, prev_link_index = 0x%x\n", prev_node, prev_link_index);
				if (!(nodes[prev_node].link_next[prev_link_index].is_loop_edge)) {
					tmp = prev_node;
					break;
				}
			}
			node_b = tmp;
			if (0 == node_b) {
				break;
			}
			tmp = is_subset(nodes[n].path_size, nodes[n].path, nodes[node_b].path_size, nodes[node_b].path);
			//debug_print(DEBUG_ANALYSE, 1, "node_dominance: %d = 0x%x, 0x%x\n", tmp, n, node_b);
			if (tmp) {
				nodes[n].dominator = node_b;
				break;
			}
		}
	}
	return 0;
}

int build_node_type(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size)
{
	int n;
	int tmp;
	int count = 0;
	int type = 0;

	for(n = 1; n <= *nodes_size; n++) {
		type = 0;
		/* Check that it is a branch statement */
		if (2 != nodes[n].next_size) {
			if (nodes[n].next_size > 2) {
				/* FIXME: need to get this better. Check for JMPT instruction */
				type = NODE_TYPE_JMPT;
				goto build_node_type_found;
			} else {
				continue;
			}
		}
		/* A loop_head statement */
		if (nodes[n].loop_head) {
			if (nodes[n].link_next[0].is_loop_exit == 1) {
				type = NODE_TYPE_LOOP;
			} else if (nodes[n].link_next[1].is_loop_exit == 1) {
				type = NODE_TYPE_LOOP;
			} else if ((nodes[n].link_next[0].is_normal == 1) &&
					(nodes[n].link_next[1].is_normal == 1)) {
				/* Loop head with both links of type is_normal */
				type = NODE_TYPE_LOOP_THEN_ELSE;
			}
		} else {
			/* Control flow within a loop */
			if (nodes[n].link_next[0].is_loop_exit == 1) {
				type = NODE_TYPE_IF_THEN_GOTO;
			} else if (nodes[n].link_next[1].is_loop_exit == 1) {
				type = NODE_TYPE_IF_THEN_GOTO;
			} else if ((nodes[n].link_next[0].is_normal == 1) &&
					(nodes[n].link_next[1].is_normal == 1)) {
				/* A normal IF statement */
				type = NODE_TYPE_IF_THEN_ELSE;
			}
		}
		if (!type) {
			continue;
		}
build_node_type_found:
		nodes[n].type = type;
		debug_print(DEBUG_ANALYSE, 1, "node_type: node = 0x%x, type = 0x%x\n", n, nodes[n].type);
	}
	return 0;
}

/* find the position of a node in a base path */
/* negative results imply that the node is found in a parent path */
/* returns the "index" */
int find_node_in_path(struct self_s *self, struct path_s *paths, int paths_size, int base_path, int node, int *index)
{
	int position;
	int position_in_path;
	int path;
	int n;
	int step;
	int found = 0;
	int tmp;

	step = paths[base_path].path_size; /* convert size to index */
	position = step;
	path = base_path;
	while (1) {
		step--;
		position--;
		if (step < 0) {
			/* If path_prev == path, we have reached the beginning of the path list */
			if (paths[path].path_prev != path) {
				tmp = paths[path].path_prev;
				step = paths[path].path_prev_index;
				path = tmp;
			} else {
				found = 0;
				break;
			}
		}
		if (node == paths[path].path[step]) {
			found = 1;
			break;	
		}
	}
	if (found) {
		debug_print(DEBUG_ANALYSE, 1, "found node_in_path base_path = 0x%X, node = 0x%x, path = 0x%x step = 0x%x, position = 0x%x\n",
			base_path, node, path, step, position);
		*index = position;
		return 0;
	} else {
		debug_print(DEBUG_ANALYSE, 1, "not found node_in_path\n");
		return 1;
	}
}

/* Returns the "node" */
int find_node_at_index_in_path(struct self_s *self, struct path_s *paths, int paths_size, int base_path, int index, int *node)
{
	int position;
	int position_in_path;
	int path;
	int n;
	int step;
	int found = 0;
	int tmp;

	step = paths[base_path].path_size; /* convert size to index */
	position = step;
	path = base_path;
	/* FIXME: This can be optimised */
	while (1) {
		step--;
		position--;
		if (step < 0) {
			/* If path_prev == path, we have reached the beginning of the path list */
			if (paths[path].path_prev != path) {
				tmp = paths[path].path_prev;
				step = paths[path].path_prev_index;
				path = tmp;
			} else {
				found = 0;
				break;
			}
		}
		if (position == index) {
			found = 1;
			break;	
		}
	}
	if (found) {
		*node = paths[path].path[step];
		debug_print(DEBUG_ANALYSE, 1, "found node_at_index base_path = 0x%X, node = 0x%x, path = 0x%x step = 0x%x, position = 0x%x\n",
			base_path, *node, path, step, position);
		return 0;
	} else {
		debug_print(DEBUG_ANALYSE, 1, "not found node_at_index\n");
		return 1;
	}
	return 0;
}

int build_node_if_tail(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size)
{
	int n,m;
	int node_b = 1;
	int tmp;
	int count = 0;
	// int m;
	int subset_method = 0;
	int type = 0;
	int branch_follow_exit = 0;
	int follow_path = 0;
	int start_node;
	struct path_s *paths;
	int paths_size;
	int loops_size;
	struct loop_s *loops;

	for(n = 1; n <= *nodes_size; n++) {
		start_node = n;
		if (!nodes[start_node].valid) {
			continue;
		}
		type = nodes[n].type;
		//debug_print(DEBUG_ANALYSE, 1, "%s: start_node = 0x%x, nodes[start_node].entry_point = 0x%x\n", __FUNCTION__, start_node, nodes[start_node].entry_point);
		paths_size = self->external_entry_points[nodes[start_node].entry_point - 1].paths_size;
		paths = self->external_entry_points[nodes[start_node].entry_point - 1].paths;
		loops_size = self->external_entry_points[nodes[start_node].entry_point - 1].loops_size;
		loops = self->external_entry_points[nodes[start_node].entry_point - 1].loops;
		/* Check that it is a branch statement */
		if (2 > nodes[n].next_size) {
			continue;
		}
		debug_print(DEBUG_ANALYSE_PATHS, 1, "if_tail: start_node = 0x%x, type = 0x%x\n", start_node, nodes[start_node].type);
		switch (nodes[n].type) {
		case NODE_TYPE_IF_THEN_ELSE:
			/* A normal IF statement */
			if (nodes[n].path_size >= 2) {
				subset_method = 0; /* paths */
				branch_follow_exit = 0;  /* 0 = non-exit link, 1 = exit_links */
				follow_path = 1;
			} else {
				subset_method = 1; /* loops */
				branch_follow_exit = 0;  /* 0 = non-exit link, 1 = exit_links */
				follow_path = 1;
			}
			break;
		case NODE_TYPE_JMPT:
			/* A normal IF statement */
			if (nodes[n].path_size >= 2) {
				subset_method = 0; /* paths */
				branch_follow_exit = 0;  /* 0 = non-exit link, 1 = exit_links */
				follow_path = 1;
			} else {
				subset_method = 1; /* loops */
				branch_follow_exit = 0;  /* 0 = non-exit link, 1 = exit_links */
				follow_path = 1;
			}
			break;
		case NODE_TYPE_IF_THEN_GOTO:
			/* Control flow within a loop */
			subset_method = 0; /* paths */
			branch_follow_exit = 1;  /* 0 = non-exit link, 1 = exit_links */
			follow_path = 0;
			break;
		case NODE_TYPE_LOOP:
			/* A loop_head statement */
			if (nodes[n].multi_exit > 1) {
				subset_method = 0; /* paths */
				branch_follow_exit = 0;  /* 0 = non-exit link, 1 = exit_links */
				follow_path = 1;
			} else {
				subset_method = 0; /* paths */
				branch_follow_exit = 1;  /* 0 = non-exit link, 1 = exit_links */
				follow_path = 0;
			}
			break;
		case NODE_TYPE_LOOP_THEN_ELSE:
			/* Loop head with both links of type is_normal */
			if (nodes[n].multi_exit > 1) {
				subset_method = 0; /* paths */
				branch_follow_exit = 0;  /* 0 = non-exit link, 1 = exit_links */
				follow_path = 1;
			} else {
				subset_method = 1; /* loops */
				branch_follow_exit = 0;  /* 0 = non-exit link, 1 = exit_links */
				follow_path = 0;
			}
			break;
		default:
			debug_print(DEBUG_ANALYSE_PATHS, 1, "if_tail node type 0x%x unknown\n", nodes[n].type);
			exit(1);
		}

		debug_print(DEBUG_ANALYSE_PATHS, 1, "if_tail: subset_method = 0x%x, branch_follow_exit = 0x%x, follow_path = 0x%x\n",
			subset_method, branch_follow_exit, follow_path);
		node_b = n;
		while ((node_b != 0) ) {
			struct node_link_s *link;
			struct node_link_s *link_exit;

			tmp = 0;
			if (follow_path && !subset_method) {
				int path;
				int index;
				int next_node;

				if (nodes[start_node].path_size >= 2) {
					path = nodes[start_node].path[0];
					debug_print(DEBUG_ANALYSE_PATHS, 1, "Folling path 0x%x, size 0x%x, looking for node 0x%x\n", path, paths[path].path_size, node_b);
					tmp = find_node_in_path(self, paths, paths_size, path, node_b, &index);
					debug_print(DEBUG_ANALYSE_PATHS, 1, "find_node_in_path=%d, index=%d\n", tmp, index);
					tmp = find_node_at_index_in_path(self, paths, paths_size, path, index + 1, &next_node);
					debug_print(DEBUG_ANALYSE_PATHS, 1, "find_node_in_path next_node = 0x%x\n", next_node);
					if (!tmp) {
						tmp = next_node;
					} else {
						tmp = 0;
					}
				} else if (nodes[start_node].path_size == 1) {
					path = nodes[start_node].path[0];
					debug_print(DEBUG_ANALYSE_PATHS, 1, "Folling path 0x%x, size 0x%x, looking for node 0x%x\n", path, paths[path].path_size, node_b);
					tmp = find_node_in_path(self, paths, paths_size, path, node_b, &index);
					debug_print(DEBUG_ANALYSE_PATHS, 1, "find_node_in_path=%d, index=%d\n", tmp, index);
					tmp = find_node_at_index_in_path(self, paths, paths_size, path, index + 1, &next_node);
					debug_print(DEBUG_ANALYSE_PATHS, 1, "find_node_in_path next_node = 0x%x\n", next_node);
					if (!tmp) {
						tmp = next_node;
					} else {
						tmp = 0;
					}
				} else {
					debug_print(DEBUG_ANALYSE_PATHS, 1, "follow path failed1 path_size = 0x%x\n", nodes[start_node].path_size);
					exit(1);
				}
			} else if (follow_path && subset_method) {
				int path;

				debug_print(DEBUG_ANALYSE_PATHS, 1, "follow if...then...else in loop. looped_path_size = 0x%x\n",
					nodes[start_node].looped_path_size);
				if (nodes[start_node].looped_path_size >= 2) {
					path = nodes[start_node].looped_path[0];
					for (m = 0; m < paths[path].path_size; m++) {
						debug_print(DEBUG_ANALYSE_PATHS, 1, "node_b = 0x%x, looped_path = 0x%x, m = 0x%x\n",
							node_b, path, m);
						if (paths[path].path[m] == node_b) {
							if ((m + 1) < paths[path].path_size) {
								tmp = paths[path].path[m + 1];
								debug_print(DEBUG_ANALYSE_PATHS, 1, "follow path next = 0x%x\n", tmp);
								break;
							} else {
								debug_print(DEBUG_ANALYSE_PATHS, 1, "follow path failed2/n");
								exit(1);
							}
						}
					}
				} else {
					debug_print(DEBUG_ANALYSE_PATHS, 1, "follow path failed3 path_size = 0x%x\n", nodes[start_node].path_size);
					exit(1);
				}
			} else {
				if (nodes[node_b].next_size == 0) {
					debug_print(DEBUG_ANALYSE_PATHS, 1, "if_tail: end of function()\n");
					break;
				} else if (nodes[node_b].next_size == 1) {
					link = &(nodes[node_b].link_next[0]);
					if (link->is_loop_edge) {
						debug_print(DEBUG_ANALYSE_PATHS, 1, "if_tail: not following loop edge\n");
						break;
					}
				} else if (nodes[node_b].next_size == 2) {
				/* FIXME: preferred is only valid the first time round the loop */
				/* FIXME: what to do if the node is a loop edge and no other links */
					link_exit = NULL;
					if (nodes[node_b].link_next[0].is_loop_exit == 1) {
						link_exit = &(nodes[node_b].link_next[0]);
					} else if (nodes[node_b].link_next[1].is_loop_exit == 1) {
						link_exit = &(nodes[node_b].link_next[1]);
					} if ((nodes[node_b].link_next[0].is_loop_exit == 1) &&
						(nodes[node_b].link_next[1].is_loop_exit == 1)) {
						break;
					}

					link = NULL;
					if (nodes[node_b].link_next[0].is_normal == 1) {
						link = &(nodes[node_b].link_next[0]);
					} else if (nodes[node_b].link_next[1].is_normal == 1) {
						link = &(nodes[node_b].link_next[1]);
					}
					if (link) debug_print(DEBUG_ANALYSE_PATHS, 1, "link node = 0x%x\n", link->node);
					if (link_exit) debug_print(DEBUG_ANALYSE_PATHS, 1, "link_exit node = 0x%x\n", link_exit->node);
					if (branch_follow_exit) {
						link = link_exit;
					}
					if (!link) {
						debug_print(DEBUG_ANALYSE_PATHS, 1, "node_if_tail: empty link\n");
						break;
					}
					/* Do not follow loop edges */
					if (link->is_loop_edge) {
						break;
					}
					debug_print(DEBUG_ANALYSE_PATHS, 1, "node = 0x%x, is_norm = %d, is_loop_edge = %d, is_loop_exit = %d, is_loop_entry = %d\n",
						node_b, link->is_normal, link->is_loop_edge, link->is_loop_exit, link->is_loop_entry);
					tmp = link->node;
				}
			}
			debug_print(DEBUG_ANALYSE_PATHS, 1, "next node=0x%x\n", tmp);

			node_b = tmp;
			if (0 == node_b) {
				break;
			}
			if (subset_method == 0) {
				tmp = is_subset(nodes[start_node].path_size, nodes[start_node].path, nodes[node_b].path_size, nodes[node_b].path);
			} else {
				tmp = is_subset(nodes[start_node].looped_path_size, nodes[start_node].looped_path, nodes[node_b].looped_path_size, nodes[node_b].looped_path);
			}
			debug_print(DEBUG_ANALYSE_PATHS, 1, "node_if_tail: %d = 0x%x, 0x%x\n", tmp, start_node, node_b);
			count++;
			if (count > 1000) {
				debug_print(DEBUG_ANALYSE_PATHS, 1, "node_if_tail: failed, too many if_tails\n");
				debug_print(DEBUG_ANALYSE_PATHS, 1, "Start node: 0x%x is_norm = %d, is_loop_edge = %d is_loop_exit = %d is_loop_entry = %d\n",
					n, link->is_normal, link->is_loop_edge, link->is_loop_exit, link->is_loop_entry);
				exit(1);
			}
			if (tmp) {
				nodes[n].if_tail = node_b;
				break;
			}
		}
		debug_print(DEBUG_ANALYSE_PATHS, 1, "if_tail:function end\n");
	}
	debug_print(DEBUG_ANALYSE_PATHS, 1, "if_tail:end\n");
	return 0;
}


int build_node_paths(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, struct path_s *paths, int *paths_size, int entry_point)

{
	int l;
	int path;
	int offset;

	debug_print(DEBUG_ANALYSE_PATHS, 1, "paths_size = %d\n", *paths_size);
	for (l = 0; l < *paths_size; l++) {
		path = l;
		offset = paths[l].path_size - 1;
		if (paths[l].path_size > 0) {
			while (1) {
				//debug_print(DEBUG_ANALYSE, 1, "Path=0x%x, offset=%d, Node=0x%x\n", l, offset, paths[path].path[offset]);
				if (paths[l].type == PATH_TYPE_LOOP) {
					add_looped_path_to_node(&(nodes[paths[path].path[offset]]), l);
				} else {
					add_path_to_node(&(nodes[paths[path].path[offset]]), l);
				}
				nodes[paths[path].path[offset]].entry_point = entry_point;
				offset--;
				if (offset < 0) {
					offset = paths[path].path_prev_index;
					if (path == paths[path].path_prev) {
						break;
					}
					path = paths[path].path_prev;
				}
			};
		}

	}
	return 0;
}

int build_control_flow_paths(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size, struct path_s *paths, int *paths_size, int *paths_used, int node_start)
{
	struct node_mid_start_s *node_mid_start;
	int found = 0;
	int path = 0;
	int step = 0;
	int n;
	//int l;
	//int m;
	int node = 1;
	int tmp;
	int loop = 0;

	node_mid_start = calloc(1000, sizeof(struct node_mid_start_s));

	node_mid_start[0].node = node_start;
	node_mid_start[0].path_prev = 0;
	node_mid_start[0].path_prev_index = 0;

	do {
		found = 0;
		for (n = 0; n < 1000; n++) {
			if (node_mid_start[n].node != 0) {
				found = 1;
				break;
			}
		}
		if (found == 1) {
			step = 0;
			node = node_mid_start[n].node;
			paths[path].used = 1;
			paths[path].path[step] = node;
			paths[path].path_prev = node_mid_start[n].path_prev;
			paths[path].path_prev_index = node_mid_start[n].path_prev_index;
			debug_print(DEBUG_ANALYSE_PATHS, 1, "JCD1: path 0x%x:0x%x, 0x%x\n", path, step, node_mid_start[n].node);
			node_mid_start[n].node = 0;
			step++;
			loop = 0;
			do {
				loop = path_loop_check(paths, path, step - 1, node, *nodes_size);

				if (loop) {
					debug_print(DEBUG_ANALYSE_PATHS, 1, "JCD0: path = 0x%x, step = 0x%x, node = 0x%x, loop = %d\n", path, step, node, loop);
					paths[path].loop_head = node;
					nodes[node].type = NODE_TYPE_LOOP;
					nodes[node].loop_head = 1;
					/* Loops with more than one block */
					if (step >= 2) {
						int node1 = paths[path].path[step - 2];
						int node2 = paths[path].path[step - 1];
						debug_print(DEBUG_ANALYSE_PATHS, 1, "JCD4:loop: 0x%x, 0x%x\n", paths[path].path[step - 2], paths[path].path[step - 1]);
						for (n = 0; n < nodes[node1].next_size; n++) {
							if (nodes[node1].link_next[n].node == node2) {
								nodes[node1].link_next[n].is_loop_edge = 1;
							}
						}
					} else {
						debug_print(DEBUG_ANALYSE_PATHS, 1, "JCD1: testing for do while loop on node = 0x%x, step = 0x%x, path=0x%x\n",
							node, step, path);
						paths[path].loop_head = node;
						nodes[node].type = NODE_TYPE_LOOP;
						nodes[node].loop_head = 1;
						for (n = 0; n < nodes[node].next_size; n++) {
							if (nodes[node].link_next[n].node == node) {
								nodes[node].link_next[n].is_loop_edge = 1;
							}
						}
						if (path) {
							int node1 = paths[paths[path].path_prev].path[paths[path].path_prev_index];
							int node2 = node;

							for (n = 0; n < nodes[node1].next_size; n++) {
								if (nodes[node1].link_next[n].node == node2) {
									nodes[node1].link_next[n].is_loop_edge = 1;
								}
							}
						}
						break;
					}
				} else if (nodes[node].next_size == 1) {
					debug_print(DEBUG_ANALYSE_PATHS, 1, "JCD2: path 0x%x:0x%x, 0x%x -> 0x%x\n", path, step, node, nodes[node].link_next[0].node);
					node = nodes[node].link_next[0].node;
					paths[path].path[step] = node;
					step++;
				} else if (nodes[node].next_size > 1) {
					tmp = node_mid_start_add(&nodes[node], node_mid_start, path, step - 1);
					debug_print(DEBUG_ANALYSE_PATHS, 1, "JCD3: path 0x%x:0x%x, 0x%x -> 0x%x\n", path, step, node, nodes[node].link_next[0].node);
					node = nodes[node].link_next[0].node;
					paths[path].path[step] = node;
					step++;
				}
			} while ((nodes[node].next_size > 0) && (loop == 0));
			paths[path].path_size = step;
			path++;
			debug_print(DEBUG_ANALYSE_PATHS, 1, "end path = 0x%x\n", path);
			if (path >= *paths_size) {
				debug_print(DEBUG_ANALYSE_PATHS, 1, "TOO MANY PATHS, %d\n", path);
				return 1;
			}
		}
	} while (found == 1);
	free (node_mid_start);
	*paths_used = path;
	return 0;
}

int build_control_flow_depth(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size, struct path_s *paths, int *paths_size, int *paths_used, int node_start)
{
	int n, m;
	int node;
	int depth;
	
	node = paths[0].path[0];
	nodes[node].depth = 1;
	

	for (m = 0; m < *paths_size; m++) {
		if (paths[m].used && (paths[m].type != 1)) {
			if (m == 0) {
				depth = 1;
			} else {
				node = paths[paths[m].path_prev].path[paths[m].path_prev_index];
				depth = nodes[node].depth + 1;
			}
			for (n = 0; n < paths[m].path_size; n++) {
				node = paths[m].path[n];
				if (nodes[node].depth < depth) {
					nodes[node].depth = depth;
					depth++;
				} else {
					depth = nodes[node].depth + 1;
				}
			}
		}
	}
	return 0;
}	


int print_control_flow_paths(struct self_s *self, struct path_s *paths, int *paths_size)
{
	int n, m;
	debug_print(DEBUG_ANALYSE_PATHS, 1, "print control flow paths size=0x%x\n", *paths_size);
	for (m = 0; m < *paths_size; m++) {
		if (paths[m].used) {
			debug_print(DEBUG_ANALYSE_PATHS, 1, "Path 0x%x: type=%d, loop_head=0x%x, prev 0x%x:0x%x\n", m, paths[m].type, paths[m].loop_head, paths[m].path_prev, paths[m].path_prev_index);
			for (n = 0; n < paths[m].path_size; n++) {
				debug_print(DEBUG_ANALYSE_PATHS, 1, "Path 0x%x=0x%x\n", m, paths[m].path[n]);
			}
//		} else {
			//debug_print(DEBUG_ANALYSE, 1, "Un-used Path 0x%x: type=%d, loop_head=0x%x, prev 0x%x:0x%x\n", m, paths[m].type, paths[m].loop_head, paths[m].path_prev, paths[m].path_prev_index);
		}

	}
	return 0;
}

int build_control_flow_nodes(struct self_s *self, struct control_flow_node_s *nodes, int *node_size)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log2;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	int node = 1;
	int inst_start = 1;
	int inst_end;
	int n;
	int m;
	int l;
	int tmp;

	debug_print(DEBUG_ANALYSE, 1, "build_control_flow_nodes:\n");	
	//inst_log_entry[inst_start].node_start = 1;
	debug_print(DEBUG_ANALYSE, 1, "f_node_start = inst 0x%x\n", inst_start);	
	/* Start by scanning all the inst_log for node_start and node_end. */
	for (n = 1; n < inst_log; n++) {
		inst_log1 = &inst_log_entry[n];
		debug_print(DEBUG_ANALYSE, 1, "inst 0x%x prev_size = %d, next_size = %d\n", n, inst_log1->prev_size, inst_log1->next_size);	
		if (inst_log1->prev_size > 0) {
			debug_print(DEBUG_ANALYSE, 1, "inst 0x%x prev = 0x%x\n", n, inst_log1->prev[0]);
		}
		if (inst_log1->next_size > 0) {
			debug_print(DEBUG_ANALYSE, 1, "inst 0x%x next = 0x%x\n", n, inst_log1->next[0]);
		}

		/* Test for end of node */
		if ((inst_log1->next_size > 1) ||
			(inst_log1->next_size == 0)) {
			inst_end = n;
			inst_log_entry[inst_end].node_end = 1;
			debug_print(DEBUG_ANALYSE, 1, "n_node_end = inst 0x%x\n", inst_end);	
			/* Handle special case of duplicate prev_inst */
			/* FIXME: Stop duplicate prev_inst being created in the first place */
			for (m = 0; m < inst_log1->next_size; m++) {
				/* Mark all the node_starts */
				inst_start = inst_log_entry[inst_end].next[m];
				inst_log_entry[inst_start].node_start = 1;
				debug_print(DEBUG_ANALYSE, 1, "n_node_start = inst 0x%x\n", inst_start);	
			}
		}
		if ((inst_log1->prev_size > 1) ||
			(inst_log1->prev_size == 0)) {
			inst_start = n;
			inst_log_entry[inst_start].node_start = 1;
			debug_print(DEBUG_ANALYSE, 1, "p_node_start = inst 0x%x\n", inst_start);	
			for (m = 0; m < inst_log1->prev_size; m++) {
				/* Mark all the node_starts */
				inst_end = inst_log_entry[inst_start].prev[m];
				inst_log_entry[inst_end].node_end = 1;
				debug_print(DEBUG_ANALYSE, 1, "p_node_end = inst 0x%x\n", inst_end);	
				if (inst_log_entry[inst_end].next_size == 1) {
					inst_log_entry[inst_log_entry[inst_end].next[0]].node_start = 1;
					debug_print(DEBUG_ANALYSE, 1, "p_node_start2 = inst 0x%x\n", inst_log_entry[inst_end].next[0]);	
				}
			}
			/* Handle special case of duplicate prev_inst */
			/* FIXME: Stop duplicate prev_inst being created in the first place */
		}
	}
	node = 1;
	for (n = 1; n < inst_log; n++) {
		inst_log1 = &inst_log_entry[n];
		if (inst_log1->node_start) {
			inst_start = n;
			inst_log1->node_member = node;
			if (!inst_log1->node_end) {
				do {
					tmp = inst_log1->next[0];
					inst_log1 = &inst_log_entry[tmp];
					inst_log1->node_member = node;
				} while (!(inst_log1->node_end));
				inst_end = tmp;
			} else {
				inst_end = n;
			}
			nodes[node].inst_start = inst_start;
			nodes[node].inst_end = inst_end;
			nodes[node].valid = 1;
			node++;
		}
	}
	*node_size = node - 1;

	/* Start by building the entire node table, with prev and next node. */
	for (n = 1; n <= *node_size; n++) {
		inst_log1 =  &inst_log_entry[nodes[n].inst_start];
		if (inst_log1->prev_size > 0) {
			nodes[n].prev_node = calloc(inst_log1->prev_size, sizeof(int));
			nodes[n].prev_link_index = calloc(inst_log1->prev_size, sizeof(int));
			nodes[n].prev_size = inst_log1->prev_size;

			for (m = 0; m < inst_log1->prev_size; m++) {
				tmp = find_node_from_inst(self, nodes, node_size, inst_log1->prev[m]);
				nodes[n].prev_node[m] = tmp;
			}
		}
		inst_log1 =  &inst_log_entry[nodes[n].inst_end];
		if (inst_log1->next_size > 0) {
			nodes[n].link_next = calloc(inst_log1->next_size, sizeof(struct node_link_s));
			nodes[n].next_size = inst_log1->next_size;
			if (nodes[n].next_size > 2) {
				debug_print(DEBUG_ANALYSE, 1, "build_cfg next_size, 0x%x, too big for node 0x%x, inst 0x%x. Might be a JMPT.\n", nodes[n].next_size, n, nodes[n].inst_end);
			}

			for (m = 0; m < inst_log1->next_size; m++) {
				tmp = find_node_from_inst(self, nodes, node_size, inst_log1->next[m]);
				nodes[n].link_next[m].node = tmp;
			}
		}
	}
	/* Once the full prev/next node table is completed,
	 * add in the prev_link_index.
	 * the prev_link_index can only be built once the prev/next node table is complete.
	 */
	for (n = 1; n <= *node_size; n++) {
		for (m = 0; m < nodes[n].next_size; m++) {
			tmp = nodes[n].link_next[m].node;
			for (l = 0; l < nodes[tmp].prev_size; l++) {
				if (nodes[tmp].prev_node[l] == n) {
					nodes[tmp].prev_link_index[l] = m;
					debug_print(DEBUG_ANALYSE, 1, "prev_link_index: 0x%x, 0x%x 0x%x\n",
						tmp, m, l);
				}
			}
		}
	}
	return 0;
}



int print_control_flow_nodes(struct self_s *self, struct control_flow_node_s *nodes, int *node_size)
{
	int n;
	int m;
	int prev_node;
	int prev_link_index;

	debug_print(DEBUG_ANALYSE, 1, "print_control_flow_nodes: size = %d\n", *node_size);	
	for (n = 1; n <= *node_size; n++) {
		debug_print(DEBUG_ANALYSE, 1, "Node:0x%x, valid=%d, type=%d, dominator=0x%x, if_tail=0x%x, loop_head=%d, inst_start=0x%x, inst_end=0x%x, entry_point=0x%x, multi_exit=0x%x, depth=0x%x\n",
			n,
			nodes[n].valid,
			nodes[n].type,
			nodes[n].dominator,
			nodes[n].if_tail,
			nodes[n].loop_head,
			nodes[n].inst_start,
			nodes[n].inst_end,
			nodes[n].entry_point,
			nodes[n].multi_exit,
			nodes[n].depth);
		for (m = 0; m < nodes[n].prev_size; m++) {
			prev_node = nodes[n].prev_node[m];
			prev_link_index = nodes[n].prev_link_index[m];
			/* make a special case for when prev_node == 0 */
			if (prev_node) {
				debug_print(DEBUG_ANALYSE, 1, "nodes[0x%x].prev_node[%d] = 0x%x, prev_link_index=0x%x norm=%d edge=%d exit=%d entry=%d\n",
					n, m, prev_node, prev_link_index,
					nodes[prev_node].link_next[prev_link_index].is_normal,
					nodes[prev_node].link_next[prev_link_index].is_loop_edge,
					nodes[prev_node].link_next[prev_link_index].is_loop_exit,
					nodes[prev_node].link_next[prev_link_index].is_loop_entry);
			} else {
				debug_print(DEBUG_ANALYSE, 1, "nodes[0x%x].prev_node[%d] = 0x%x, prev_link_index=0x%x\n",
					n, m, prev_node, prev_link_index);
			}
		}
		for (m = 0; m < nodes[n].next_size; m++) {
			debug_print(DEBUG_ANALYSE, 1, "nodes[0x%x].link_next[%d].node = 0x%x, next norm=%d edge=%d exit=%d entry=%d\n",
				n, m, nodes[n].link_next[m].node,
				nodes[n].link_next[m].is_normal,
				nodes[n].link_next[m].is_loop_edge,
				nodes[n].link_next[m].is_loop_exit,
				nodes[n].link_next[m].is_loop_entry);
		}
		if (nodes[n].next_size > 2) {
			/* FIXME: only an error so long as we are not yet supporting jump indexes. */
			debug_print(DEBUG_ANALYSE, 1, "Oversized node\n");
		}
		for (m = 0; m < nodes[n].member_of_loop_size; m++) {
			debug_print(DEBUG_ANALYSE, 1, "nodes[0x%x].member_of_loop[%d] = 0x%x\n", n, m, nodes[n].member_of_loop[m]);
		}
		debug_print(DEBUG_ANALYSE, 1, "nodes[0x%x].path_size = 0x%x\n", n, nodes[n].path_size);
		debug_print(DEBUG_ANALYSE, 1, "nodes[0x%x].looped_size = 0x%x\n", n, nodes[n].looped_path_size);
//		for (m = 0; m < nodes[n].path_size; m++) {
//			debug_print(DEBUG_ANALYSE, 1, "nodes[0x%x].path[%d] = 0x%x\n", n, m, nodes[n].path[m]);
//		}
//		for (m = 0; m < nodes[n].looped_path_size; m++) {
//			debug_print(DEBUG_ANALYSE, 1, "nodes[0x%x].looped_path[%d] = 0x%x\n", n, m, nodes[n].looped_path[m]);
//		}

	}
	return 0;
}

/* Try to identify the node link types for each node */
int analyse_control_flow_node_links(struct self_s *self, struct control_flow_node_s *nodes, int *node_size)
{
	int l, n;
	struct control_flow_node_s *node;
	struct control_flow_node_s *next_node;
	//int head;
	int next;
	//int type;
	//int found;
	int tmp;

	for (n = 1; n <= *node_size; n++) {
		node = &nodes[n];
		for (l = 0; l < node->next_size; l++) {
			tmp = node->link_next[l].is_loop_edge;
			if (tmp != 0) {
				/* Only modify when the type is undefined == 0 */
				continue;
			}
			//type = 0;
			next = node->link_next[l].node;
			next_node = &nodes[next];
			if (next_node->loop_head != 0) {
				/* Loop entry: If the next node is a loop_head */
				/* Add check for node member_of_loop subset, else NEXT_TYPE_LOOP_EXIT */
				node->link_next[l].is_loop_entry = 1;
			}
			/* Loop exit: If the next node is a member_of_loop subset of the existing node */
			/* But special case if at a loop_head node or a node that is a member of
			 * multiple loops. Need to identify a primary member_of_loop entry.
			 * The primary member_of_loop entry is the one that equals loop_head.
			 * Normal: If the next node is a member_of_loop identical to node */
			if (node->loop_head) {
				if ((next_node->member_of_loop_size == 1) &&
					(next_node->member_of_loop[0] == n)) {
					node->link_next[l].is_normal = 1;
				} else {
					node->link_next[l].is_loop_exit = 1;
				}
			} else {
				tmp = is_subset(next_node->member_of_loop_size, next_node->member_of_loop,
					 node->member_of_loop_size, node->member_of_loop);
				if (tmp == 2) { /* subset */
					node->link_next[l].is_loop_exit = 1;
				} else if (tmp == 1) { /* exactly the same */
					node->link_next[l].is_normal = 1;
				}
			}
		}
	}
	/* If is_loop_edge or is_loop_exit is set, reset is_normal to 0 */
	for (n = 1; n <= *node_size; n++) {
		node = &nodes[n];
		for (l = 0; l < node->next_size; l++) {
			int is_loop_edge; 
			int is_loop_exit; 
			int is_normal; 
			is_loop_edge = node->link_next[l].is_loop_edge;
			is_loop_exit = node->link_next[l].is_loop_exit;
			is_normal = node->link_next[l].is_normal;
			if ((is_loop_edge && is_normal) ||
				(is_loop_exit && is_normal)) {
				node->link_next[l].is_normal = 0;
			}
		}
	}
	/* If only is_loop_entry == 1, set is_normal to 1 */
	for (n = 1; n <= *node_size; n++) {
		node = &nodes[n];
		for (l = 0; l < node->next_size; l++) {
			int is_loop_edge; 
			int is_loop_exit; 
			int is_normal; 
			int is_loop_entry; 
			is_loop_edge = node->link_next[l].is_loop_edge;
			is_loop_exit = node->link_next[l].is_loop_exit;
			is_normal = node->link_next[l].is_normal;
			is_loop_entry = node->link_next[l].is_loop_entry;
			if (!is_loop_edge && !is_normal && !is_loop_exit) {
				node->link_next[l].is_normal = 1;
			}
		}
	}
	return 0;
}

int analyse_multi_ret(struct self_s *self, struct path_s *paths, int *paths_size, int *multi_ret_size, int **multi_ret)
{
	int n,m;
	int first_node = 0;
	int found;
	int *ret_list = NULL;
	int size = 0;

	for (n = 0; n < *paths_size; n++) {
		if ((paths[n].used == 1) && (!paths[n].loop_head)) {
			//debug_print(DEBUG_ANALYSE, 1, "multi_ret2: 0x%x: path_end = 0x%x\n", n, paths[n].path[paths[n].path_size - 1]);
			if (!first_node) {
				first_node = paths[n].path[paths[n].path_size - 1];
			} else {
				if (paths[n].path[paths[n].path_size - 1] != first_node) {
					//debug_print(DEBUG_ANALYSE, 1, "multi_ret: 0x%x: path_size = 0x%x, multi_ret_size = 0x%x\n",
					//	n, paths[n].path_size, size);
					//debug_print(DEBUG_ANALYSE, 1, "multi_ret: 0x%x: 0x%x 0x%x\n", n, first_node, paths[n].path[paths[n].path_size - 1]);
					found = 0;
					for (m = 0; m < size; m++) {
						//debug_print(DEBUG_ANALYSE, 1, "multi_ret3: 0x%x: path_end = 0x%x multi_ret = 0x%x\n", m, paths[n].path[paths[n].path_size - 1], ret_list[m]);
						if (paths[n].path[paths[n].path_size - 1] == ret_list[m]) {
							found = 1;
							break;
						}
					}
					if (found) {
						//debug_print(DEBUG_ANALYSE, 1, "found\n");
						continue;
					}	
					//debug_print(DEBUG_ANALYSE, 1, "multi_ret2: 0x%x: path_size = 0x%x\n", n, paths[n].path_size);
					//debug_print(DEBUG_ANALYSE, 1, "multi_ret2: 0x%x: 0x%x\n", n, paths[n].path[paths[n].path_size - 1]);
					if (size == 0) {
						ret_list = malloc(sizeof(int));
					} else {
						ret_list = realloc(ret_list, (size + 1) * sizeof(int));
					}
					ret_list[size] = paths[n].path[paths[n].path_size - 1];
					size++;
				}
			}
		}
	}
	if (size > 0) {
		ret_list = realloc(ret_list, (size + 1) * sizeof(int));
		ret_list[size] = first_node;
		size++;
	}
	*multi_ret_size = size;
	*multi_ret = ret_list;
	return 0;
}

int compare_inst(struct self_s *self, int inst_a, int inst_b) {
	struct inst_log_entry_s *inst_log_a;
	struct inst_log_entry_s *inst_log_b;
	struct instruction_s *instruction_a;
	struct instruction_s *instruction_b;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	int ret;

	instruction_a =  &(inst_log_entry[inst_a].instruction);
	instruction_b =  &(inst_log_entry[inst_b].instruction);
	ret = 0;
	if ((instruction_a->opcode == instruction_b->opcode) &&
		(instruction_a->flags == instruction_b->flags)) {
		if ((instruction_a->srcA.store == instruction_b->srcA.store) &&
			(instruction_a->srcA.relocated == instruction_b->srcA.relocated) &&
			(instruction_a->srcA.indirect == instruction_b->srcA.indirect) &&
			(instruction_a->srcA.indirect_size == instruction_b->srcA.indirect_size) &&
			(instruction_a->srcA.index == instruction_b->srcA.index) &&
			(instruction_a->srcA.value_size == instruction_b->srcA.value_size)) {
			if ((instruction_a->dstA.store == instruction_b->dstA.store) &&
				(instruction_a->dstA.relocated == instruction_b->dstA.relocated) &&
				(instruction_a->dstA.indirect == instruction_b->dstA.indirect) &&
				(instruction_a->dstA.indirect_size == instruction_b->dstA.indirect_size) &&
				(instruction_a->dstA.index == instruction_b->dstA.index) &&
				(instruction_a->dstA.value_size == instruction_b->dstA.value_size)) {
				ret = 1;
			} else {
				debug_print(DEBUG_ANALYSE, 1, "compare_inst: failed at dstA\n");
			}
		} else {
			debug_print(DEBUG_ANALYSE, 1, "compare_inst: failed at srcA\n");
		}
	} else {
		debug_print(DEBUG_ANALYSE, 1, "compare_inst: failed at opcode/flags\n");
	}
	return ret;
}

int analyse_merge_nodes(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, int node_a, int node_b) {
	int inst_a, inst_b;
	int offset;
	int ret;
	int n,m;
	int node_new = *node_size + 1;
	int new_inst_start;
	int node_a_size;
	int node_b_size;
	int tmp;

	debug_print(DEBUG_ANALYSE, 1, "merge_nodes:  node_a = 0x%x, node_b = 0x%x\n", node_a, node_b);
	node_a_size = nodes[node_a].inst_end - nodes[node_a].inst_start;
	node_b_size = nodes[node_b].inst_end - nodes[node_b].inst_start;
	if (node_a_size > node_b_size) {
		// Swap node_a and node_b
		tmp = node_a;
		node_a = node_b;
		node_b = tmp;
	}
	debug_print(DEBUG_ANALYSE, 1, "merge_nodes: last a is inst 0x%x\n", nodes[node_a].inst_end);
	debug_print(DEBUG_ANALYSE, 1, "merge_nodes: last b is inst 0x%x\n", nodes[node_b].inst_end);
	inst_a = nodes[node_a].inst_end;
	inst_b = nodes[node_b].inst_end;
	offset = inst_b - inst_a;
	for (n = inst_a; n >= nodes[node_a].inst_start; n--) {
		if (!compare_inst(self, n, n + offset)) {
			debug_print(DEBUG_ANALYSE, 1, "Merge0 compare failed at 0x%x\n", n);
			break;
		}
	}
	new_inst_start = n + 1;
	debug_print(DEBUG_ANALYSE, 1, "Merge inst_a 0x%x, n 0x%x, new_inst_start 0x%x, inst_start 0x%x\n", inst_a, n, new_inst_start, nodes[node_a].inst_start);
	if (n == inst_a) {
		debug_print(DEBUG_ANALYSE, 1, "Merge1 no match found\n");
		ret = 0;
	} else if (new_inst_start == nodes[node_a].inst_start) {
		if (node_a_size == node_b_size) {
			int size = nodes[node_a].prev_size;
			int size_node_b = nodes[node_b].prev_size;
			// node_a identical to node_b
			ret = 1;
			debug_print(DEBUG_ANALYSE, 1, "Merge2  inst_a = 0x%x, n = 0x%x\n", inst_a, n);
			debug_print(DEBUG_ANALYSE, 1, "Merge2  node_a = 0x%x, node_b = 0x%x\n", node_a, node_b);
			debug_print(DEBUG_ANALYSE, 1, "Merge2  node_a prev size = 0x%x, size_node_b prev = 0x%x\n", size, size_node_b);
			nodes[node_a].prev_node = realloc(nodes[node_a].prev_node, (size + size_node_b) * sizeof(int));
			nodes[node_a].prev_link_index = realloc(nodes[node_a].prev_link_index, (size + size_node_b) * sizeof(int));
			for (m = 0; m < size_node_b; m++) {
				int node_b_prev_node = nodes[node_b].prev_node[m];
				int node_b_prev_link_index = nodes[node_b].prev_link_index[m];
				nodes[node_a].prev_node[size + m] = node_b_prev_node;
				nodes[node_a].prev_link_index[size + m] = node_b_prev_link_index;
				nodes[node_b_prev_node].link_next[node_b_prev_link_index].node = node_a;
			}
			nodes[node_a].prev_size += size_node_b;
			/* Mark the node_b as un-used */
			nodes[node_b].inst_end = new_inst_start + offset - 1;
			nodes[node_b].prev_size = 0;
			nodes[node_b].valid = 0;
			free (nodes[node_b].prev_node);
			free (nodes[node_b].prev_link_index);
			free (nodes[node_b].link_next);
		} else {
			int size = nodes[node_a].prev_size;
			// Whole of node a contained in node b
			ret = 1;
			debug_print(DEBUG_ANALYSE, 1, "Merge3  inst_a = 0x%x, n = 0x%x\n", inst_a, n);
			nodes[node_a].prev_node = realloc(nodes[node_a].prev_node, (size + 1) * sizeof(int));
			nodes[node_a].prev_link_index = realloc(nodes[node_a].prev_link_index, (size + 1) * sizeof(int));
			nodes[node_a].prev_node[size] = node_b;
			nodes[node_a].prev_link_index[size] = 0;
			nodes[node_a].prev_size++;
			nodes[node_b].inst_end = new_inst_start + offset - 1;
			nodes[node_b].link_next = calloc(1, sizeof(struct node_link_s));
			nodes[node_b].next_size = 1;
			nodes[node_b].link_next[0].node = node_a;
		}
	} else {
		ret = 1;
		debug_print(DEBUG_ANALYSE, 1, "Merge4 inst_a = 0x%x, n = 0x%x\n", inst_a, n);
		// FIXME: Now create a new node, and merge node_a and node_b into it.
		//	This will create a single ret node for the function. 
		nodes[node_new].inst_start = new_inst_start;
		nodes[node_new].inst_end = inst_a;
		nodes[node_a].inst_end = new_inst_start - 1;
		nodes[node_b].inst_end = new_inst_start + offset - 1;
		nodes[node_new].prev_node = calloc(2, sizeof(int));
		nodes[node_new].prev_link_index = calloc(2, sizeof(int));
		nodes[node_new].prev_size = 2;
		nodes[node_new].prev_node[0] = node_a;
		nodes[node_new].prev_node[1] = node_b;
		nodes[node_new].prev_link_index[0] = 0;
		nodes[node_new].prev_link_index[1] = 0;
		nodes[node_new].valid = 1;
		nodes[node_a].link_next = calloc(1, sizeof(struct node_link_s));
		nodes[node_a].next_size = 1;
		nodes[node_a].link_next[0].node = node_new;
		nodes[node_b].link_next = calloc(1, sizeof(struct node_link_s));
		nodes[node_b].next_size = 1;
		nodes[node_b].link_next[0].node = node_new;
		
		(*node_size)++;
	}

	return ret;
}

int get_value_from_index(struct operand_s *operand, uint64_t *index)
{
	if (operand->indirect) {
		debug_print(DEBUG_ANALYSE, 1, " /%d%s[%s0x%"PRIx64"],",
			operand->value_size,
			indirect_table[operand->indirect],
			store_table[operand->store],
			operand->index);
	} else {
		debug_print(DEBUG_ANALYSE, 1, " /%d%s0x%"PRIx64",",
		operand->value_size,
		store_table[operand->store],
		operand->index);
	}
	return 1;
}

/************************************************************
 * This function uses information from instruction log entries
 * and creates labels.
 ************************************************************/
int log_to_label(int store, int indirect, uint64_t index, uint64_t relocated, uint64_t value_scope, uint64_t value_id, uint64_t indirect_offset_value, uint64_t indirect_value_id, struct label_s *label) {
	//int tmp;

	/* FIXME: May handle by using first switch as switch (indirect) */
	debug_print(DEBUG_ANALYSE, 1, "value in log_to_label: store=0x%x, indirect=0x%x, index=0x%"PRIx64", relocated = 0x%"PRIx64", scope = 0x%"PRIx64", id = 0x%"PRIx64", ind_off_value = 0x%"PRIx64", ind_val_id = 0x%"PRIx64"\n",
				store,
				indirect,
				index,
				relocated,
				value_scope,
				value_id,
				indirect_offset_value,
				indirect_value_id);


	switch (store) {
	case STORE_DIRECT:
		/* FIXME: Handle the case of an immediate value being &data */
		/* but it is very difficult to know if the value is a pointer (&data) */
		/* or an offset (data[x]) */
		/* need to use the relocation table to find out */
		/* no relocation table entry == offset */
		/* relocation table entry == pointer */
		/* this info should be gathered at disassembly point */
		/* FIXME: relocation table not present in 16bit x86 mode, so another method will need to be found */
		if (indirect == IND_MEM) {
			label->scope = 3;
			label->type = 1;
			label->lab_pointer = 1;
			label->value = index;
		} else if (relocated) {
			label->scope = 3;
			label->type = 2;
			label->lab_pointer = 0;
			label->value = index;
		} else {
			label->scope = 3;
			label->type = 3;
			label->lab_pointer = 0;
			label->value = index;
		}
		break;
	case STORE_REG:
		switch (value_scope) {
		case 1:
			/* params */
			if (IND_STACK == indirect) {
				label->scope = 2;
				label->type = 2;
				label->lab_pointer = 0;
				label->value = indirect_offset_value;
				debug_print(DEBUG_ANALYSE, 1, "PARAM_STACK^\n");
			} else if (0 == indirect) {
				label->scope = 2;
				label->type = 1;
				label->lab_pointer = 0;
				label->value = index;
				debug_print(DEBUG_ANALYSE, 1, "PARAM_REG^\n");
			} else {
				debug_print(DEBUG_ANALYSE, 1, "JCD: UNKNOWN PARAMS\n");
			}
			break;
		case 2:
			/* locals */
			if (IND_STACK == indirect) {
				label->scope = 1;
				label->type = 2;
				label->lab_pointer = 0;
				label->value = value_id;
			} else if (0 == indirect) {
				label->scope = 1;
				label->type = 1;
				label->lab_pointer = 0;
				label->value = value_id;
			} else {
				debug_print(DEBUG_ANALYSE, 1, "JCD: UNKNOWN LOCAL\n");
			}
			break;
		case 3: /* Data */
			/* FIXME: introduce indirect_value_id and indirect_value_scope */
			/* in order to resolve somewhere */
			/* It will always be a register, and therefore can re-use the */
			/* value_id to identify it. */
			/* It will always be a local and not a param */
			/* FIXME: This should be handled scope = 1, type = 1 above. */
			/* was scope = 4*/
			/* FIXME: get the label->value right */
			label->scope = 1;
			label->type = 1;
			label->lab_pointer = 1;
			label->value = indirect_value_id;
			break;
		default:
			label->scope = 0;
			label->type = value_scope;
			label->lab_pointer = 0;
			label->value = 0;
			debug_print(DEBUG_ANALYSE, 1, "unknown value scope: %04"PRIx64";\n", (value_scope));
			return 1;
			break;
		}
		break;
	default:
		debug_print(DEBUG_ANALYSE, 1, "Unhandled store1\n");
		return 1;
		break;
	}
	return 0;
}

int register_label(struct external_entry_point_s *entry_point, uint64_t value_id,
	struct memory_s *value, struct label_redirect_s *label_redirect, struct label_s *labels)
{
	int n;
	int found;
	struct label_s *label;
	int label_offset;
	label_offset = label_redirect[value_id].redirect;
	label = &labels[label_offset];
	label->size_bits = value->length * 8;
	debug_print(DEBUG_ANALYSE, 1, "Registering label: value_id = 0x%"PRIx64", scope 0x%"PRIx64", type 0x%"PRIx64", value 0x%"PRIx64", size 0x%"PRIx64", pointer 0x%"PRIx64", signed 0x%"PRIx64", unsigned 0x%"PRIx64"\n",
		value_id,
		label->scope,
		label->type,
		label->value,
		label->size_bits,
		label->lab_pointer,
		label->lab_signed,
		label->lab_unsigned);
	//int params_size;
	//int *params;
	//int *params_order;
	//int locals_size;
	//int *locals;
	//int *locals_order;
	found = 0;
	switch (label->scope) {
	case 2:
		debug_print(DEBUG_ANALYSE, 1, "PARAM\n");
		for(n = 0; n < entry_point->params_size; n++) {
			debug_print(DEBUG_ANALYSE, 1, "looping 0x%x\n", n);
			if (entry_point->params[n] == label_offset) {
				debug_print(DEBUG_ANALYSE, 1, "Duplicate\n");
				found = 1;
				break;
			}
		}
		if (found) {
			break;
		}
		(entry_point->params_size)++;
		entry_point->params = realloc(entry_point->params, entry_point->params_size * sizeof(int));
		entry_point->params[entry_point->params_size - 1] = label_offset;
		break;
	case 1:
		debug_print(DEBUG_ANALYSE, 1, "LOCAL\n");
		for(n = 0; n < entry_point->locals_size; n++) {
			debug_print(DEBUG_ANALYSE, 1, "looping 0x%x\n", n);
			if (entry_point->locals[n] == label_offset) {
				debug_print(DEBUG_ANALYSE, 1, "Duplicate\n");
				found = 1;
				break;
			}
		}
		if (found) {
			break;
		}
		(entry_point->locals_size)++;
		entry_point->locals = realloc(entry_point->locals, entry_point->locals_size * sizeof(int));
		entry_point->locals[entry_point->locals_size - 1] = label_offset;
		break;
	case 3:
		debug_print(DEBUG_ANALYSE, 1, "HEX VALUE\n");
		break;
	default:
		debug_print(DEBUG_ANALYSE, 1, "VALUE unhandled 0x%"PRIx64"\n", label->scope);
		break;
	}
	debug_print(DEBUG_ANALYSE, 1, "params_size = 0x%x, locals_size = 0x%x\n",
		entry_point->params_size,
		entry_point->locals_size);

	debug_print(DEBUG_ANALYSE, 1, "value: 0x%"PRIx64", 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64"\n",
		value->start_address,
		value->length,
		value->init_value,
		value->offset_value,
		value->value_type,
		value->value_scope,
		value->value_id);
	//tmp = register_label(label, &(inst_log1->value3));
	return 0;
}

int scan_for_labels_in_function_body(struct self_s *self, struct external_entry_point_s *entry_point,
			 int start, int end, struct label_redirect_s *label_redirect, struct label_s *labels)
{
	int tmp, n;
	//int err;
	uint64_t value_id;
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	//struct memory_s *value;
	//struct label_s *label;

	if (!start || !end) {
		debug_print(DEBUG_ANALYSE, 1, "scan_for_labels_in_function:Invalid start or end\n");
		return 1;
	}
	debug_print(DEBUG_ANALYSE, 1, "scan_for_labels:start=0x%x, end=0x%x\n", start, end);

	for (n = start; n <= end; n++) {
		inst_log1 =  &inst_log_entry[n];
		if (!inst_log1) {
			debug_print(DEBUG_ANALYSE, 1, "scan_for_labels:Invalid inst_log1[0x%x]\n", n);
			return 1;
		}

		instruction =  &inst_log1->instruction;

		/* Test to see if we have an instruction to output */
		debug_print(DEBUG_ANALYSE, 1, "Inst 0x%04x: %d: value_type = %d, %d, %d\n", n,
			instruction->opcode,
			inst_log1->value1.value_type,
			inst_log1->value2.value_type,
			inst_log1->value3.value_type);
		if ((0 == inst_log1->value3.value_type) ||
			(1 == inst_log1->value3.value_type) ||
			(2 == inst_log1->value3.value_type) ||
			(3 == inst_log1->value3.value_type) ||
			(4 == inst_log1->value3.value_type) ||
			(6 == inst_log1->value3.value_type) ||
			(5 == inst_log1->value3.value_type)) {
			debug_print(DEBUG_ANALYSE, 1, "Instruction Opcode = 0x%x\n", instruction->opcode);
			switch (instruction->opcode) {
			case MOV:
			case SEX:
				debug_print(DEBUG_ANALYSE, 1, "SEX or MOV\n");
				if (inst_log1->value1.value_type == 6) {
					debug_print(DEBUG_ANALYSE, 1, "ERROR1 %d\n", instruction->opcode);
					//break;
				}
				if (inst_log1->value1.value_type == 5) {
					debug_print(DEBUG_ANALYSE, 1, "ERROR2\n");
					//break;
				}
				if (1 == instruction->dstA.indirect) {
					value_id = inst_log1->value3.indirect_value_id;
				} else {
					value_id = inst_log1->value3.value_id;
				}
				tmp = register_label(entry_point, value_id, &(inst_log1->value3), label_redirect, labels);
				if (1 == instruction->srcA.indirect) {
					value_id = inst_log1->value1.indirect_value_id;
				} else {
					value_id = inst_log1->value1.value_id;
				}
				tmp = register_label(entry_point, value_id, &(inst_log1->value1), label_redirect, labels);

				break;
			case ADD:
			case MUL:
			case IMUL:
			case SUB:
			case SBB:
			case rAND:
			case OR:
			case XOR:
			case NOT:
			case NEG:
			case SHL:
			case SHR:
			case SAL:
			case SAR:
			case ICMP:
				if (IND_MEM == instruction->dstA.indirect) {
					value_id = inst_log1->value3.indirect_value_id;
				} else {
					value_id = inst_log1->value3.value_id;
				}
				debug_print(DEBUG_ANALYSE, 1, "value3\n");
				tmp = register_label(entry_point, value_id, &(inst_log1->value3), label_redirect, labels);
				if (IND_MEM == instruction->srcA.indirect) {
					value_id = inst_log1->value1.indirect_value_id;
				} else {
					value_id = inst_log1->value1.value_id;
				}
				debug_print(DEBUG_ANALYSE, 1, "value1\n");
				tmp = register_label(entry_point, value_id, &(inst_log1->value1), label_redirect, labels);
				break;
			case JMP:
				break;
			case JMPT:
				break;
			case CALL:
				if (IND_MEM == instruction->dstA.indirect) {
					value_id = inst_log1->value3.indirect_value_id;
				} else {
					value_id = inst_log1->value3.value_id;
				}
				tmp = register_label(entry_point, value_id, &(inst_log1->value3), label_redirect, labels);
				/* Special case for function pointers */
				if (IND_MEM == instruction->srcA.indirect) {
					value_id = inst_log1->value1.indirect_value_id;
					tmp = register_label(entry_point, value_id, &(inst_log1->value1), label_redirect, labels);
				}
				break;
			case CMP:
			case TEST:
				if (IND_MEM == instruction->srcB.indirect) {
					value_id = inst_log1->value2.indirect_value_id;
				} else {
					value_id = inst_log1->value2.value_id;
				}
				debug_print(DEBUG_ANALYSE, 1, "JCD6: Registering CMP label, value_id = 0x%"PRIx64"\n", value_id);
				tmp = register_label(entry_point, value_id, &(inst_log1->value2), label_redirect, labels);
				if (IND_MEM == instruction->srcA.indirect) {
					value_id = inst_log1->value1.indirect_value_id;
				} else {
					value_id = inst_log1->value1.value_id;
				}
				debug_print(DEBUG_ANALYSE, 1, "JCD6: Registering CMP label, value_id = 0x%"PRIx64"\n", value_id);
				tmp = register_label(entry_point, value_id, &(inst_log1->value1), label_redirect, labels);
				break;

			case IF:
				debug_print(DEBUG_ANALYSE, 1, "IF: This might give signed or unsigned info to labels\n");
				break;

			case BC:
				debug_print(DEBUG_ANALYSE, 1, "BC: TODO\n");
				break;

			case NOP:
				break;
			case RET:
				if (IND_MEM == instruction->srcA.indirect) {
					value_id = inst_log1->value1.indirect_value_id;
				} else {
					value_id = inst_log1->value1.value_id;
				}
				tmp = register_label(entry_point, value_id, &(inst_log1->value1), label_redirect, labels);
				break;
			default:
				debug_print(DEBUG_ANALYSE, 1, "Unhandled scan instruction1\n");
				if (print_inst(self, instruction, n, labels))
					return 1;
				return 1;
				break;
			}
		}
	}
	return 0;
}
/***********************************************************************************
 * This is a complex routine. It utilises dynamic lists in order to reduce 
 * memory usage.
 **********************************************************************************/
int search_back_local_reg_stack(struct self_s *self, uint64_t mid_start_size, struct mid_start_s *mid_start, int reg_stack, uint64_t indirect_init_value, uint64_t indirect_offset_value, uint64_t *size, int *search_back_seen, uint64_t **inst_list)
{
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	//uint64_t value_id;
	uint64_t inst_num;
	uint64_t tmp;
	int found = 0;
	int n;

	*size = 0;
	/* FIXME: This could be optimized out if the "seen" value just increased on each call */
	for (n = 0; n < INST_LOG_ENTRY_SIZE; n++) {
		search_back_seen[n] = 0;
	}

	debug_print(DEBUG_ANALYSE, 1, "search_back_local_stack: 0x%"PRIx64", 0x%"PRIx64"\n", indirect_init_value, indirect_offset_value);
	if (0 < mid_start_size) {
		debug_print(DEBUG_ANALYSE, 1, "search_back:prev_size=0x%"PRIx64"\n", mid_start_size);
	}
	if (0 == mid_start_size) {
		debug_print(DEBUG_ANALYSE, 1, "search_back ended\n");
		return 1;
	}

	do {
		found = 0;
		for(n = 0; n < mid_start_size; n++) {
			if (1 == mid_start[n].valid) {
				inst_num = mid_start[n].mid_start;
				mid_start[n].valid = 0;
				found = 1;
				debug_print(DEBUG_ANALYSE, 1, "mid_start removed 0x%"PRIx64" at 0x%x, size=0x%"PRIx64"\n", mid_start[n].mid_start, n, mid_start_size);
				break;
			}
		}
		if (!found) {
			debug_print(DEBUG_ANALYSE, 1, "mid_start not found, exiting\n");
			goto search_back_exit_free;
		}
		if (search_back_seen[inst_num]) {
			continue;
		}
		search_back_seen[inst_num] = 1;
		inst_log1 =  &inst_log_entry[inst_num];
		instruction =  &inst_log1->instruction;
		//value_id = inst_log1->value3.value_id;
		debug_print(DEBUG_ANALYSE, 1, "inst_num:0x%"PRIx64"\n", inst_num);
		/* STACK */
		if ((reg_stack == 2) &&
			(instruction->dstA.store == STORE_REG) &&
			(inst_log1->value3.value_scope == 2) &&
			(instruction->dstA.indirect == IND_STACK) &&
			(inst_log1->value3.indirect_init_value == indirect_init_value) &&
			(inst_log1->value3.indirect_offset_value == indirect_offset_value)) {
			tmp = *size;
			tmp++;
			*size = tmp;
			if (tmp == 1) {
				*inst_list = malloc(sizeof(*inst_list));
				(*inst_list)[0] = inst_num;
			} else {
				*inst_list = realloc(*inst_list, tmp * sizeof(*inst_list));
				(*inst_list)[tmp - 1] = inst_num;
			}
		/* REGISTER */
		} else if ((reg_stack == 1) &&
			(instruction->dstA.store == STORE_REG) &&
			(instruction->dstA.indirect == IND_DIRECT) &&
			(instruction->dstA.index == indirect_init_value)) {
			tmp = *size;
			tmp++;
			*size = tmp;
			if (tmp == 1) {
				*inst_list = malloc(sizeof(*inst_list));
				(*inst_list)[0] = inst_num;
				debug_print(DEBUG_ANALYSE, 1, "JCD2: inst_list[0] = 0x%"PRIx64"\n", inst_num);
			} else {
				*inst_list = realloc(*inst_list, tmp * sizeof(*inst_list));
				(*inst_list)[tmp - 1] = inst_num;
			}
		} else {
			if ((inst_log1->prev_size > 0) &&
				(inst_log1->prev[0] != 0)) {
				int prev_index;
				found = 0;
				prev_index = 0;
				for(n = 0; n < mid_start_size; n++) {
					if (0 == mid_start[n].valid) {
						mid_start[n].mid_start = inst_log1->prev[prev_index];
						prev_index++;
						mid_start[n].valid = 1;
						debug_print(DEBUG_ANALYSE, 1, "mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[n].mid_start, n);
						found = 1;
					}
					if (prev_index >= inst_log1->prev_size) {
						break;
					}
				}
				if (prev_index < inst_log1->prev_size) {
					uint64_t mid_next;
					mid_next = mid_start_size + inst_log1->prev_size - prev_index;
					mid_start = realloc(mid_start, mid_next * sizeof(struct mid_start_s));
					for(n = mid_start_size; n < mid_next; n++) {
						mid_start[n].mid_start = inst_log1->prev[prev_index];
						prev_index++;
						debug_print(DEBUG_ANALYSE, 1, "mid_start realloc added 0x%"PRIx64" at 0x%x\n", mid_start[n].mid_start, n);
						mid_start[n].valid = 1;
					}
					mid_start_size = mid_next;
				}

				if (!found) {
					debug_print(DEBUG_ANALYSE, 1, "not found\n");
					goto search_back_exit_free;
				}
			}
		}
	/* FIXME: There must be deterministic exit point */
	} while (1);
	debug_print(DEBUG_ANALYSE, 1, "end of loop, exiting\n");

search_back_exit_free:
	free(mid_start);
	return 0;
}

