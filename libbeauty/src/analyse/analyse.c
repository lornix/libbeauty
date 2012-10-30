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

	for (n = 1; n <= inst_log; n++) {
		inst_log1 =  &inst_log_entry[n];
		if (inst_log1->next_size > 1) {
			if (inst_log1->next_size > 2) {
				printf("next: over:before inst 0x%x\n", n);
				for (m = 0; m < inst_log1->next_size; m++) {
					printf("next: 0x%x: next[0x%x] = 0x%x\n", n, m, inst_log1->next[m]);
				}
			}
			for (m = 0; m < (inst_log1->next_size - 1); m++) {
				for (l = m + 1; l < inst_log1->next_size; l++) {
					printf("next: 0x%x: m=0x%x, l=0x%x\n", n, inst_log1->next[m],inst_log1->next[l]);
					if (inst_log1->next[m] == inst_log1->next[l]) {
						inst_log1->next[m] = 0;
						printf("next: post: 0x%x: m=0x%x, l=0x%x\n", n, inst_log1->next[m],inst_log1->next[l]);
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
				printf("next: over:after inst 0x%x\n", n);
				for (m = 0; m < inst_log1->next_size; m++) {
					printf("next: 0x%x: next[0x%x] = 0x%x\n", n, m, inst_log1->next[m]);
				}
			}
		}
		if (inst_log1->prev_size > 1) {
			for (m = 0; m < (inst_log1->prev_size - 1); m++) {
				for (l = m + 1; l < inst_log1->prev_size; l++) {
					printf("prev: 0x%x: m=0x%x, l=0x%x\n", n, inst_log1->prev[m],inst_log1->prev[l]);
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

	}
	return 0;
}

int find_node_from_inst(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, int inst)
{
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

	printf("path_loop_check: path = 0x%x, step = 0x%x, node = 0x%x, loop_head = 0x%x\n", path, step, node, paths[path].loop_head);

	while (n < limit) {
		n++;
		step--;
		if (step < 0) {
			//printf("step < 0: 0x%x, 0x%x\n", paths[path].path_prev, paths[path].path_prev_index);
			if (paths[path].path_prev != path) {
				tmp = paths[path].path_prev;
				step = paths[path].path_prev_index;
				path = tmp;
			} else {
			// printf("No loop\n");
				return 0;
			}
		}
		//printf("loop_check: path=0x%x, step=0x%x, path_step=0x%x, node=0x%x\n",
		//	path, step, paths[path].path[step], node);
		if (paths[path].path[step] ==  node) {
			// printf("Loop found\n");
			paths[path1].type = PATH_TYPE_LOOP;
			return 1;
		}
	};
	if (n >= limit) {
		/* The maximum lenght of a path is the number of nodes */
		printf("loop check limit reached\n");
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

	printf("trying to merge path %d into loop\n", path);

	loop->head = paths[path].loop_head;
	step = paths[path].path_size - 1; /* convert size to index */
	if (paths[path].path[step] != loop->head) {
		printf("merge_path failed path 0x%x != head 0x%x\n", paths[path].path[step], loop->head);
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
				printf("No loop\n");
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
			printf("Merge: adding 0x%x\n",  paths[path].path[step]);
			tmp = paths[path].path[step];
			list[loop->size] = tmp;
			loop->size++;
		}

		if (paths[path].path[step] == loop->head) {
			printf("Start of merge Loop found\n");
			break;
		}
	}
	printf("merged head = 0x%x, size = 0x%x\n", loop->head, loop->size);
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
					printf("flow_loops found = %d\n", found);
					break;
				}
			}
			if (found == -1) {
				for(m = 0; m < *loop_size; m++) {
					if (loops[m].head == 0) {
						found = m;
						printf("flow_loops2 found = %d\n", found);
						break;
					}
				}
			}
			if (found == -1) {
				printf("build_control_flow_loops problem\n");
				exit(1);
			}
			if (found >= *loop_size) {
				printf("build_control_flow_loops problem2\n");
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
					printf("flow_loops2 found = %d\n", found);
					break;
				}
			}
			if (found == -1) {
				printf("loop nesting failed\n");
				return 1;
			}
			tmp = paths[n].path_prev;
			if (paths[tmp].loop_head != 0) {
				printf("flow_loops2 path %d nesting %d in %d:%d\n", n, m, tmp, paths[tmp].loop_head);
				loops[m].nest = paths[tmp].loop_head;
			}
		}
	}
#if 0
	for(m = 0; m < *loop_size; m++) {
		if (loops[m].size) {
			printf("flow_loops2 loop:%d head=%d nest=%d size=%d\n", m, loops[m].head, loops[m].nest, loops[m].size);
		}
	}
#endif
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

	printf("Printing loops size = %d\n", *loops_size);
	for (m = 0; m < *loops_size; m++) {
		if (loops[m].size > 0) {
			printf("Loop %d: loop_head=%d, nest=%d\n", m, loops[m].head, loops[m].nest);
			for (n = 0; n < loops[m].size; n++) {
				printf("Loop %d=0x%x\n", m, loops[m].list[n]);
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
	int type;

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
				//printf("dom: prev_node = 0x%x, prev_link_index = 0x%x\n", prev_node, prev_link_index);
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
			//printf("node_dominance: %d = 0x%x, 0x%x\n", tmp, n, node_b);
			if (tmp) {
				nodes[n].dominator = node_b;
				break;
			}
		}
	}
	return 0;
}

int build_node_if_tail(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size)
{
	int n;
	int node_b = 1;
	int tmp;
	int count = 0;
	int m;
	int method = 0;
	int type = 0;
	int preferred = 0;
	int start_node;

	for(n = 1; n <= *nodes_size; n++) {
		type = 0;
		start_node = n;
		/* Check that it is a branch statement */
		if (2 != nodes[n].next_size) {
			continue;
		}
		/* A normal IF statement */
		if ((nodes[n].link_next[0].is_normal == 1) &&
			(nodes[n].link_next[1].is_normal == 1)) {
			if (nodes[n].path_size >= 2) {
				method = 1;
				type = NODE_TYPE_IF_THEN_ELSE;
				preferred = 0;
			} else {
				method = 0;
				type = NODE_TYPE_IF_THEN_ELSE;
				preferred = 0;
			}
		}
		/* A loop_head statement */
		if (nodes[n].loop_head) {
			if (nodes[n].link_next[0].is_loop_exit == 1) {
				method = 1;
				type = NODE_TYPE_LOOP;
				preferred = 0;
			} else if (nodes[n].link_next[1].is_loop_exit == 1) {
				method = 1;
				type = NODE_TYPE_LOOP;
				preferred = 1;
			}
		}
		/* Control flow within a loop */
		if (!nodes[n].loop_head) {
			if (nodes[n].link_next[0].is_loop_exit == 1) {
				method = 1;
				type = NODE_TYPE_IF_THEN_GOTO;
				preferred = 0;
				if (nodes[n].member_of_loop_size == 1) {
					start_node = nodes[n].member_of_loop[0];
				}
			} else if (nodes[n].link_next[1].is_loop_exit == 1) {
				method = 1;
				type = NODE_TYPE_IF_THEN_GOTO;
				preferred = 1;
				if (nodes[n].member_of_loop_size == 1) {
					start_node = nodes[n].member_of_loop[0];
				}
			}
		}
		if (!type) {
			continue;
		}

		node_b = n;
		while ((node_b != 0) ) {
			struct node_link_s *link;
			if (nodes[node_b].next_size == 0) {
				break;
			} else if (nodes[node_b].next_size == 1) {
				link = &(nodes[node_b].link_next[0]);
				if (link->is_loop_edge) {
					break;
				}
			} else if (nodes[node_b].next_size == 2) {
			/* FIXME: preferred is only valid the first time round the loop */
			/* FIXME: what to do if the node is a loop edge and no other links */
				link = &(nodes[node_b].link_next[preferred]);
				/* Do not follow loop edges */
				if (link->is_loop_edge) {
					link = &(nodes[node_b].link_next[preferred ^ 1]);
				}
			} else {
				printf("BROKEN\n");
				break;
			}
			//printf("node = 0x%x, is_norm = %d, is_loop_edge = %d, is_loop_exit = %d, is_loop_entry = %d\n",
			//	node_b, link->is_normal, link->is_loop_edge, link->is_loop_exit, link->is_loop_entry);
			tmp = link->node;
			node_b = tmp;
			if (0 == node_b) {
				break;
			}
			if (method == 1) {
				tmp = is_subset(nodes[start_node].path_size, nodes[start_node].path, nodes[node_b].path_size, nodes[node_b].path);
			} else {
				tmp = is_subset(nodes[start_node].looped_path_size, nodes[start_node].looped_path, nodes[node_b].looped_path_size, nodes[node_b].looped_path);
			}
			//printf("node_if_tail: %d = 0x%x, 0x%x\n", tmp, n, node_b);
			count++;
			if (count > 1000) {
				printf("node_if_tail: failed, too many if_tails\n");
				printf("Start node: 0x%x is_norm = %d, is_loop_edge = %d is_loop_exit = %d is_loop_entry = %d\n",
					n, link->is_normal, link->is_loop_edge, link->is_loop_exit, link->is_loop_entry);
				exit(1);
			}
			if (tmp) {
				nodes[n].if_tail = node_b;
				nodes[n].type = type;
				break;
			}
		}
	}
	return 0;
}

int build_node_paths(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, struct path_s *paths, int *paths_size)

{
	int l,m,n;
	int path;
	int offset;

	printf("paths_size = %d\n", *paths_size);
	for (l = 0; l < *paths_size; l++) {
		path = l;
		offset = paths[l].path_size - 1;
		if (paths[l].path_size > 0) {
			while (1) {
				printf("Path=0x%x, offset=%d, Node=0x%x\n", l, offset, paths[path].path[offset]);
				if (paths[l].type == PATH_TYPE_LOOP) {
					add_looped_path_to_node(&(nodes[paths[path].path[offset]]), l);
				} else {
					add_path_to_node(&(nodes[paths[path].path[offset]]), l);
				}
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
	int l;
	int m;
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
			printf("JCD1: path 0x%x:0x%x, 0x%x\n", path, step, node_mid_start[n].node);
			node_mid_start[n].node = 0;
			step++;
			loop = 0;
			do {
				loop = path_loop_check(paths, path, step - 1, node, *nodes_size);

				if (loop) {
					printf("JCD0: path = 0x%x, step = 0x%x, node = 0x%x, loop = %d\n", path, step, node, loop);
					paths[path].loop_head = node;
					nodes[node].type = NODE_TYPE_LOOP;
					nodes[node].loop_head = 1;
					/* Loops with more than one block */
					if (step >= 2) {
						int node1 = paths[path].path[step - 2];
						int node2 = paths[path].path[step - 1];
						printf("JCD4:loop: 0x%x, 0x%x\n", paths[path].path[step - 2], paths[path].path[step - 1]);
						for (n = 0; n < nodes[node1].next_size; n++) {
							if (nodes[node1].link_next[n].node == node2) {
								nodes[node1].link_next[n].is_loop_edge = 1;
							}
						}
					} else {
						printf("JCD1: testing for do while loop on node = 0x%x, step = 0x%x, path=0x%x\n",
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
					printf("JCD2: path 0x%x:0x%x, 0x%x -> 0x%x\n", path, step, node, nodes[node].link_next[0].node);
					node = nodes[node].link_next[0].node;
					paths[path].path[step] = node;
					step++;
				} else if (nodes[node].next_size > 1) {
					tmp = node_mid_start_add(&nodes[node], node_mid_start, path, step - 1);
					printf("JCD3: path 0x%x:0x%x, 0x%x -> 0x%x\n", path, step, node, nodes[node].link_next[0].node);
					node = nodes[node].link_next[0].node;
					paths[path].path[step] = node;
					step++;
				}
			} while ((nodes[node].next_size > 0) && (loop == 0));
			paths[path].path_size = step;
			path++;
			printf("end path = 0x%x\n", path);
			if (path >= *paths_size) {
				printf("TOO MANY PATHS, %d\n", path);
				return 1;
			}
		}
	} while (found == 1);
	free (node_mid_start);
	*paths_used = path;
	return 0;
}

int print_control_flow_paths(struct self_s *self, struct path_s *paths, int *paths_size)
{
	int n, m;
	printf("print control flow paths size=0x%x\n", *paths_size);
	for (m = 0; m < *paths_size; m++) {
		if (paths[m].used) {
			printf("Path 0x%x: type=%d, loop_head=0x%x, prev 0x%x:0x%x\n", m, paths[m].type, paths[m].loop_head, paths[m].path_prev, paths[m].path_prev_index);
			for (n = 0; n < paths[m].path_size; n++) {
				printf("Path 0x%x=0x%x\n", m, paths[m].path[n]);
			}
//		} else {
			//printf("Un-used Path 0x%x: type=%d, loop_head=0x%x, prev 0x%x:0x%x\n", m, paths[m].type, paths[m].loop_head, paths[m].path_prev, paths[m].path_prev_index);
		}

	}
	return 0;
}

int build_control_flow_nodes(struct self_s *self, struct control_flow_node_s *nodes, int *node_size)
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	int node = 1;
	int inst_start = 1;
	int inst_end;
	int n;
	int m;
	int l;
	int tmp;

	printf("build_control_flow_nodes:\n");	
	for (n = 1; n <= inst_log; n++) {
		inst_log1 =  &inst_log_entry[n];
		/* Test for end of node */
		if ((inst_log1->next_size > 1) ||
			(inst_log1->next_size == 0) ||
			((inst_log1->next_size == 1) && (inst_log1->next[0] != (n + 1)))) {
			inst_end = n;
			/* Handle special case of duplicate prev_inst */
			/* FIXME: Stop duplicate prev_inst being created in the first place */
			if (inst_end >= inst_start) {
				nodes[node].inst_start = inst_start;
				nodes[node].inst_end = inst_end;
				node++;
				inst_start = n + 1;
			}
		}
		if (inst_log1->prev_size > 1) {
			inst_end = n - 1;
			/* Handle special case of duplicate prev_inst */
			/* FIXME: Stop duplicate prev_inst being created in the first place */
			if (inst_end >= inst_start) {
				nodes[node].inst_start = inst_start;
				nodes[node].inst_end = inst_end;
				node++;
				inst_start = n;
			}
		}
	}
	*node_size = node - 1;

	for (n = 1; n <= *node_size; n++) {
		inst_log1 =  &inst_log_entry[nodes[n].inst_start];
		if (inst_log1->prev_size > 0) {
			nodes[n].prev_node = calloc(inst_log1->prev_size, sizeof(int));
			nodes[n].prev_link_index = calloc(inst_log1->prev_size, sizeof(int));
			nodes[n].prev_size = inst_log1->prev_size;

			for (m = 0; m < inst_log1->prev_size; m++) {
				tmp = find_node_from_inst(self, nodes, node_size, inst_log1->prev[m]);
				nodes[n].prev_node[m] = tmp;
				for (l = 0; l < nodes[tmp].next_size; l++) {
					if (nodes[tmp].link_next[l].node == n) {
						nodes[n].prev_link_index[m] = l;
					}
				}
			}
		}
		inst_log1 =  &inst_log_entry[nodes[n].inst_end];
		if (inst_log1->next_size > 0) {
			nodes[n].link_next = calloc(inst_log1->next_size, sizeof(struct node_link_s));
			nodes[n].next_size = inst_log1->next_size;
			if (nodes[n].next_size > 2) {
				printf("build_cfg next_size too big for node 0x%x, inst 0x%x\n", n, nodes[n].inst_end);
				exit(1);
			}

			for (m = 0; m < inst_log1->next_size; m++) {
				tmp = find_node_from_inst(self, nodes, node_size, inst_log1->next[m]);
				nodes[n].link_next[m].node = tmp;
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

	printf("print_control_flow_nodes: size = %d\n", *node_size);	
	for (n = 1; n <= *node_size; n++) {
		printf("Node:0x%x, type=%d, dominator=0x%x, if_tail=0x%x, loop_head=%d, inst_start=0x%x, inst_end=0x%x, entry_point=0x%x\n",
			n,
			nodes[n].type,
			nodes[n].dominator,
			nodes[n].if_tail,
			nodes[n].loop_head,
			nodes[n].inst_start,
			nodes[n].inst_end,
			nodes[n].entry_point);
		for (m = 0; m < nodes[n].prev_size; m++) {
			prev_node = nodes[n].prev_node[m];
			prev_link_index = nodes[n].prev_link_index[m];
			/* make a special case for when prev_node == 0 */
			if (prev_node) {
				printf("nodes[0x%x].prev_node[%d] = 0x%x, prev_link_index=0x%x norm=%d edge=%d exit=%d entry=%d\n",
					n, m, prev_node, prev_link_index,
					nodes[prev_node].link_next[prev_link_index].is_normal,
					nodes[prev_node].link_next[prev_link_index].is_loop_edge,
					nodes[prev_node].link_next[prev_link_index].is_loop_exit,
					nodes[prev_node].link_next[prev_link_index].is_loop_entry);
			} else {
				printf("nodes[0x%x].prev_node[%d] = 0x%x, prev_link_index=0x%x\n",
					n, m, prev_node, prev_link_index);
			}
		}
		for (m = 0; m < nodes[n].next_size; m++) {
			printf("nodes[0x%x].link_next[%d].node = 0x%x, next norm=%d edge=%d exit=%d entry=%d\n",
				n, m, nodes[n].link_next[m].node,
				nodes[n].link_next[m].is_normal,
				nodes[n].link_next[m].is_loop_edge,
				nodes[n].link_next[m].is_loop_exit,
				nodes[n].link_next[m].is_loop_entry);
		}
		if (nodes[n].next_size > 2) {
			/* FIXME: only an error so long as we are not yet supporting jump indexes. */
			printf("Oversized node\n");
			exit(1);
		}
		for (m = 0; m < nodes[n].member_of_loop_size; m++) {
			printf("nodes[0x%x].member_of_loop[%d] = 0x%x\n", n, m, nodes[n].member_of_loop[m]);
		}
		printf("nodes[0x%x].path_size = 0x%x\n", n, nodes[n].path_size);
		printf("nodes[0x%x].looped_size = 0x%x\n", n, nodes[n].looped_path_size);
//		for (m = 0; m < nodes[n].path_size; m++) {
//			printf("nodes[0x%x].path[%d] = 0x%x\n", n, m, nodes[n].path[m]);
//		}
//		for (m = 0; m < nodes[n].looped_path_size; m++) {
//			printf("nodes[0x%x].looped_path[%d] = 0x%x\n", n, m, nodes[n].looped_path[m]);
//		}

	}
	return 0;
}

/* Try to identify the node link types for each node */
int analyse_control_flow_node_links(struct self_s *self, struct control_flow_node_s *nodes, int *node_size)
{
	int l, m, n, n2;
	struct control_flow_node_s *node;
	struct control_flow_node_s *next_node;
	int head;
	int next;
	int type;
	int found;
	int tmp;

	for (n = 1; n <= *node_size; n++) {
		node = &nodes[n];
		for (l = 0; l < node->next_size; l++) {
			tmp = node->link_next[l].is_loop_edge;
			if (tmp != 0) {
				/* Only modify when the type is undefined == 0 */
				continue;
			}
			type = 0;
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
	return 0;
}


int get_value_from_index(struct operand_s *operand, uint64_t *index)
{
	if (operand->indirect) {
		printf(" %s%s[%s0x%"PRIx64"],",
			size_table[operand->value_size],
			indirect_table[operand->indirect],
			store_table[operand->store],
			operand->index);
	} else {
		printf(" %s%s0x%"PRIx64",",
		size_table[operand->value_size],
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
	int tmp;

	/* FIXME: May handle by using first switch as switch (indirect) */
	printf("value in log_to_label: store=0x%x, indirect=0x%x, index=0x%"PRIx64", relocated = 0x%"PRIx64", scope = 0x%"PRIx64", id = 0x%"PRIx64", ind_off_value = 0x%"PRIx64", ind_val_id = 0x%"PRIx64"\n",
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
				printf("PARAM_STACK^\n");
			} else if (0 == indirect) {
				label->scope = 2;
				label->type = 1;
				label->lab_pointer = 0;
				label->value = index;
				printf("PARAM_REG^\n");
			} else {
				printf("JCD: UNKNOWN PARAMS\n");
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
				printf("JCD: UNKNOWN LOCAL\n");
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
			printf("unknown value scope: %04"PRIx64";\n", (value_scope));
			return 1;
			break;
		}
		break;
	default:
		printf("Unhandled store1\n");
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
	printf("Registering label: value_id = 0x%"PRIx64", scope 0x%"PRIx64", type 0x%"PRIx64", value 0x%"PRIx64", size 0x%"PRIx64", pointer 0x%"PRIx64", signed 0x%"PRIx64", unsigned 0x%"PRIx64"\n",
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
		printf("PARAM\n");
		for(n = 0; n < entry_point->params_size; n++) {
			printf("looping 0x%x\n", n);
			if (entry_point->params[n] == label_offset) {
				printf("Duplicate\n");
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
		printf("LOCAL\n");
		for(n = 0; n < entry_point->locals_size; n++) {
			printf("looping 0x%x\n", n);
			if (entry_point->locals[n] == label_offset) {
				printf("Duplicate\n");
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
		printf("HEX VALUE\n");
		break;
	default:
		printf("VALUE unhandled 0x%"PRIx64"\n", label->scope);
		break;
	}
	printf("params_size = 0x%x, locals_size = 0x%x\n",
		entry_point->params_size,
		entry_point->locals_size);

	printf("value: 0x%"PRIx64", 0x%x, 0x%"PRIx64", 0x%"PRIx64", 0x%x, 0x%x, 0x%"PRIx64"\n",
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
	int err;
	uint64_t value_id;
	struct instruction_s *instruction;
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct memory_s *value;
	struct label_s *label;

	if (!start || !end) {
		printf("scan_for_labels_in_function:Invalid start or end\n");
		return 1;
	}
	printf("scan_for_labels:start=0x%x, end=0x%x\n", start, end);

	for (n = start; n <= end; n++) {
		inst_log1 =  &inst_log_entry[n];
		if (!inst_log1) {
			printf("scan_for_labels:Invalid inst_log1[0x%x]\n", n);
			return 1;
		}

		instruction =  &inst_log1->instruction;

		/* Test to see if we have an instruction to output */
		printf("Inst 0x%04x: %d: value_type = %d, %d, %d\n", n,
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
			printf("Instruction Opcode = 0x%x\n", instruction->opcode);
			switch (instruction->opcode) {
			case MOV:
			case SEX:
				printf("SEX or MOV\n");
				if (inst_log1->value1.value_type == 6) {
					printf("ERROR1 %d\n", instruction->opcode);
					//break;
				}
				if (inst_log1->value1.value_type == 5) {
					printf("ERROR2\n");
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
				if (IND_MEM == instruction->dstA.indirect) {
					value_id = inst_log1->value3.indirect_value_id;
				} else {
					value_id = inst_log1->value3.value_id;
				}
				printf("value3\n");
				tmp = register_label(entry_point, value_id, &(inst_log1->value3), label_redirect, labels);
				if (IND_MEM == instruction->srcA.indirect) {
					value_id = inst_log1->value1.indirect_value_id;
				} else {
					value_id = inst_log1->value1.value_id;
				}
				printf("value1\n");
				tmp = register_label(entry_point, value_id, &(inst_log1->value1), label_redirect, labels);
				break;
			case JMP:
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
				if (IND_MEM == instruction->dstA.indirect) {
					value_id = inst_log1->value2.indirect_value_id;
				} else {
					value_id = inst_log1->value2.value_id;
				}
				printf("JCD6: Registering CMP label, value_id = 0x%"PRIx64"\n", value_id);
				tmp = register_label(entry_point, value_id, &(inst_log1->value2), label_redirect, labels);
				if (IND_MEM == instruction->srcA.indirect) {
					value_id = inst_log1->value1.indirect_value_id;
				} else {
					value_id = inst_log1->value1.value_id;
				}
				printf("JCD6: Registering CMP label, value_id = 0x%"PRIx64"\n", value_id);
				tmp = register_label(entry_point, value_id, &(inst_log1->value1), label_redirect, labels);
				break;

			case IF:
				printf("IF: This might give signed or unsigned info to labels\n");
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
				printf("Unhandled scan instruction1\n");
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
	uint64_t value_id;
	uint64_t inst_num;
	uint64_t tmp;
	int found = 0;
	int n;

	*size = 0;
	/* FIXME: This could be optimized out if the "seen" value just increased on each call */
	for (n = 0; n < INST_LOG_ENTRY_SIZE; n++) {
		search_back_seen[n] = 0;
	}

	printf("search_back_local_stack: 0x%"PRIx64", 0x%"PRIx64"\n", indirect_init_value, indirect_offset_value);
	if (0 < mid_start_size) {
		printf("search_back:prev_size=0x%"PRIx64"\n", mid_start_size);
	}
	if (0 == mid_start_size) {
		printf("search_back ended\n");
		return 1;
	}

	do {
		found = 0;
		for(n = 0; n < mid_start_size; n++) {
			if (1 == mid_start[n].valid) {
				inst_num = mid_start[n].mid_start;
				mid_start[n].valid = 0;
				found = 1;
				printf("mid_start removed 0x%"PRIx64" at 0x%x, size=0x%"PRIx64"\n", mid_start[n].mid_start, n, mid_start_size);
				break;
			}
		}
		if (!found) {
			printf("mid_start not found, exiting\n");
			goto search_back_exit_free;
		}
		if (search_back_seen[inst_num]) {
			continue;
		}
		search_back_seen[inst_num] = 1;
		inst_log1 =  &inst_log_entry[inst_num];
		instruction =  &inst_log1->instruction;
		value_id = inst_log1->value3.value_id;
		printf("inst_num:0x%"PRIx64"\n", inst_num);
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
				printf("JCD2: inst_list[0] = 0x%"PRIx64"\n", inst_num);
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
						printf("mid_start added 0x%"PRIx64" at 0x%x\n", mid_start[n].mid_start, n);
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
						printf("mid_start realloc added 0x%"PRIx64" at 0x%x\n", mid_start[n].mid_start, n);
						mid_start[n].valid = 1;
					}
					mid_start_size = mid_next;
				}

				if (!found) {
					printf("not found\n");
					goto search_back_exit_free;
				}
			}
		}
	/* FIXME: There must be deterministic exit point */
	} while (1);
	printf("end of loop, exiting\n");

search_back_exit_free:
	free(mid_start);
	return 0;
}

int link_reloc_table_code_to_external_entry_point(struct rev_eng *handle, struct external_entry_point_s *external_entry_points)
{
	int n;
	int l;
	int tmp;

	for (n = 0; n < handle->reloc_table_code_sz; n++) {
		int len, len1;

		len = strlen(handle->reloc_table_code[n].symbol_name);
		for (l = 0; l < EXTERNAL_ENTRY_POINTS_MAX; l++) {
			if (external_entry_points[l].valid != 0) {
				len1 = strlen(external_entry_points[l].name);
				if (len != len1) {
					continue;
				}
				tmp = strncmp(external_entry_points[l].name, handle->reloc_table_code[n].symbol_name, len);
				if (0 == tmp) {
					handle->reloc_table_code[n].external_functions_index = l;
					handle->reloc_table_code[n].type =
						external_entry_points[l].type;
				}
			}
		}
	}
	return 0;
}




