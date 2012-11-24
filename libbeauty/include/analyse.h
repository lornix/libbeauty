#ifndef __ANALYSE__
#define __ANALYSE__

struct relocation_s {
	int type; /* 0 = invalid, 1 = external_entry_point, 2 = data */
	uint64_t index; /* Index into the external_entry_point or data */
};

struct mid_start_s {
	uint64_t mid_start;
	uint64_t valid;
};

extern int tidy_inst_log(struct self_s *self);
extern int find_node_from_inst(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, int inst);
extern int node_mid_start_add(struct control_flow_node_s *node, struct node_mid_start_s *node_mid_start, int path, int step);
extern int path_loop_check(struct path_s *paths, int path, int step, int node, int limit);
extern int merge_path_into_loop(struct path_s *paths, struct loop_s *loop, int path);
extern int build_control_flow_loops(struct self_s *self, struct path_s *paths, int *paths_size, struct loop_s *loops, int *loop_size);
extern int build_control_flow_loops_node_members(struct self_s *self,
	struct control_flow_node_s *nodes, int *nodes_size,
	struct loop_s *loops, int *loops_size);
extern int print_control_flow_loops(struct self_s *self, struct loop_s *loops, int *loops_size);
extern int add_path_to_node(struct control_flow_node_s *node, int path);
extern int add_looped_path_to_node(struct control_flow_node_s *node, int path);
extern int is_subset(int size_a, int *a, int size_b, int *b);
extern int build_node_dominance(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size);
extern int build_node_type(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size);
extern int build_node_if_tail(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size);
extern int build_node_paths(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, struct path_s *paths, int *paths_size);
extern int build_control_flow_paths(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size, struct path_s *paths, int *paths_size, int *paths_used, int node_start);
extern int print_control_flow_paths(struct self_s *self, struct path_s *paths, int *paths_size);
extern int build_control_flow_nodes(struct self_s *self, struct control_flow_node_s *nodes, int *node_size);
extern int build_control_flow_depth(struct self_s *self, struct control_flow_node_s *nodes, int *nodes_size, struct path_s *paths, int *paths_size, int *paths_used, int node_start);
extern int print_control_flow_nodes(struct self_s *self, struct control_flow_node_s *nodes, int *node_size);
extern int analyse_control_flow_node_links(struct self_s *self, struct control_flow_node_s *nodes, int *node_size);
extern int analyse_merge_nodes(struct self_s *self, struct control_flow_node_s *nodes, int *node_size, int node_a, int node_b);
extern int get_value_from_index(struct operand_s *operand, uint64_t *index);
extern int log_to_label(int store, int indirect, uint64_t index, uint64_t relocated, uint64_t value_scope, uint64_t value_id, uint64_t indirect_offset_value, uint64_t indirect_value_id, struct label_s *label);
extern int register_label(struct external_entry_point_s *entry_point, uint64_t value_id,
	struct memory_s *value, struct label_redirect_s *label_redirect, struct label_s *labels);
extern int scan_for_labels_in_function_body(struct self_s *self, struct external_entry_point_s *entry_point,
			 int start, int end, struct label_redirect_s *label_redirect, struct label_s *labels);
extern int search_back_local_reg_stack(struct self_s *self, uint64_t mid_start_size, struct mid_start_s *mid_start, int reg_stack, uint64_t indirect_init_value, uint64_t indirect_offset_value, uint64_t *size, int *search_back_seen, uint64_t **inst_list);
extern int link_reloc_table_code_to_external_entry_point(struct rev_eng *handle, struct external_entry_point_s *external_entry_points);



#endif /* __ANALYSE__ */
