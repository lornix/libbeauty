/*
 *  Copyright (C) 2012  The libbeauty Team
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
 * 06-05-2012 Initial work.
 *   Copyright (C) 2012 James Courtier-Dutton James@superbug.co.uk
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#ifdef __cplusplus
extern "C" int label_to_string(struct label_s *label, char *string, int size);
extern "C" int output_cfg_dot(struct self_s *self,
                         struct label_redirect_s *label_redirect, struct label_s *labels, int entry_point);
extern "C" int output_cfg_dot_basic(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
extern "C" int output_cfg_dot_basic2(struct self_s *self, struct external_entry_point_s *external_entry_point);
#else
extern int label_to_string(struct label_s *label, char *string, int size);
int output_cfg_dot(struct self_s *self,
                         struct label_redirect_s *label_redirect, struct label_s *labels, int entry_point);
int output_cfg_dot_basic(struct self_s *self, struct control_flow_node_s *nodes, int nodes_size);
int output_cfg_dot_basic2(struct self_s *self, struct external_entry_point_s *external_entry_point);
#endif

#endif /* OUTPUT_H */
