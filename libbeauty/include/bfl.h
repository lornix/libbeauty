/*
 *  Copyright (C) 2004-2009 The libbeauty Team
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
 */

#ifndef BFL_H
#define BFL_H

#include <inttypes.h>

const char *bfd_err(void);

void *bf_test_open_file(const char *fn);
int bf_get_arch_mach(void *handle_void, uint32_t *arch, uint64_t *mach);
void bf_test_close_file(void *handle_void);
int64_t bf_get_code_size(void *handle_void);
int bf_copy_code_section(void *handle_void, uint8_t *data, uint64_t data_size);
int64_t bf_get_data_size(void *handle_void);
int bf_copy_data_section(void *handle_void, uint8_t *data, uint64_t data_size);
int64_t bf_get_rodata_size(void *handle_void);
int bf_copy_rodata_section(void *handle_void, uint8_t *data, uint64_t data_size);
int bf_get_reloc_table_code_section(void *handle_void);
int bf_get_reloc_table_data_section(void *handle_void);
int bf_get_reloc_table_rodata_section(void *handle_void);
int bf_get_reloc_table_code_size(void *handle_void);
struct reloc_table_s * bf_get_reloc_table_code(void *handle_void);
int bf_get_reloc_table_data_size(void *handle_void);
struct reloc_table_s * bf_get_reloc_table_data(void *handle_void);
int bf_get_reloc_table_rodata_size(void *handle_void);
struct reloc_table_s * bf_get_reloc_table_rodata(void *handle_void);

int bf_print_reloc_table_code_section(void *handle_void);
int external_entry_points_init_bfl(struct external_entry_point_s *external_entry_points, void *handle_void);
uint32_t bf_relocated_code(void *handle_void, uint8_t *base_address, uint64_t offset, uint64_t size, struct reloc_table_s **reloc_table_entry);
uint32_t bf_relocated_data(void *handle_void, uint64_t offset, uint64_t size);
int bf_find_relocation_rodata(void *handle_void, uint64_t index, int *relocation_area, uint64_t *relocation_index);
int bf_link_reloc_table_code_to_external_entry_point(void *handle, struct external_entry_point_s *external_entry_points);
int bf_print_symtab(void *handle_void);
int bf_init_section_number_mapping(void *handle_void, int **section_number_mapping);
int bf_print_sectiontab(void *handle_void);
extern int bf_disassemble_init(void *handle_void, int inst_size, uint8_t *inst);
void bf_disassemble_callback_start(void *handle_void);
void bf_disassemble_callback_end(void *handle_void);
int bf_disassemble(void *handle_void, int offset);
int bf_disassemble_set_options(void *handle_void, char *options);

#endif /* BFL_H */
