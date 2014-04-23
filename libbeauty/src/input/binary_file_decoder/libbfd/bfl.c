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
 * 10-10-2009 Updates.
 *   Copyright (C) 2009 James Courtier-Dutton James@superbug.co.uk
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>

#include <rev.h>
#include "bfl-internal.h"
#include <bfl.h>

/* The symbol table.  */
//static asymbol **syms;

/* Number of symbols in `syms'.  */
//static long symcount = 0;

char *disassemble_string;

static void insert_section(struct bfd *b, asection *sect, void *obj)
{
	struct rev_eng *r = obj;
        debug_print(DEBUG_INPUT_BFD, 1, "Section entered\n");
	r->section[r->section_sz++] = sect;
}

static void print_sections(struct rev_eng* ret)
{
	char *comma;
	unsigned int       opb = bfd_octets_per_byte (ret->bfd);
	asection          *section;
	int n;

	printf("bfd:print_sections: 0x%"PRIx64" sections\n", ret->section_sz);
	for (n = 0; n < ret->section_sz; n++) {
		comma = "";
		section = ret->section[n];
		printf ("%3d %-13s %08lx  ", section->index,
		bfd_get_section_name (ret->bfd, section),
			(unsigned long) bfd_section_size (ret->bfd, section) / opb);
		bfd_printf_vma (ret->bfd, bfd_get_section_vma (ret->bfd, section));
		printf("  ");
		bfd_printf_vma (ret->bfd, section->lma);
		printf("  %08lx  2**%u", (unsigned long) section->filepos,
		bfd_get_section_alignment (ret->bfd, section));
		printf("\n                ");
		printf("  ");

#define PF(x, y) \
	if (section->flags & x) { printf ("%s%s", comma, y); comma = ", "; }

		PF (SEC_HAS_CONTENTS, "CONTENTS");
		PF (SEC_ALLOC, "ALLOC");
		PF (SEC_LOAD, "LOAD");
		PF (SEC_RELOC, "RELOC");
		PF (SEC_READONLY, "READONLY");
		PF (SEC_CODE, "CODE");
		PF (SEC_DATA, "DATA");
		PF (SEC_ROM, "ROM");
		PF (SEC_CONSTRUCTOR, "CONSTRUCTOR");
		PF (SEC_NEVER_LOAD, "NEVER_LOAD");
		PF (SEC_THREAD_LOCAL, "THREAD_LOCAL");
		PF (SEC_HAS_GOT_REF, "GOT_REF");
		PF (SEC_IS_COMMON, "IS_COMMON");
		PF (SEC_DEBUGGING, "DEBUGGING");
		PF (SEC_IN_MEMORY, "IN_MEMORY");
		PF (SEC_EXCLUDE, "EXCLUDE");
		PF (SEC_SORT_ENTRIES, "SORT_ENTRIES");
		PF (SEC_LINK_ONCE, "LINK_ONCE");
		PF (SEC_LINK_DUPLICATES, "LINK_DUPLICATES");
		PF (SEC_LINK_DUPLICATES_ONE_ONLY, "LINK_DUPLICATES_ONE_ONLY");
		PF (SEC_LINK_DUPLICATES_SAME_SIZE, "LINK_DUPLICATES_SAME_SIZE");
		PF (SEC_LINKER_CREATED, "LINKER_CREATED");
		PF (SEC_KEEP, "KEEP");
		PF (SEC_SMALL_DATA, "SMALL_DATA");
		PF (SEC_MERGE, "MERGE");
		PF (SEC_STRINGS, "STRINGS");
		PF (SEC_GROUP, "GROUP");
		PF (SEC_COFF_SHARED_LIBRARY, "COFF_SHARED_LIBRARY");
		PF (SEC_COFF_SHARED, "COFF_SHARED");
		PF (SEC_TIC54X_BLOCK, "TIC54X_BLOCK");
		PF (SEC_TIC54X_CLINK, "TIC54X_CLINK");

		/*      if (section->comdat != NULL)
		 *       printf (" (COMDAT %s %ld)", section->comdat->name,
		 *               section->comdat->symbol);
		 */

		comma = ", ";

		printf ("\n");
	}
	#undef PF
}

#if 0
static void print_code_section(struct rev_eng* ret)
{
  asection          *section = ret->section[0];
  int                n;
  bfd_byte          *data = NULL;
  bfd_size_type      datasize = 0;

  datasize = bfd_get_section_size(section);
  if (datasize == 0)
    return;
  data = malloc(datasize);
  bfd_get_section_contents(ret->bfd, section, data, 0, datasize);
  for(n=0;n<datasize;n++) {
    debug_print(DEBUG_INPUT_BFD, 1, "0x%x ",data[n]);
  }
  debug_print(DEBUG_INPUT_BFD, 1, "\n");
  free(data);
  data = NULL;
}
#endif

int bf_find_section(void *handle_void, char *name, int name_len, int *section_number)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	int n;
	int found = 0;
	*section_number = 0;

	for (n = 0; n < ret->section_sz; n++) {
		/* The + 1 is there to ensure both strings have zero terminators */
		if (!strncmp(ret->section[n]->name, name, name_len + 1)) {
			debug_print(DEBUG_INPUT_BFD, 1, "bf_find_section %s\n", ret->section[n]->name);
			found = 1;
			*section_number = n;
			break;
		}
	}
	return found;
}


int64_t bf_get_code_size(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection          *section = ret->section[0];
	bfd_size_type      datasize = 0;
	int64_t            code_size = 0;
	int n;
	int tmp;

	tmp = bf_find_section(ret, ".text", 5, &n);
	
	if (tmp) {
		section = ret->section[n];
		datasize = bfd_get_section_size(section);
		code_size = datasize;
	}
	return code_size;
}

int64_t bf_get_data_size(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection          *section = ret->section[1];
	bfd_size_type      datasize = 0;
	int64_t            code_size = 0;
	int n;
	int tmp;

	tmp = bf_find_section(ret, ".data", 5, &n);
	
	if (tmp) {
		section = ret->section[n];
		datasize = bfd_get_section_size(section);
		code_size = datasize;
	}
	return code_size;
}

int64_t bf_get_rodata_size(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection          *section = ret->section[1];
	bfd_size_type      datasize = 0;
	int64_t            code_size = 0;
	int n;
	int tmp;

	tmp = bf_find_section(ret, ".rodata", 7, &n);
	
	if (tmp) {
		section = ret->section[n];
		datasize = bfd_get_section_size(section);
		code_size = datasize;
	}
	return code_size;
}

int bf_get_reloc_table_size_code_section(void *handle_void, uint64_t *size)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection          *section = ret->section[0];
	bfd_size_type      datasize = *size;

	datasize = bfd_get_reloc_upper_bound(ret->bfd, section);
	*size = datasize;
	return 1;
}

uint32_t bf_relocated_code(void *handle_void, uint8_t *base_address, uint64_t offset, uint64_t size, struct reloc_table_s **reloc_table_entry)
{
	int n;
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	for (n = 0; n < handle->reloc_table_code_sz; n++) {
		if (handle->reloc_table_code[n].address == offset) {
			*reloc_table_entry = &(handle->reloc_table_code[n]);
			return 0;
		}
	}
	return 1;
}

int bf_find_relocation_rodata(void *handle_void, uint64_t index, int *relocation_area, uint64_t *relocation_index)
{
	int n;
	int found = 1;
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	struct reloc_table_s *reloc_table_entry;
	debug_print(DEBUG_EXE, 1, "JMPT rodata_sz = 0x%"PRIx64"\n", handle->reloc_table_rodata_sz);
	for (n = 0; n < handle->reloc_table_rodata_sz; n++) {
		if (handle->reloc_table_rodata[n].address == index) {
			reloc_table_entry = &(handle->reloc_table_rodata[n]);
			print_reloc_table_entry(reloc_table_entry);
			found = 0;
			*relocation_area = reloc_table_entry->relocated_area;
			*relocation_index = reloc_table_entry->symbol_value;
			break;
		}
	}
	return found;
}

int bf_link_reloc_table_code_to_external_entry_point(void *handle_void, struct external_entry_point_s *external_entry_points)
{
	int n;
	int l;
	int tmp;
	struct rev_eng *handle = (struct rev_eng*) handle_void;

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

/* If relocated_data returns 1, it means that there was a
 * relocation table entry for this data location.
 * This most likely means that this is a pointer.
 * FIXME: What to do if the relocation is to the code segment? Pointer to function?
 */
uint32_t bf_relocated_data(void *handle_void, uint64_t offset, uint64_t size)
{
	int n;
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	for (n = 0; n < handle->reloc_table_data_sz; n++) {
		if (handle->reloc_table_data[n].address == offset) {
			return 1;
		}
	}
	return 0;
}

static void
dump_reloc_set (bfd *abfd, asection *sec, arelent **relpp, long relcount)
{
  arelent **p;
//  char *last_filename, *last_functionname;
//  unsigned int last_line;

  /* Get column headers lined up reasonably.  */
  {
    static int width;

    if (width == 0)
      {
	char buf[30];

	bfd_sprintf_vma (abfd, buf, (bfd_vma) -1);
	width = strlen (buf) - 7;
      }
    printf ("OFFSET %*s TYPE %*s VALUE \n", width, "", 12, "");
  }

//  last_filename = NULL;
//  last_functionname = NULL;
//  last_line = 0;

  for (p = relpp; relcount && *p != NULL; p++, relcount--)
    {
      arelent *q = *p;
      const char *sym_name;
      const char *section_name;

      if (q->sym_ptr_ptr && *q->sym_ptr_ptr)
	{
	  sym_name = (*(q->sym_ptr_ptr))->name;
	  section_name = (*(q->sym_ptr_ptr))->section->name;
	}
      else
	{
	  sym_name = NULL;
	  section_name = NULL;
	}

      bfd_printf_vma (abfd, q->address);
      if (q->howto == NULL)
	printf (" *unknown*         ");
      else if (q->howto->name)
	printf (" %-16s  ", q->howto->name);
      else
	printf (" %-16d  ", q->howto->type);
      if (sym_name)
	debug_print(DEBUG_INPUT_BFD, 1, "sym_name: %s\n", sym_name);
//	objdump_print_symname (abfd, NULL, *q->sym_ptr_ptr);
      else
	{
	  if (section_name == NULL)
	    section_name = "*unknown*";
	  printf ("[%s]", section_name);
	}

      if (q->addend)
	{
	  printf ("+0x");
	  bfd_printf_vma (abfd, q->addend);
	}

      printf ("\n");
    }
}

int bf_get_reloc_table_code_size(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	return ret->reloc_table_code_sz;
}

struct reloc_table_s * bf_get_reloc_table_code(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	return ret->reloc_table_code;
}

int bf_get_reloc_table_code_section(void *handle_void)
{
	/* FIXME: search for .text section instead of selecting 0 */
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection	*section;
	asection	*sym_sec;
	bfd_size_type	datasize;
	arelent		**relpp;
	arelent		*rel;
	uint64_t relcount;
	int n;
	int tmp;
	const char *sym_name;
	uint64_t sym_val;

	tmp = bf_find_section(ret, ".text", 5, &n);
	//debug_print(DEBUG_INPUT_BFD, 1, "%s: section = 0x%x\n", __FUNCTION__, n);
	section = ret->section[n];

	datasize = bfd_get_reloc_upper_bound(ret->bfd, section);
	relpp = malloc (datasize);
	/* This function silently fails if ret->symtab is not set
	 * to an already loaded symbol table.
	 */
	relcount = bfd_canonicalize_reloc(ret->bfd, section, relpp, ret->symtab);
	//debug_print(DEBUG_INPUT_BFD, 1, "Relcount=0x%"PRIx64"\n", relcount);
	ret->reloc_table_code = calloc(relcount, sizeof(*ret->reloc_table_code));
	ret->reloc_table_code_sz = relcount;
	//debug_print(DEBUG_INPUT_BFD, 1, "reloc_size=0x%"PRIx64"\n", sizeof(*ret->reloc_table_code));
	//dump_reloc_set (ret->bfd, section, relpp, relcount);
	for (n=0; n < relcount; n++) {
		rel = relpp[n];
		//debug_print(DEBUG_INPUT_BFD, 1, "rel:addr = 0x%"PRIx64"\n", rel->address);
		ret->reloc_table_code[n].address = rel->address;
		ret->reloc_table_code[n].size = (uint64_t) bfd_get_reloc_size (rel->howto);
		ret->reloc_table_code[n].addend = rel->addend;
		//debug_print(DEBUG_INPUT_BFD, 1, "rel:size = 0x%"PRIx64"\n", (uint64_t) bfd_get_reloc_size (rel->howto));
		//if (rel->howto == NULL) {
		//	printf (" howto *unknown*\n");
		//} else if (rel->howto->name) {
		//	printf (" howto->name %-16s\n", rel->howto->name);
		//	printf (" howto->type %-16d\n", rel->howto->type);
		//} else {
		//	printf (" howto->type %-16d\n", rel->howto->type);
		//}

		//debug_print(DEBUG_INPUT_BFD, 1, "p1 %p\n",&rel->sym_ptr_ptr);
		//debug_print(DEBUG_INPUT_BFD, 1, "p2 %p\n",rel->sym_ptr_ptr);
		if (rel->sym_ptr_ptr == NULL) {
			continue;
		}
		
		sym_name = bfd_asymbol_name(*rel->sym_ptr_ptr);
		sym_val = bfd_asymbol_value(*rel->sym_ptr_ptr);
		sym_sec = bfd_get_section(*rel->sym_ptr_ptr);
		ret->reloc_table_code[n].section_index = sym_sec->index;
		ret->reloc_table_code[n].relocated_area = ret->section_number_mapping[sym_sec->index];
		ret->reloc_table_code[n].section_name = sym_sec->name;
		ret->reloc_table_code[n].symbol_name = sym_name;
		ret->reloc_table_code[n].symbol_value = sym_val;
		
		printf ("sym_name = %s, sym_val = 0x%"PRIx64"\n",sym_name, sym_val);

	}
	free(relpp);
	return 1;
}

int bf_get_reloc_table_data_size(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	return ret->reloc_table_data_sz;
}

struct reloc_table_s * bf_get_reloc_table_data(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	return ret->reloc_table_data;
}

int bf_get_reloc_table_data_section(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection	*section;
	asection	*sym_sec;
	bfd_size_type	datasize;
	arelent		**relpp;
	arelent		*rel;
	uint64_t relcount;
	int n;
	int tmp;
	const char *sym_name;
	uint64_t sym_val;

	tmp = bf_find_section(ret, ".data", 5, &n);
	//debug_print(DEBUG_INPUT_BFD, 1, "%s: section = 0x%x\n", __FUNCTION__, n);
	section = ret->section[n];

	datasize = bfd_get_reloc_upper_bound(ret->bfd, section);
	relpp = malloc (datasize);
	/* This function silently fails if ret->symtab is not set
	 * to an already loaded symbol table.
	 */
	relcount = bfd_canonicalize_reloc(ret->bfd, section, relpp, ret->symtab);
	//debug_print(DEBUG_INPUT_BFD, 1, "relcount=0x%"PRIx64"\n", relcount);
	ret->reloc_table_data = calloc(relcount, sizeof(*ret->reloc_table_data));
	ret->reloc_table_data_sz = relcount;
	//debug_print(DEBUG_INPUT_BFD, 1, "reloc_size=%d\n", sizeof(*ret->reloc_table));
	//dump_reloc_set (ret->bfd, section, relpp, relcount);
	for (n=0; n < relcount; n++) {
		rel = relpp[n];
		//debug_print(DEBUG_INPUT_BFD, 1, "rel:addr = 0x%"PRIx64"\n", rel->address);
		ret->reloc_table_data[n].address = rel->address;
		ret->reloc_table_data[n].size = (uint64_t) bfd_get_reloc_size (rel->howto);
		//debug_print(DEBUG_INPUT_BFD, 1, "rel:size = 0x%"PRIx64"\n", (uint64_t) bfd_get_reloc_size (rel->howto));
		//if (rel->howto == NULL)
		//	printf (" *unknown*\n");
		//else if (rel->howto->name)
		//	printf (" %-16s\n", rel->howto->name);
		//else
		//	printf (" %-16d\n", rel->howto->type);

		//debug_print(DEBUG_INPUT_BFD, 1, "p1 %p\n",&rel->sym_ptr_ptr);
		//debug_print(DEBUG_INPUT_BFD, 1, "p2 %p\n",rel->sym_ptr_ptr);
		if (rel->sym_ptr_ptr == NULL) {
			continue;
		}
		
		//sym_name = bfd_asymbol_name(*rel->sym_ptr_ptr);
		sym_name = bfd_asymbol_name(*rel->sym_ptr_ptr);
		sym_val = bfd_asymbol_value(*rel->sym_ptr_ptr);
		sym_sec = bfd_get_section(*rel->sym_ptr_ptr);
		ret->reloc_table_data[n].section_index = sym_sec->index;
		ret->reloc_table_data[n].relocated_area = ret->section_number_mapping[sym_sec->index];
		ret->reloc_table_data[n].section_name = sym_sec->name;
		ret->reloc_table_data[n].symbol_name = sym_name;
		ret->reloc_table_data[n].symbol_value = sym_val;
		
		//printf (" %i, %s\n",sym_sec->index, sym_name);

	}
	free(relpp);
	return 1;
}

int bf_get_reloc_table_rodata_size(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	return ret->reloc_table_rodata_sz;
}

struct reloc_table_s * bf_get_reloc_table_rodata(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	return ret->reloc_table_rodata;
}

int bf_get_reloc_table_rodata_section(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection	*section;
	asection	*sym_sec;
	bfd_size_type	datasize;
	arelent		**relpp;
	arelent		*rel;
	uint64_t relcount;
	int n;
	int tmp;
	const char *sym_name;
	uint64_t sym_val;

	tmp = bf_find_section(ret, ".rodata", 7, &n);
	debug_print(DEBUG_INPUT_BFD, 1, "%s: section = 0x%x\n", __FUNCTION__, n);
	section = ret->section[n];
	debug_print(DEBUG_INPUT_BFD, 1, "%s: section_ptr = %p\n", __FUNCTION__, section);

	datasize = bfd_get_reloc_upper_bound(ret->bfd, section);
	debug_print(DEBUG_INPUT_BFD, 1, "%s: datasize = 0x%lx\n", __FUNCTION__, datasize);
	relpp = malloc (datasize);
	debug_print(DEBUG_INPUT_BFD, 1, "%s: relpp = %p\n", __FUNCTION__, relpp);
	/* This function silently fails if ret->symtab is not set
	 * to an already loaded symbol table.
	 */
	relcount = bfd_canonicalize_reloc(ret->bfd, section, relpp, ret->symtab);
	//debug_print(DEBUG_INPUT_BFD, 1, "relcount=0x%"PRIx64"\n", relcount);
	ret->reloc_table_rodata = calloc(relcount, sizeof(*ret->reloc_table_rodata));
	ret->reloc_table_rodata_sz = relcount;
	//debug_print(DEBUG_INPUT_BFD, 1, "reloc_size=%d\n", sizeof(*ret->reloc_table));
	//dump_reloc_set (ret->bfd, section, relpp, relcount);
	for (n=0; n < relcount; n++) {
		rel = relpp[n];
		//debug_print(DEBUG_INPUT_BFD, 1, "rel:addr = 0x%"PRIx64"\n", rel->address);
		ret->reloc_table_rodata[n].address = rel->address;
		ret->reloc_table_rodata[n].size = (uint64_t) bfd_get_reloc_size (rel->howto);
		ret->reloc_table_rodata[n].addend = rel->addend;
		//debug_print(DEBUG_INPUT_BFD, 1, "rel:size = 0x%"PRIx64"\n", (uint64_t) bfd_get_reloc_size (rel->howto));
		//debug_print(DEBUG_INPUT_BFD, 1, "value 0x%"PRIx64"\n", rel->addend);
//		if (rel->howto == NULL)
//			printf ("howto *unknown*\n");
//		else if (rel->howto->name)
//			printf ("howto %-16s\n", rel->howto->name);
//		else
//			printf ("howto %-16d\n", rel->howto->type);

//		debug_print(DEBUG_INPUT_BFD, 1, "p1 %p\n",&rel->sym_ptr_ptr);
//		debug_print(DEBUG_INPUT_BFD, 1, "p2 %p\n",rel->sym_ptr_ptr);
		if (rel->sym_ptr_ptr == NULL) {
			continue;
		}
		
		sym_name = bfd_asymbol_name(*rel->sym_ptr_ptr);
		sym_val = bfd_asymbol_value(*rel->sym_ptr_ptr);
		sym_sec = bfd_get_section(*rel->sym_ptr_ptr);
		ret->reloc_table_rodata[n].section_index = sym_sec->index;
		ret->reloc_table_rodata[n].relocated_area = ret->section_number_mapping[sym_sec->index];
		ret->reloc_table_rodata[n].section_name = sym_sec->name;
		ret->reloc_table_rodata[n].symbol_name = sym_name;
		ret->reloc_table_rodata[n].symbol_value = sym_val;
		
		//printf (" %i, %s\n",sym_sec->index, sym_name);

	}
	free(relpp);
	return 1;
}

int bf_print_reloc_table_entry(struct reloc_table_s *reloc_table_entry)
{
	debug_print(DEBUG_INPUT_BFD, 1, "Reloc Type:0x%x\n", reloc_table_entry->type);
	debug_print(DEBUG_INPUT_BFD, 1, "Address:0x%"PRIx64"\n", reloc_table_entry->address);
	debug_print(DEBUG_INPUT_BFD, 1, "Size:0x%"PRIx64"\n", reloc_table_entry->size);
	debug_print(DEBUG_INPUT_BFD, 1, "AddEnd:0x%"PRIx64"\n", reloc_table_entry->addend);
	debug_print(DEBUG_INPUT_BFD, 1, "External Function Index:0x%"PRIx64"\n", reloc_table_entry->external_functions_index);
	debug_print(DEBUG_INPUT_BFD, 1, "Section index:0x%"PRIx64"\n", reloc_table_entry->section_index);
	debug_print(DEBUG_INPUT_BFD, 1, "Section name:%s\n", reloc_table_entry->section_name);
	debug_print(DEBUG_INPUT_BFD, 1, "Symbol name:%s\n", reloc_table_entry->symbol_name);
	debug_print(DEBUG_INPUT_BFD, 1, "Symbol Value:0x%"PRIx64"\n", reloc_table_entry->symbol_value);
	return 0;
}

int bf_print_reloc_table_code_section(void *handle_void)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	int64_t reloc_table_size;
	struct reloc_table_s *reloc_table_entry;
	int n;
	int tmp;
	reloc_table_size = ret->reloc_table_code_sz;
	debug_print(DEBUG_INPUT_BFD, 1, "reloc_table_code_sz=0x%"PRIx64"\n", reloc_table_size);
	for (n = 0; n < reloc_table_size; n++) {
		reloc_table_entry = &(ret->reloc_table_code[n]);
		tmp = bf_print_reloc_table_entry(reloc_table_entry);
	}
        return 0;
}

int external_entry_points_init_bfl(struct external_entry_point_s *external_entry_points, void *handle_void)
{
	int n;
	int l;
	struct rev_eng *handle = (struct rev_eng*) handle_void;

	/* Print the symtab */
	debug_print(DEBUG_MAIN, 1, "symtab_sz = %lu\n", handle->symtab_sz);
	if (handle->symtab_sz >= 100) {
		debug_print(DEBUG_MAIN, 1, "symtab too big!!! EXITING\n");
		return 1;
	}
	n = 0;
	for (l = 0; l < handle->symtab_sz; l++) {
		size_t length;
		/* FIXME: value == 0 for the first function in the .o file. */
		/*        We need to be able to handle more than
		          one function per .o file. */
		debug_print(DEBUG_MAIN, 1, "section_id = %d, section_index = %d, flags = 0x%04x, value = 0x%04"PRIx64"\n",
			handle->symtab[l]->section->id,
			handle->symtab[l]->section->index,
			handle->symtab[l]->flags,
			handle->symtab[l]->value);
		if ((handle->symtab[l]->flags & 0x8) ||
			(handle->symtab[l]->flags == 0)) {
			external_entry_points[n].valid = 1;
			/* 1: Public function entry point
			 * 2: Private function entry point
			 * 3: Private label entry point
			 */
			if (handle->symtab[l]->flags & 0x8) {
				external_entry_points[n].type = 1;
			} else {
				external_entry_points[n].type = 2;
			}
			external_entry_points[n].section_offset = l;
			external_entry_points[n].section_id = 
				handle->symtab[l]->section->id;
			external_entry_points[n].section_index = 
				handle->symtab[l]->section->index;
			external_entry_points[n].value = handle->symtab[l]->value;
			length = strlen(handle->symtab[l]->name);
			external_entry_points[n].name = malloc(length+1);
			strncpy(external_entry_points[n].name, handle->symtab[l]->name, length+1);
			n++;
		}

	}
	return 0;
}



int bf_copy_code_section(void *handle_void, uint8_t *data, uint64_t data_size)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection	*section;
	bfd_size_type	datasize = data_size;
	int		n, tmp;
	int 		result = 0;

	if (!ret)
		return 0;

	tmp = bf_find_section(ret, ".text", 5, &n);
	
	if (tmp) {
		section = ret->section[n];
		bfd_get_section_contents(ret->bfd, section, data, 0, datasize);
		debug_print(DEBUG_INPUT_BFD, 1, "Text Data at %p\n",data);
		result = 1;
	}
	return result;
}

int bf_copy_data_section(void *handle_void, uint8_t *data, uint64_t data_size)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection	*section;
	bfd_size_type	datasize = data_size;
	int		n, tmp;
	int 		result = 0;

	if (!ret)
		return 0;

	tmp = bf_find_section(ret, ".data", 5, &n);
	
	if (tmp) {
		section = ret->section[n];
		bfd_get_section_contents(ret->bfd, section, data, 0, datasize);
		debug_print(DEBUG_INPUT_BFD, 1, "Data at %p\n",data);
		result = 1;
	}
	return result;
}

int bf_copy_rodata_section(void *handle_void, uint8_t *data, uint64_t data_size)
{
	struct rev_eng *ret = (struct rev_eng*) handle_void;
	asection	*section;
	bfd_size_type	datasize = data_size;
	int		n, tmp;
	int 		result = 0;

	if (!ret)
		return 0;

	tmp = bf_find_section(ret, ".rodata", 7, &n);
	
	if (tmp) {
		section = ret->section[n];
		bfd_get_section_contents(ret->bfd, section, data, 0, datasize);
		debug_print(DEBUG_INPUT_BFD, 1, "ROData at %p\n",data);
		result = 1;
	}
	return result;
}

const char *bfd_err(void)
{
	return bfd_errmsg(bfd_get_error());
}

int bf_get_arch_mach(void *handle_void, uint32_t *arch, uint64_t *mach)
{
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	bfd *b;

	if (!handle) {
		return 1;
	}
	
	b = handle->bfd;
	debug_print(DEBUG_INPUT_BFD, 1, "format:%"PRIu32", %"PRIu64"\n",bfd_get_arch(b), bfd_get_mach(b));
	*arch = bfd_get_arch(b);
	*mach = bfd_get_mach(b);
	return 0;
}


void *bf_test_open_file(const char *fn)
{
	struct rev_eng *ret;
	int64_t tmp;
	bfd *b;
	char **matching;
	int result;
	int64_t storage_needed;
	int64_t number_of_symbols;
	//symbol_info sym_info;

        debug_print(DEBUG_INPUT_BFD, 1, "Open entered\n");
	/* Open the file with libbfd */
	b = bfd_openr(fn, NULL);
	if ( b == NULL ) {
		printf("Error opening %s:%s\n",
				fn, bfd_err());
		return NULL;
	}
	result = bfd_check_format_matches (b, bfd_object, &matching);
	debug_print(DEBUG_INPUT_BFD, 1, "check format result=%d, file format=%s\n",result, b->xvec->name);
	debug_print(DEBUG_INPUT_BFD, 1, "format:%"PRIu32", %"PRIu64"\n",bfd_get_arch(b), bfd_get_mach(b));
	debug_print(DEBUG_INPUT_BFD, 1, "arch:%"PRIu32", mach64:%"PRIu32", mach32:%"PRIu32"\n",bfd_arch_i386, bfd_mach_x86_64, bfd_mach_i386_i386);

	if (bfd_get_error () == bfd_error_file_ambiguously_recognized)
	{
		debug_print(DEBUG_INPUT_BFD, 1, "Couldn't determine format of %s:%s\n",
				fn, bfd_err());
		bfd_close(b);
		return NULL;
	}
/*
		nonfatal (bfd_get_filename (abfd));
		list_matching_formats (matching);
		free (matching);
		return;
	}

  if (bfd_get_error () != bfd_error_file_not_recognized)
    {
      nonfatal (bfd_get_filename (abfd));
      return;
    }

  if (bfd_check_format_matches (abfd, bfd_core, &matching))
    {
      dump_bfd (abfd);
      return;
    }
*/

	/* Check it's an object file and not a core dump, or
	 * archive file or whatever else...
	 */
	if ( !bfd_check_format(b, bfd_object) ) {
		debug_print(DEBUG_INPUT_BFD, 1, "Couldn't determine format of %s:%s\n",
				fn, bfd_err());
		bfd_close(b);
		return NULL;
	}

	/* Create our structure */
	ret = calloc(1, sizeof(*ret));
	if ( ret == NULL ) {
		debug_print(DEBUG_INPUT_BFD, 1, "Couldn't calloc struct rev_eng\n");
		bfd_close(b);
		return NULL;
        }

	ret->bfd = b;

	tmp = bfd_count_sections(ret->bfd);
	if ( tmp <= 0 ) {
          debug_print(DEBUG_INPUT_BFD, 1, "Couldn't count sections\n");
          bfd_close(b);
          return NULL;
        }
	ret->section = calloc(tmp, sizeof(*ret->section));
	if ( ret->section == NULL ) {
          debug_print(DEBUG_INPUT_BFD, 1, "Couldn't calloc struct ret->section\n");
          bfd_close(b);
          return NULL;
        }
	bfd_map_over_sections(ret->bfd, insert_section, ret);
	print_sections(ret);
/*
	print_code_section(ret);
*/
	storage_needed  = bfd_get_symtab_upper_bound(ret->bfd);
	debug_print(DEBUG_INPUT_BFD, 1, "symtab_upper_bound = %"PRId64"\n", storage_needed);
	ret->symtab = calloc(1, storage_needed);
	debug_print(DEBUG_INPUT_BFD, 1, "symtab = %p\n", ret->symtab);
	number_of_symbols = bfd_canonicalize_symtab(ret->bfd, ret->symtab);
	ret->symtab_sz = number_of_symbols;
	debug_print(DEBUG_INPUT_BFD, 1, "symtab_canon = %"PRId64"\n", number_of_symbols);
#if 0
	for (l = 0; l < number_of_symbols; l++) {
		debug_print(DEBUG_INPUT_BFD, 1, "%"PRId64"\n", l);
		debug_print(DEBUG_INPUT_BFD, 1, "type:0x%02x\n", ret->symtab[l]->flags);
		debug_print(DEBUG_INPUT_BFD, 1, "name:%s\n", ret->symtab[l]->name);
		debug_print(DEBUG_INPUT_BFD, 1, "value=0x%02"PRIx64"\n", ret->symtab[l]->value);
		//debug_print(DEBUG_INPUT_BFD, 1, "value2=0x%02x\n",
		//	bfd_asymbol_flavour(ret->symtab[l]));
		//debug_print(DEBUG_INPUT_BFD, 1, "value3=0x%02x\n",
		//	bfd_asymbol_base(ret->symtab[l]));
#if 0
		debug_print(DEBUG_INPUT_BFD, 1, "%d:0x%02x:%s=%lld\n",
			n, sym_info.type, sym_info.name, sym_info.value);
#endif
		/* Print the "other" value for a symbol.  For common symbols,
		 * we've already printed the size; now print the alignment.
		 * For other symbols, we have no specified alignment, and
		 * we've printed the address; now print the size.  */
#if 0
		if (bfd_is_com_section(ret->symtab[n]->section))
			val = ((elf_symbol_type *) symbol)->internal_elf_sym.st_value;
		else
			val = ((elf_symbol_type *) symbol)->internal_elf_sym.st_size;
		bfd_fprintf_vma(abfd, file, val);
#endif

	}
#endif
        debug_print(DEBUG_INPUT_BFD, 1, "Setup ok\n");

	return (void*)ret;
}

void bf_test_close_file(void *handle_void)
{
	struct rev_eng *r = (struct rev_eng*) handle_void;
	if (!r) return;
	if ( r->section )
		free(r->section);
	if ( r->symtab )
		free(r->symtab);
	if ( r->dynsymtab )
		free(r->dynsymtab);
	if ( r->dynreloc )
		free(r->dynreloc);
	bfd_close(r->bfd);
	free(r);
}


int bf_print_symtab(void *handle_void)
{
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	int l;
	debug_print(DEBUG_INPUT_BFD, 1, "symtab_size = %ld\n", handle->symtab_sz);
	for (l = 0; l < handle->symtab_sz; l++) {
		debug_print(DEBUG_MAIN, 1, "%d\n", l);
		debug_print(DEBUG_MAIN, 1, "type:0x%02x\n", handle->symtab[l]->flags);
		debug_print(DEBUG_MAIN, 1, "name:%s\n", handle->symtab[l]->name);
		debug_print(DEBUG_MAIN, 1, "value=0x%02"PRIx64"\n", handle->symtab[l]->value);
		debug_print(DEBUG_MAIN, 1, "section=%p\n", handle->symtab[l]->section);
		debug_print(DEBUG_MAIN, 1, "section name=%s\n", handle->symtab[l]->section->name);
		debug_print(DEBUG_MAIN, 1, "section flags=0x%02x\n", handle->symtab[l]->section->flags);
		debug_print(DEBUG_MAIN, 1, "section index=0x%02"PRIx32"\n", handle->symtab[l]->section->index);
		debug_print(DEBUG_MAIN, 1, "section id=0x%02"PRIx32"\n", handle->symtab[l]->section->id);
	}
	return 0;
}

int bf_init_section_number_mapping(void *handle_void, int **section_number_mapping)
{
	int l;
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	int *map;

	map = calloc(handle->section_sz, sizeof(int));
	handle->section_number_mapping = map;
	for (l = 0; l < handle->section_sz; l++) {
			const char *name = handle->section[l]->name;
		if (!strncmp(".text", name, 5)) {
			map[l] = 1;
		}
		if (!strncmp(".rodata", name, 7)) {
			map[l] = 2;
		}
		if (!strncmp(".data", name, 5)) {
			map[l] = 3;
		}
	}
	*section_number_mapping = map;
	return 0;
}

int bf_print_sectiontab(void *handle_void)
{
	int l;
	struct rev_eng *handle = (struct rev_eng*) handle_void;

	debug_print(DEBUG_MAIN, 1, "sectiontab_size = %ld\n", handle->section_sz);
	for (l = 0; l < handle->section_sz; l++) {
		debug_print(DEBUG_MAIN, 1, "%d\n", l);
		debug_print(DEBUG_MAIN, 1, "flags:0x%02x\n", handle->section[l]->flags);
		debug_print(DEBUG_MAIN, 1, "name:%s\n", handle->section[l]->name);
		debug_print(DEBUG_MAIN, 1, "index=0x%02"PRIx32"\n", handle->section[l]->index);
		debug_print(DEBUG_MAIN, 1, "id=0x%02"PRIx32"\n", handle->section[l]->id);
		debug_print(DEBUG_MAIN, 1, "sectio=%p\n", handle->section[l]);
		debug_print(DEBUG_MAIN, 1, "section_number_mapping=0x%x\n", handle->section_number_mapping[l]);
	}
	return 0;
}

void bf_disassemble_callback_start(void *handle_void)
{
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	handle->disassemble_string[0] = 0;
}

void bf_disassemble_callback_end(void *handle_void)
{
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	debug_print(DEBUG_INPUT_DIS, 1, "%s\n", handle->disassemble_string);
}

int bf_disassemble_print_callback(FILE *stream, const char *format, ...)
{
	va_list ap;
	char *str1;
	va_start(ap, format);
	if (!strncmp(format, "%s", 2)) {
		str1 = va_arg(ap, char *);
		strcat(disassemble_string, str1);
	} else if (!strncmp(format, "0x%s", 4)) {
		str1 = va_arg(ap, char *);
		strcat(disassemble_string, "0x");
		strcat(disassemble_string, str1);
	} else {
		strcat(disassemble_string, format);
	}
	va_end(ap);
	return 0;
}


int bf_disassemble_init(void *handle_void, int inst_size, uint8_t *inst)
{
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	struct disassemble_info *disasm_info = &(handle->disasm_info);
	disassembler_ftype disassemble_fn;

	init_disassemble_info(disasm_info, stdout, (fprintf_ftype) bf_disassemble_print_callback);
	disasm_info->flavour = bfd_get_flavour(handle->bfd);
	disasm_info->arch = bfd_get_arch(handle->bfd);
	disasm_info->mach = bfd_get_mach(handle->bfd);
	disasm_info->disassembler_options = "intel";
	disasm_info->octets_per_byte = bfd_octets_per_byte(handle->bfd);
	disasm_info->skip_zeroes = 8;
	disasm_info->skip_zeroes_at_end = 3;
	disasm_info->disassembler_needs_relocs = 0;
	disasm_info->buffer_length = inst_size;
	disasm_info->buffer = inst;

	debug_print(DEBUG_MAIN, 1, "disassemble_fn inst=%p, inst_size = 0x%x\n", inst, inst_size);
	disassemble_fn = disassembler(handle->bfd);
	handle->disassemble_fn = disassemble_fn;
	/* disassemble_string point needs to be a global for the bf_disassemble_print_callback */
	disassemble_string = calloc(1, 1024);
	handle->disassemble_string = disassemble_string;
	debug_print(DEBUG_MAIN, 1, "disassemble_fn done %p, %p\n", disassemble_fn, print_insn_i386);
	return 0;
}

int bf_disassemble_set_options(void *handle_void, char *options)
{
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	handle->disasm_info.disassembler_options = options;
	return 0;
}

int bf_disassemble(void *handle_void, int offset)
{
	struct rev_eng *handle = (struct rev_eng*) handle_void;
	struct disassemble_info *disasm_info = &(handle->disasm_info);
	disassembler_ftype disassemble_fn = handle->disassemble_fn;
	int octets = 0;
	debug_print(DEBUG_MAIN, 1, "bf_disassemble_fn %p, %p offset = 0x%x\n", disassemble_fn, print_insn_i386, offset);
#if 0
	for (n = 0; n < disasm_info->buffer_length; n++) {
		printf("0x%x ", disasm_info->buffer[n]);
	}
	printf("\n");
#endif
	octets = (*disassemble_fn) (offset, disasm_info);
	return octets;
}
