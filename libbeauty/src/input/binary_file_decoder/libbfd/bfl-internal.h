#ifndef __BFL_INTERNAL__
#define __BFL_INTERNAL__

#include <bfd.h>
#include <inttypes.h>
#include <dis-asm.h>
#include <opcodes.h>

const char *bfd_err(void);

struct rev_eng {
	bfd		*bfd;		/* libbfd structure */
	asection	**section;	/* sections */
	long		section_sz;
	asymbol		**symtab;	/* symbols (sorted) */
	long		symtab_sz;
	asymbol		**dynsymtab; 	/* dynamic symbols (sorted) */
	long		dynsymtab_sz;
	arelent		**dynreloc;	/* dynamic relocations (sorted) */
	long		dynreloc_sz;
	struct reloc_table_s	*reloc_table_code;   /* relocation table */
	uint64_t	reloc_table_code_sz;
	struct reloc_table_s	*reloc_table_data;   /* relocation table */
	uint64_t	reloc_table_data_sz;
	struct reloc_table_s	*reloc_table_rodata;   /* relocation table */
	uint64_t	reloc_table_rodata_sz;
	int		*section_number_mapping;    /* Mapping bfd sections onto libbeauty sections */
	disassembler_ftype disassemble_fn;
	struct disassemble_info disasm_info;
	char *disassemble_string;
};

#endif /* __BFL_INTERNAL__ */
