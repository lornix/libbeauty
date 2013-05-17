
#ifndef __EXE__
#define __EXE__

/* redirect is used for SSA correction, when one needs to rename a variable */
/* renaming the variable within the log entries would take too long. */
/* so use log entry value_id -> redirect -> label_s */
struct label_redirect_s {
	uint64_t redirect;
} ;

struct label_s {
	/* local = 1, param = 2, data = 3, mem = 4, sp_bp = 5 */
	uint64_t scope;
	/* For local or param: reg = 1, stack = 2 */
	/* For data: data = 1, &data = 2, value = 3 */
	uint64_t type;
	/* value */
	uint64_t value;
	/* size in bits */
	uint64_t size_bits;
	/* is it a pointer */
	uint64_t lab_pointer;
	/* is it a signed */
	uint64_t lab_signed;
	/* is it a unsigned */
	uint64_t lab_unsigned;
	/* human readable name */
	char *name;
} ;

extern struct memory_s *search_store(
        struct memory_s *memory, uint64_t index, int size);
extern struct memory_s *add_new_store(
	struct memory_s *memory, uint64_t index, int size);

//extern instructions_t instructions;
extern uint8_t *inst;
extern void *handle;
extern struct disassemble_info disasm_info;
extern char *dis_flags_table[];
extern uint64_t inst_log;      /* Pointer to the current free instruction log entry. */
extern char out_buf[1024];
extern size_t inst_size;

#endif /* __EXE__ */
