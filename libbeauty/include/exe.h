
#ifndef EXE_H
#define EXE_H


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

#endif /* EXE_H */
