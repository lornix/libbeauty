int rmb(void *handle_void, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset, uint64_t size, uint8_t rex, uint8_t *return_reg, int *half);
int prefix_0f(void *handle_void, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset, uint64_t size, uint8_t rex);

int dis_Gx_Ex(void *handle_void, int opcode, uint8_t rex, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset, uint8_t *reg, int size);
int dis_Ex_Gx(void *handle_void, int opcode, uint8_t rex, struct dis_instructions_s *dis_instructions, uint8_t *base_address, uint64_t offset, uint8_t *reg, int size);
uint32_t getword(uint8_t *base_address, uint64_t offset);
void split_ModRM(uint8_t byte, uint8_t rex, uint8_t *reg,  uint8_t *reg_mem, uint8_t *mod);
void split_SIB(uint8_t byte, uint8_t rex, uint8_t *mul,  uint8_t *index, uint8_t *base);
