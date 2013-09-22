
#define KIND_EMPTY 0
#define KIND_REG 1
#define KIND_IMM 2
#define KIND_SCALE 3
#define KIND_IND_REG 4
#define KIND_IND_IMM 5
#define KIND_IND_SCALE 6

struct sub_operand_low_level_s {
	uint64_t value;
	int size;
	uint64_t offset;
};

struct operand_low_level_s {
	int kind;
	int size;
	struct sub_operand_low_level_s operand[16];
};
	


struct instruction_low_level_s {
	int opcode;
	uint64_t address;
	int octets;
	int predicate;
	struct operand_low_level_s srcA;
	struct operand_low_level_s srcB;
	struct operand_low_level_s dstA;
};

