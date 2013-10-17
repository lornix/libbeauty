
//#include <llvm-c/Disassembler.h>

#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDisassembler.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCInstPrinter.h"
#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/MemoryObject.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Debug.h"

#include "X86BaseInfo.h"
#include "decode_inst.h"
#include "opcodes.h"

namespace llvm {

struct dis_info_s {
	llvm::MCInst *Inst;
	int offset[16];
	int size[16];
};

class DecodeAsmX86_64 {
public:

DecodeAsmX86_64() {}

~DecodeAsmX86_64();

int DecodeAsmInstruction(uint8_t *Bytes,
	uint64_t BytesSize, uint64_t PC,
	struct instruction_low_level_s *ll_inst);
int setup();
int DecodeInstruction(uint8_t *Bytes,
	uint64_t BytesSize, uint64_t PC,
	struct instruction_low_level_s *ll_inst);
int copy_operand(struct operand_low_level_s *src, struct operand_low_level_s *dst);
int PrintOperand(struct operand_low_level_s *operand);
int PrintInstruction(struct instruction_low_level_s *ll_inst);

private:
const llvm::Target *TheTarget;
MCDisassembler *DisAsm;
MCInstPrinter *IP;
const MCInstrInfo *MII;
struct decode_inst_helper_s *new_helper;
struct dis_info_s *DisInfo;
// memory object;
llvm::MCInst Inst;
const char *TripleName;
int get_reg_size_helper(int value, int *reg_index);

protected:


};

}; // namespace llvm
