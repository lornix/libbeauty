
#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include "llvm/MC/MCInstrInfo.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"

using namespace llvm;

struct dis_info_s {
	MCInst *Inst;
	int offset[16];
	int size[16];
};

struct dis_info_s *LLVMCreateDisInfo(void) {
	int n;
	MCInst *inst = new MCInst;
	struct dis_info_s *dis_info = (struct dis_info_s*) calloc (1, sizeof (struct dis_info_s));
	dis_info->Inst = inst;
	dis_info->Inst->clear();
	for (n = 0; n < 16; n++) {
		dis_info->offset[n] = 0;
		dis_info->size[n] = 0;
	}
	return dis_info;
}

int LLVMDecodeOpInfoCallback(void *DisInfo, uint64_t PC,
                                  uint64_t Offset, uint64_t Size,
                                  int TagType, void *TagBuf) {
	struct dis_info_s *dis_info = (struct dis_info_s *) DisInfo;
	MCInst *Inst = dis_info->Inst;
	int num_operands = Inst->getNumOperands();
	if (num_operands >= 16) {
		outs() << "num_operands >= 16\n";
		exit(1);
	}
	dis_info->offset[num_operands] = Offset;
	dis_info->size[num_operands] = Size;
	outs() << format("NumOperands = 0x%x, ", num_operands) << format("Offset = 0x%x, ", Offset) << format("Size = 0x%x", Size) << "\n";
	return 0;
}

int main(int argc, char *argv[])
{
	int octets = 0;
	int offset = 0;
	LLVMDisasmContextRef DC;
	uint8_t buffer1[1024];
	uint8_t *buffer;
	size_t buffer_size = 0;
	uint8_t test_data[] = {0x0f, 0xb6, 0x75, 0xa0};
	int test_data_size = 4;

	LLVMInitializeAllTargetInfos();
	LLVMInitializeAllTargetMCs();
	LLVMInitializeAllAsmParsers();
	LLVMInitializeAllDisassemblers();

	struct dis_info_s *dis_info = LLVMCreateDisInfo();
	DC = LLVMCreateDisasm("x86_64-pc-linux-gnu", dis_info,
		0, &LLVMDecodeOpInfoCallback,
		NULL);
	if (!DC) {
		outs() << "LLVMCreateDisasm() failed\n";
		exit(1);
	}

	buffer_size = test_data_size;
	buffer = &(test_data[0]);
	octets = LLVMDisasmInstruction(DC, buffer,
		buffer_size, offset,
		(char *)buffer1, 1023);
	if (dis_info->size[0] == 1) {
		outs() << "Test passed\n";
	} else {
		outs() << "Test failed\n";
	}
	return 0;

}
