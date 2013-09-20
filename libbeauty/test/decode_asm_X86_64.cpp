
#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <stdio.h>
#include <llvm-c/Disassembler.h>

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
#include "decode_inst_disasm.h"
#include "decode_inst.h"
#include "opcodes.h"
//#include "decode_inst_helper.h"
#include "decode_asm_X86_64.h"


using namespace llvm;

struct dis_info_s {
	MCInst *Inst;
	int offset[16];
	int size[16];
};

int DecodeAsmOpInfoCallback(void *DisInfo, uint64_t PC,
                                  uint64_t Offset, uint64_t Size,
                                  int TagType, void *TagBuf) {
	struct dis_info_s *dis_info = (struct dis_info_s *) DisInfo;
	MCInst *Inst = dis_info->Inst;
	outs() << "DisInfo = " << DisInfo << "\n";
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


int DecodeAsmX86_64::setup() {

  // Initialize targets and assembly printers/parsers.
  // FIXME: Clients are responsible for initializing the targets. And this
  // would be done by calling routines in "llvm-c/Target.h" which are static
  // line functions. But the current use of LLVMCreateDecodeAsm() is to dynamically
  // load libLTO with dlopen() and then lookup the symbols using dlsym().
  // And since these initialize routines are static that does not work which
  // is why the call to them in this 'C' library API was added back.
//  llvm::InitializeAllTargetInfos();
//  llvm::InitializeAllTargetMCs();
//  llvm::InitializeAllAsmParsers();
//  llvm::InitializeAllDisassemblers();
	LLVMOpInfoCallback GetOpInfo = &(DecodeAsmOpInfoCallback);
//(void *, uint64_t,
//                                  uint64_t , uint64_t ,
//                                  int , void *));

	LLVMSymbolLookupCallback SymbolLookUp = NULL;
	int TagType = 0;

	TripleName = "x86_64-pc-linux-gnu";
	// Get the target.
	std::string Error;
//	TargetRegistry::printRegisteredTargetsForVersion();
	DecodeAsmX86_64::TheTarget = TargetRegistry::lookupTarget(TripleName, Error);
	if (!TheTarget)
		return 1;

	const MCRegisterInfo *MRI = TheTarget->createMCRegInfo(TripleName);
	if (!MRI)
		return 1;

	// Get the assembler info needed to setup the MCContext.
	const MCAsmInfo *MAI = TheTarget->createMCAsmInfo(*MRI, TripleName);
	if (!MAI)
		return 1;

	const MCInstrInfo *MII = TheTarget->createMCInstrInfo();
	if (!MII)
		return 1;

	int tmp = MII->getNumOpcodes();
	outs() << format("Number of opcodes = 0x%x\n", tmp);

	// Package up features to be passed to target/subtarget
	std::string FeaturesStr;
	std::string CPU;

	const MCSubtargetInfo *STI = TheTarget->createMCSubtargetInfo(TripleName, CPU,
                                                                FeaturesStr);
	if (!STI)
		return 1;

	// Set up the MCContext for creating symbols and MCExpr's.
	MCContext *Ctx = new MCContext(MAI, MRI, 0);
	if (!Ctx)
		return 1;

	// Set up disassembler.
	MCDisassembler *DisAsm = TheTarget->createMCDisassembler(*STI);
	if (!DisAsm)
		return 1;

	OwningPtr<MCRelocationInfo> RelInfo(
		TheTarget->createMCRelocationInfo(TripleName, *Ctx));
	if (!RelInfo)
		return 1;

//	OwningPtr<MCSymbolizer> Symbolizer(
//		TheTarget->createMCSymbolizer(TripleName, GetOpInfo, SymbolLookUp, DisInfo,
//			Ctx, RelInfo.take()));
	OwningPtr<MCSymbolizer> Symbolizer(
		TheTarget->createMCSymbolizer(TripleName, GetOpInfo, SymbolLookUp, DisInfo,
			Ctx, RelInfo.take()));
	DisAsm->setSymbolizer(Symbolizer);
	//DisAsm->setupForSymbolicDisassembly(GetOpInfo, SymbolLookUp, DisInfo, Ctx, RelInfo);
	DisAsm->setupForSymbolicDisassembly(GetOpInfo, SymbolLookUp, DisInfo, Ctx, RelInfo);

	// Set up the instruction printer.
	int AsmPrinterVariant = MAI->getAssemblerDialect();
	MCInstPrinter *IP = TheTarget->createMCInstPrinter(AsmPrinterVariant,
                                                     *MAI, *MII, *MRI, *STI);
	if (!IP)
		return 1;

	LLVMDisasmContext *DC = new LLVMDisasmContext(TripleName, DisInfo, TagType,
		GetOpInfo, SymbolLookUp,
		TheTarget, MAI, MRI,
		STI, MII, Ctx, DisAsm, IP);
	if (!DC)
		return 1;
	return 0;

}
