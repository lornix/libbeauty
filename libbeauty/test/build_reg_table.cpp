#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <string>
#include "llvm/ADT/OwningPtr.h"
#include "llvm/ADT/SmallString.h"
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

namespace llvm {

int build_reg_table() {
	std::string buf;
	llvm::StringRef reg_name;
	int n;
	int tmp;

	MCInst *inst = new MCInst;

	LLVMSymbolLookupCallback SymbolLookUp = NULL;

	std::string TripleName = "x86_64-pc-linux-gnu";
	// Get the target.
	std::string Error;
	//TargetRegistry::printRegisteredTargetsForVersion();
	const llvm::Target *TheTarget = llvm::TargetRegistry::lookupTarget(TripleName, Error);
	if (!TheTarget)
		return 1;

	//outs() << TheTarget;

	const MCRegisterInfo *MRI = TheTarget->createMCRegInfo(TripleName);
	if (!MRI)
		return 2;

	// Get the assembler info needed to setup the MCContext.
	const MCAsmInfo *MAI = TheTarget->createMCAsmInfo(*MRI, TripleName);
	if (!MAI)
		return 3;

	const MCInstrInfo *MII = TheTarget->createMCInstrInfo();
	if (!MII)
		return 4;

	tmp = MII->getNumOpcodes();
	//outs() << format("Number of opcodes = 0x%x\n", tmp);

	// Package up features to be passed to target/subtarget
	std::string FeaturesStr;
	std::string CPU;

	const MCSubtargetInfo *STI = TheTarget->createMCSubtargetInfo(TripleName, CPU,
                                                                FeaturesStr);
	if (!STI)
		return 5;

	// Set up the MCContext for creating symbols and MCExpr's.
	MCContext *Ctx = new MCContext(MAI, MRI, 0);
	if (!Ctx)
		return 6;

	// Set up disassembler.
	MCDisassembler *DisAsm = TheTarget->createMCDisassembler(*STI);
	if (!DisAsm)
		return 7;

	OwningPtr<MCRelocationInfo> RelInfo(
		TheTarget->createMCRelocationInfo(TripleName, *Ctx));
	if (!RelInfo)
		return 8;

	LLVMOpInfoCallback GetOpInfo = NULL;
	void *DisInfo = NULL;
	OwningPtr<MCSymbolizer> Symbolizer(
		TheTarget->createMCSymbolizer(TripleName, GetOpInfo, SymbolLookUp, DisInfo,
			Ctx, RelInfo.take()));
	//DisAsm->setSymbolizer(Symbolizer);
	//DisAsm->setupForSymbolicDisassembly(GetOpInfo, SymbolLookUp, DisInfo, Ctx, RelInfo);

	// Set up the instruction printer.
	int AsmPrinterVariant = MAI->getAssemblerDialect();
	MCInstPrinter *IP = TheTarget->createMCInstPrinter(AsmPrinterVariant,
                                                     *MAI, *MII, *MRI, *STI);
	if (!IP)
		return 9;

	llvm::raw_string_ostream OS(buf);
	OS.SetUnbuffered();
	for (n = 1; n < 233; n++) {
		buf.clear();  /* Clears the OS2 buffer */
		IP->printRegName(OS, n);
		reg_name = OS.str();
		llvm::outs() << llvm::format("Reg:0x%x:", n);
		llvm::outs() << reg_name << "\n";
	}
	return 0;
}

}

int main()
{
	int tmp;
	LLVMInitializeX86TargetInfo();
	LLVMInitializeX86TargetMC();
	LLVMInitializeX86AsmParser();
	LLVMInitializeX86Disassembler();
	tmp = llvm::build_reg_table();
	if (tmp) {
		llvm::outs() << llvm::format("tmp = 0x%x\n", tmp);
	}
	return 0;
}

