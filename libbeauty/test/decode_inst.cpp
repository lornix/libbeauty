//===-- lib/MC/Disassembler.cpp - Disassembler Public C Interface ---------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

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

#include "X86BaseInfo.h"
#include "decode_inst_disasm.h"
#include "decode_inst.h"

namespace llvm {
class Target;
} // namespace llvm
using namespace llvm;

// LLVMCreateDecodeAsm() creates a disassembler for the TripleName.  Symbolic
// disassembly is supported by passing a block of information in the DisInfo
// parameter and specifying the TagType and callback functions as described in
// the header llvm-c/Disassembler.h .  The pointer to the block and the 
// functions can all be passed as NULL.  If successful, this returns a
// disassembler context.  If not, it returns NULL.
//
LLVMDecodeAsmContextRef LLVMCreateDecodeAsm(const char *TripleName, void *DisInfo,
                                      int TagType, LLVMOpInfoCallback GetOpInfo,
                                      LLVMSymbolLookupCallback SymbolLookUp) {
  // Initialize targets and assembly printers/parsers.
  // FIXME: Clients are responsible for initializing the targets. And this
  // would be done by calling routines in "llvm-c/Target.h" which are static
  // line functions. But the current use of LLVMCreateDecodeAsm() is to dynamically
  // load libLTO with dlopen() and then lookup the symbols using dlsym().
  // And since these initialize routines are static that does not work which
  // is why the call to them in this 'C' library API was added back.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();
  llvm::InitializeAllDisassemblers();

  // Get the target.
  std::string Error;
  const llvm::Target *TheTarget = TargetRegistry::lookupTarget(TripleName, Error);
  assert(TheTarget && "Unable to create target!");

  // Get the assembler info needed to setup the MCContext.
  const MCAsmInfo *MAI = TheTarget->createMCAsmInfo(TripleName);
  assert(MAI && "Unable to create target asm info!");

  const MCInstrInfo *MII = TheTarget->createMCInstrInfo();
  assert(MII && "Unable to create target instruction info!");

	int tmp = MII->getNumOpcodes();
	outs() << format("Number of opcodes = 0x%x\n", tmp);
  const MCRegisterInfo *MRI = TheTarget->createMCRegInfo(TripleName);
  assert(MRI && "Unable to create target register info!");

  // Package up features to be passed to target/subtarget
  std::string FeaturesStr;
  std::string CPU;

  const MCSubtargetInfo *STI = TheTarget->createMCSubtargetInfo(TripleName, CPU,
                                                                FeaturesStr);
  assert(STI && "Unable to create subtarget info!");

  // Set up the MCContext for creating symbols and MCExpr's.
  MCContext *Ctx = new MCContext(*MAI, *MRI, 0);
  assert(Ctx && "Unable to create MCContext!");

  // Set up disassembler.
  MCDisassembler *DisAsm = TheTarget->createMCDisassembler(*STI);
  assert(DisAsm && "Unable to create disassembler!");
  DisAsm->setupForSymbolicDisassembly(GetOpInfo, SymbolLookUp, DisInfo, Ctx);

  // Set up the instruction printer.
  int AsmPrinterVariant = MAI->getAssemblerDialect();
  MCInstPrinter *IP = TheTarget->createMCInstPrinter(AsmPrinterVariant,
                                                     *MAI, *MII, *MRI, *STI);
  assert(IP && "Unable to create instruction printer!");

  LLVMDisasmContext *DC = new LLVMDisasmContext(TripleName, DisInfo, TagType,
                                                GetOpInfo, SymbolLookUp,
                                                TheTarget, MAI, MRI,
                                                STI, MII, Ctx, DisAsm, IP);
  assert(DC && "Allocation failure!");

  return (LLVMDecodeAsmContextRef) DC;
}

//
// LLVMDecodeAsmDispose() disposes of the disassembler specified by the context.
//
void LLVMDecodeAsmDispose(LLVMDecodeAsmContextRef DCR){
  LLVMDisasmContext *DC = (LLVMDisasmContext *)DCR;
  delete DC;
}

namespace llvm {
//
// The memory object created by LLVMDecodeAsmInstruction().
//
class DecodeAsmMemoryObject : public llvm::MemoryObject {
  uint8_t *Bytes;
  uint64_t Size;
  uint64_t BasePC;
public:
  DecodeAsmMemoryObject(uint8_t *bytes, uint64_t size, uint64_t basePC) :
                     Bytes(bytes), Size(size), BasePC(basePC) {}
 
  uint64_t getBase() const { return BasePC; }
  uint64_t getExtent() const { return Size; }

  int readByte(uint64_t Addr, uint8_t *Byte) const {
    if (Addr - BasePC >= Size)
      return -1;
    *Byte = Bytes[Addr - BasePC];
    return 0;
  }
};
} // end anonymous namespace

//
// LLVMDecodeAsmInstruction() disassembles a single instruction using the
// disassembler context specified in the parameter DC.  The bytes of the
// instruction are specified in the parameter Bytes, and contains at least
// BytesSize number of bytes.  The instruction is at the address specified by
// the PC parameter.  If a valid instruction can be disassembled its string is
// returned indirectly in OutString which whos size is specified in the
// parameter OutStringSize.  This function returns the number of bytes in the
// instruction or zero if there was no valid instruction.  If this function
// returns zero the caller will have to pick how many bytes they want to step
// over by printing a .byte, .long etc. to continue.
//
size_t LLVMDecodeAsmInstruction(LLVMDecodeAsmContextRef DCR, uint8_t *Bytes,
                             uint64_t BytesSize, uint64_t PC, char *OutString,
                             size_t OutStringSize, uint64_t *opcode, const char **opcode_name, uint64_t *TSFlags){
  LLVMDisasmContext *DC = (LLVMDisasmContext *)DCR;
  int n;
  // Wrap the pointer to the Bytes, BytesSize and PC in a MemoryObject.
  llvm::DecodeAsmMemoryObject MemoryObject2(Bytes, BytesSize, PC);

	outs() << "DECODE INST\n";
  uint64_t Size;
  MCInst Inst;
  const MCDisassembler *DisAsm = DC->getDisAsm();
  MCInstPrinter *IP = DC->getIP();
  MCDisassembler::DecodeStatus S;
	if (Bytes[0] == 0) {
		outs() << "Bytes reset to 0\n";
		exit(1);
	}
  S = DisAsm->getInstruction(Inst, Size, MemoryObject2, PC,
                             /*REMOVE*/ nulls(), DC->CommentStream);
  switch (S) {
  case MCDisassembler::Fail:
  case MCDisassembler::SoftFail:
    // FIXME: Do something different for soft failure modes?
    return 0;

  case MCDisassembler::Success: {
	StringRef Name;
	StringRef Reg;
	DC->CommentStream.flush();
	StringRef Comments = DC->CommentsToEmit.str();

	SmallVector<char, 64> InsnStr;
	InsnStr.empty();
	raw_svector_ostream OS(InsnStr);
	OS.flush();
	SmallVector<char, 64> RegStr;
	RegStr.empty();
	const MCInstrInfo *MII = DC->getInstInfo();
	int num_opcodes = MII->getNumOpcodes();
	*opcode = Inst.getOpcode();
	const MCInstrDesc Desc = MII->get(*opcode);
	*TSFlags = Desc.TSFlags;
	int opcode_form = *TSFlags & X86II::FormMask;
	Name = IP->getOpcodeName(Inst.getOpcode());
	*opcode_name = Name.data();
	outs() << "Opcode name: " << *opcode_name << "\n";
	int num_operands = Inst.getNumOperands();
	outs() << format("opcode_form = 0x%x", opcode_form) << format(", num_operands = 0x%x", num_operands) << "\n";
	MCOperand *Operand;
	switch (opcode_form) {
	default:
		outs() << "Unrecognised form\n";
		break;
	case 6:
		if (num_operands != 6) {
			outs() << "Unrecognised num_operands\n";
			break;
		}

	}
	for (n = 0; n < num_operands; n++) {
		Operand = &Inst.getOperand(n);
		outs() << "Operand = " << Operand << "\n";
		outs() << "Valid = " << Operand->isValid(); 
		outs() << ",isReg = " << Operand->isReg();
		outs() << ",isImm = " << Operand->isImm();
		outs() << ",isFPImm = " << Operand->isFPImm();
		outs() << ",isExpr = " << Operand->isExpr();
		outs() << "isInst = " << Operand->isInst() << "\n";
		//outs() << format("Operand.Kind = 0x%x\n", Operand->Kind);
		if (Operand->isImm()) {
			outs() << format("Imm = 0x%lx, ", Operand->getImm());
			int size_of_imm = X86II::getSizeOfImm(*TSFlags);
			outs() << format("sizeof(Imm) = 0x%x", size_of_imm) << "\n";
		}
		if (Operand->isReg()) {
			uint32_t reg;
			reg = Operand->getReg();
			outs() << format("Reg = 0x%x\n", reg);
			if (reg) {
				std::string Buf2;
				raw_string_ostream OS2(Buf2);
				IP->printRegName(OS2, reg);
				OS2.flush();
				Reg = OS2.str();
				outs() << "Reg: " << Reg << "\n";
			}
		}
	}
	SmallVector<char, 6400> Buffer2;
	raw_svector_ostream OS3(Buffer2);
	Inst.dump_pretty(OS3);
	OS3.flush();
	

	// Tell the comment stream that the vector changed underneath it.
	DC->CommentsToEmit.clear();
	DC->CommentStream.resync();

	assert(OutStringSize != 0 && "Output buffer cannot be zero size");
	size_t OutputSize = std::min(OutStringSize-1, InsnStr.size());
	std::memcpy(OutString, InsnStr.data(), OutputSize);
	OutString[OutputSize] = '\0'; // Terminate string.
	if (Bytes[0] == 0) {
		outs() << "Bytes reset to 0\n";
		exit(1);
	}

	return Size;
	}
  }
  llvm_unreachable("Invalid DecodeStatus!");
}

LLVMDecodeAsmMIIRef LLVMDecodeAsmGetMII(LLVMDecodeAsmContextRef DCR) {
	LLVMDisasmContext *DC = (LLVMDisasmContext *)DCR;
	return (LLVMDecodeAsmMIIRef) DC->getInstInfo();
}

int LLVMDecodeAsmGetNumOpcodes(LLVMDecodeAsmContextRef DCR) {
	LLVMDisasmContext *DC = (LLVMDisasmContext *)DCR;
	const MCInstrInfo *MII = DC->getInstInfo();
	int num_opcodes = MII->getNumOpcodes();
	return num_opcodes;
}

uint64_t LLVMDecodeAsmGetTSFlags(LLVMDecodeAsmContextRef DCR, uint64_t opcode) {
	LLVMDisasmContext *DC = (LLVMDisasmContext *)DCR;
	const MCInstrInfo *MII = DC->getInstInfo();
	const MCInstrDesc Desc = MII->get(opcode);
	uint64_t TSFlags = Desc.TSFlags;
	outs() << format("OpcodeByteShift = 0x%lx:0x%x\n", (int)X86II::OpcodeShift, X86II::getBaseOpcodeFor(TSFlags));
	outs() << format("OpSizeMask = 0x%lx:0x%lx\n", (int)X86II::OpSize, TSFlags & X86II::OpSize);
	outs() << format("AdSizeMask = 0x%lx:0x%lx\n", (int)X86II::AdSize, TSFlags & X86II::AdSize);
	outs() << format("Op0Mask = 0x%lx:0x%lx\n", (int)X86II::Op0Mask, (TSFlags & X86II::Op0Mask) >> X86II::Op0Shift);
	outs() << format("REX_W_Mask = 0x%lx:0x%lx\n", (int)X86II::REX_W, (TSFlags & X86II::REX_W) >> X86II::REXShift);
	outs() << format("Imm_Mask = 0x%lx:0x%lx\n", (int)X86II::ImmMask, (TSFlags & X86II::ImmMask) >> X86II::ImmShift);
	outs() << format("FormMask = 0x%lx:0x%lx\n", (int)X86II::FormMask, TSFlags & X86II::FormMask);
	return TSFlags;
}

int LLVMDecodeAsmPrintOpcodes(LLVMDecodeAsmContextRef DCR) {
	LLVMDisasmContext *DC = (LLVMDisasmContext *)DCR;
	const MCInstrInfo *MII = DC->getInstInfo();
	MCInstPrinter *IP = DC->getIP();
	StringRef Name;
	const char *opcode_name;
	int num_opcodes = MII->getNumOpcodes();
	int n;
	for (n = 0; n < num_opcodes; n++) {
		const MCInstrDesc Desc = MII->get(n);
		uint64_t TSFlags = Desc.TSFlags;
		outs() << format("n = 0x%x:", n);
		Name = IP->getOpcodeName(n);
		opcode_name = Name.data();
		outs() << format("opcode_name = %p:%s, 0x%lx\n", Name.data(), opcode_name, TSFlags);
	};
	return 0;
}

