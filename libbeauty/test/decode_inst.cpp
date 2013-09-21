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

#include <stdint.h>
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
#include "decode_inst.h"
#include "opcodes.h"
#include "decode_asm_X86_64.h"

namespace llvm {
class Target;
} // namespace llvm
using namespace llvm;

void LLVMPrintTargets(void) {
	TargetRegistry::printRegisteredTargetsForVersion();
}

void LLVMDisasmInstructionPrint(int octets, uint8_t *buffer, int buffer_size, uint8_t *buffer1) {
		int n;
		outs() << format("LLVM DIS octets = 0x%x:", octets);
		if (octets > buffer_size) {
			octets = buffer_size;
		}
		for (n = 0; n < octets; n++) {
			outs() << format("%02x ", buffer[n] & 0xff);
		}
		outs() << format(":%s\n", buffer1);
}

LLVMDecodeAsmX86_64Ref LLVMNewDecodeAsmX86_64() {
	DecodeAsmX86_64 *da = new DecodeAsmX86_64();
	outs() << "LLVMDecodeAsmX86_64Ref = " << da << "\n";
	return (LLVMDecodeAsmX86_64Ref)da;
}

int LLVMSetupDecodeAsmX86_64(LLVMDecodeAsmX86_64Ref DCR) {
	DecodeAsmX86_64 *da = (DecodeAsmX86_64*)DCR;
	int tmp;
	outs() << "LLVMDecodeAsmX86_64Ref = " << da << "\n";
	tmp = da->setup();
	return tmp;
}

int LLVMInstructionDecodeAsmX86_64(LLVMDecodeAsmX86_64Ref DCR, uint8_t *Bytes,
		uint64_t BytesSize, uint64_t PC,
		struct instruction_low_level_s *ll_inst) {
	int tmp;
	DecodeAsmX86_64 *da = (DecodeAsmX86_64*)DCR;
	tmp = da->DecodeInstruction(Bytes,
		BytesSize, PC, ll_inst);
//	outs() << "DisInfo = " << da->DisInfo << "\n";
	return 0;
}

//
// LLVMDecodeAsmDispose() disposes of the disassembler specified by the context.
//
void LLVMDecodeAsmDispose(LLVMDecodeAsmX86_64Ref DCR){
	DecodeAsmX86_64 *da = (DecodeAsmX86_64*)DCR;
//FIXME: Get delete working
	//delete da;
}

#define KIND_EMPTY 0
#define KIND_REG 1
#define KIND_IMM 2
#define KIND_IND_REG 3
#define KIND_IND_IMM 4
#define KIND_IND_SCALE 5

#if 0
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

int LLVMDecodeAsmOpcodesSource(LLVMDecodeAsmContextRef DCR) {
	LLVMDisasmContext *DC = (LLVMDisasmContext *)DCR;
	const MCInstrInfo *MII = DC->getInstInfo();
	MCInstPrinter *IP = DC->getIP();
	StringRef Name;
	int n,m;
	int tmp;
	const char *opcode_name;
	int num_opcodes = MII->getNumOpcodes();
	int inst_helper_size = sizeof(decode_inst_helper) / sizeof(struct decode_inst_helper_s);
	struct decode_inst_helper_s *new_helper = (struct decode_inst_helper_s *)calloc(num_opcodes, sizeof(struct decode_inst_helper_s));
	if (!new_helper) {
		return 1;
	}
	for (n = 0; n < num_opcodes; n++) {
		int start;
		const MCInstrDesc Desc = MII->get(n);
		Name = IP->getOpcodeName(n);
		new_helper[n].mc_inst = Name.data();
		start = 0;
		if ((n < inst_helper_size) &&
			(0 == strcmp(Name.data(), decode_inst_helper[n].mc_inst))) {
			/* Small optimization if the table is not changing */
			start = n;
		}
		for (m = start; m < inst_helper_size; m++) {
			tmp = strcmp(Name.data(), decode_inst_helper[m].mc_inst);
			if (tmp == 0) {
				new_helper[n].opcode = decode_inst_helper[m].opcode;
				new_helper[n].predicate = decode_inst_helper[m].predicate;
				new_helper[n].srcA_size = decode_inst_helper[m].srcA_size;
				new_helper[n].srcB_size = decode_inst_helper[m].srcB_size;
				new_helper[n].dstA_size = decode_inst_helper[m].dstA_size;
				break;
			}
		}
	}
	
	for (n = 0; n < num_opcodes; n++) {
		/* OpcodeID, Operand, offset, size, Operand, offset, size, OpcodeName */
		outs() << format("	{ %s, ", helper_opcode_table[new_helper[n].opcode]);
		outs() << format("0x%x, ", new_helper[n].predicate);
		outs() << format("0x%x, ", new_helper[n].srcA_size);
		outs() << format("0x%x, ", new_helper[n].srcB_size);
		outs() << format("0x%x, ", new_helper[n].dstA_size);
		outs() << format("0x%x, ", 0);
		outs() << format("0x%x, ", 0);
		outs() << format("\"%s\" },  // 0x%04x\n",
			new_helper[n].mc_inst,
			n);
	};
	free (new_helper);
	return 0;
}
 
#endif

