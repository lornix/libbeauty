
#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <stdarg.h>
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
#include "instruction_low_level.h"
#include "decode_inst.h"
#include "opcodes.h"
#include "decode_inst_helper.h"
#include "decode_asm_X86_64.h"
#include "rev.h"

namespace llvm {

int DecodeAsmOpInfoCallback(void *DisInfo, uint64_t PC,
                                  uint64_t Offset, uint64_t Size,
                                  int TagType, void *TagBuf) {
	struct dis_info_s *dis_info = (struct dis_info_s *) DisInfo;
	llvm::MCInst *Inst = dis_info->Inst;
	llvm::outs() << "DisInfo = " << DisInfo << "\n";
	int num_operands = Inst->getNumOperands();
	if (num_operands >= 16) {
		llvm::outs() << "num_operands >= 16\n";
		exit(1);
	}
	dis_info->offset[num_operands] = Offset;
	dis_info->size[num_operands] = Size;
	llvm::outs() << format("NumOperands = 0x%x, ", num_operands) << format("Offset = 0x%x, ", Offset) << format("Size = 0x%x", Size) << "\n";
	return 0;
}


int DecodeAsmX86_64::setup() {
	int tmp;
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

	MCInst *inst = new MCInst;
	DisInfo = (struct dis_info_s*) calloc (1, sizeof (struct dis_info_s));
	DisInfo->Inst = inst;
//	DebugFlag = true;
//	EnableDebugBuffering = true;

	LLVMOpInfoCallback GetOpInfo = &(DecodeAsmOpInfoCallback);
	LLVMSymbolLookupCallback SymbolLookUp = NULL;
	int TagType = 0;

	TripleName = "x86_64-pc-linux-gnu";
	// Get the target.
	std::string Error;
//	TargetRegistry::printRegisteredTargetsForVersion();
	DecodeAsmX86_64::TheTarget = llvm::TargetRegistry::lookupTarget(TripleName, Error);
	if (!TheTarget)
		return 1;

	/* FIXME: TheTarget */
	debug_print(DEBUG_INPUT_DIS, 1, "TheTarget = 0x%" PRIx64 "\n", TheTarget);

	const MCRegisterInfo *MRI = TheTarget->createMCRegInfo(TripleName);
	if (!MRI)
		return 1;

	// Get the assembler info needed to setup the MCContext.
	const MCAsmInfo *MAI = TheTarget->createMCAsmInfo(*MRI, TripleName);
	if (!MAI)
		return 1;

	MII = TheTarget->createMCInstrInfo();
	if (!MII)
		return 1;

	tmp = MII->getNumOpcodes();
	debug_print(DEBUG_INPUT_DIS, 1, "Number of opcodes = 0x%x\n", tmp);

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
	DisAsm = TheTarget->createMCDisassembler(*STI);
	if (!DisAsm)
		return 1;

	OwningPtr<MCRelocationInfo> RelInfo(
		TheTarget->createMCRelocationInfo(TripleName, *Ctx));
	if (!RelInfo)
		return 1;

	std::unique_ptr<MCSymbolizer> Symbolizer(
		TheTarget->createMCSymbolizer(TripleName, GetOpInfo, SymbolLookUp, DisInfo,
			Ctx, RelInfo.take()));
	//DisAsm->setSymbolizer(Symbolizer);
	//DisAsm->setupForSymbolicDisassembly(GetOpInfo, SymbolLookUp, DisInfo, Ctx, RelInfo);

	// Set up the instruction printer.
	int AsmPrinterVariant = MAI->getAssemblerDialect();
	IP = TheTarget->createMCInstPrinter(AsmPrinterVariant,
                                                     *MAI, *MII, *MRI, *STI);
	if (!IP)
		return 1;

	StringRef Name;
	int n,m;
	const char *opcode_name;
	int num_opcodes = MII->getNumOpcodes();
	int inst_helper_size = sizeof(decode_inst_helper) / sizeof(struct decode_inst_helper_s);
	new_helper = (struct decode_inst_helper_s *)calloc(num_opcodes, sizeof(struct decode_inst_helper_s));
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
	


	return 0;

}

int DecodeAsmX86_64::get_reg_size_helper(int value, int *reg_index) {
	std::string buf;
	std::string buf2;
	StringRef reg_name;
	int helper_size = sizeof(helper_reg_table) / sizeof(struct helper_reg_table_s);
	int n;
	int tmp;
	raw_string_ostream OS(buf);
	raw_string_ostream OS2(buf2);
	OS.SetUnbuffered();
	OS2.SetUnbuffered();
	//outs() << format("get_reg_size_helper value = 0x%x\n", value);
	if (value == 0) {
		return 1;
	}
	IP->printRegName(OS, value);
	OS.flush();
	reg_name = OS.str();
	for (n = 0; n < helper_size; n++) {
		tmp = strcmp(reg_name.data(),helper_reg_table[n].reg_name);
		if (tmp == 0) {
//			outs() << n << ":";
//			outs() << helper_reg_table[n].reg_name << ", ";
//			outs() << helper_reg_table[n].size << ", ";
//			outs() << helper_reg_table[n].reg_number << "\n";
			*reg_index = n;
			return 0;
		}
	}
	outs() << format("ERROR: get_reg_size_helper Unknown reg value = 0x%x\n", value);
#if 0
	for (n = 1; n < 233; n++) {
		outs() << format("Reg:0x%x\n", n);
		buf2.clear();  /* Clears the OS2 buffer */
		IP->printRegName(OS2, n);
		reg_name = OS2.str();
		outs() << reg_name << "\n";
	}
#endif
	exit(1);

	return 1;
}


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

int llvm::DecodeAsmX86_64::copy_operand(struct operand_low_level_s *src, struct operand_low_level_s *dst) {
	int n;
	dst->kind = src->kind;
	dst->size = src->size;
	for (n = 0; n < 16; n++) {
		dst->operand[n].value = src->operand[n].value;
		dst->operand[n].size = src->operand[n].size;
		dst->operand[n].offset = src->operand[n].offset;
	}
	return 0;
}

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
int llvm::DecodeAsmX86_64::DecodeInstruction(uint8_t *Bytes,
                             uint64_t BytesSize, uint64_t PC,
                             struct instruction_low_level_s *ll_inst) {
	int n;
	int result = 1;
	int rep = 0;
	int rep_inst = 0;
	// Wrap the pointer to the Bytes, BytesSize and PC in a MemoryObject.
	llvm::DecodeAsmMemoryObject MemoryObject2(Bytes, BytesSize, 0);

	debug_print(DEBUG_INPUT_DIS, 1, "DECODE INST\n");
	if (PC > BytesSize) {
		outs() << "Buffer overflow\n";
		return 1;
	}
	debug_print(DEBUG_INPUT_DIS, 1, "PC = 0x%lx\n", PC);
	uint64_t Size = 0;
	struct dis_info_s *dis_info = (struct dis_info_s *) DisInfo;
	MCInst *Inst = dis_info->Inst;
	Inst->clear();
	for (n = 0; n < 16; n++) {
		dis_info->offset[n] = 0;
		dis_info->size[n] = 0;
	}
	MCDisassembler::DecodeStatus S;
//	if (Bytes[PC] == 0) {
//		outs() << "Bytes reset to 0\n";
//		return 1;
//	}
	/* rep_inst is set if the instruction is in the
	 * group of ones that can have REP in front of them
	 */
	/* Check that the 2 bytes (PC and PC + 1) are inside the buffer */
	if (PC < BytesSize - 1) {
		if (Bytes[PC + 1] == 0x48) {
			rep_inst = 1;
		}
		if (Bytes[PC] == 0xf3 && rep_inst) {
			/* FIXME: Implement */
			debug_print(DEBUG_INPUT_DIS, 1, "REPZ\n");
			rep = 1;
			PC++;
		}
		if (Bytes[PC] == 0xf2 && rep_inst) {
			/* FIXME: Implement */
			outs() << "REPNZ\n";
			rep = 2;
			PC++;
		}
	}

	S = DisAsm->getInstruction(*Inst, Size, MemoryObject2, PC,
		/*REMOVE*/ nulls(), nulls());
	if (rep > 0) {
		Size++;
	}
	printf("getInstruction Size = 0x%lx\n", Size);
	if (S != MCDisassembler::Success) {
	// case MCDisassembler::Fail:
	// case MCDisassembler::SoftFail:
		// FIXME: Do something different for soft failure modes?
		return 1;
	}

	// case MCDisassembler::Success: {
	StringRef Name;
	StringRef Reg;
	StringRef RegCL = "CL";
	uint64_t value = 0;
	//DC->CommentStream.flush();
	//StringRef Comments = DC->CommentsToEmit.str();

	SmallVector<char, 64> InsnStr;
	InsnStr.empty();
	raw_svector_ostream OS(InsnStr);
	OS.flush();
	SmallVector<char, 64> RegStr;
	RegStr.empty();
	int num_opcodes = MII->getNumOpcodes();
	int opcode = Inst->getOpcode();
	const MCInstrDesc Desc = MII->get(opcode);
	int TSFlags = Desc.TSFlags;
	int opcode_form = TSFlags & X86II::FormMask;
	Name = IP->getOpcodeName(opcode);
	const char *opcode_name = Name.data();
	debug_print(DEBUG_INPUT_DIS, 1, "0x%lx:Opcode 0x%x, %x\n", PC, opcode, new_helper[opcode].opcode);
	debug_print(DEBUG_INPUT_DIS, 1, "Opcode Name: %s\n", opcode_name);
	ll_inst->opcode = new_helper[opcode].opcode;
	ll_inst->address = PC;
	ll_inst->octets = Size;
	ll_inst->rep = rep;
	ll_inst->predicate = new_helper[opcode].predicate;
	ll_inst->srcA.size = new_helper[opcode].srcA_size;
	ll_inst->srcB.size = new_helper[opcode].srcB_size;
	ll_inst->dstA.size = new_helper[opcode].dstA_size;
	int num_operands = Inst->getNumOperands();
	debug_print(DEBUG_INPUT_DIS, 1, "opcode_form = 0x%x, num_operands = 0x%x\n", opcode_form, num_operands);
	MCOperand *Operand;
	switch (opcode_form) {
	case 1: // RawFrm
		switch (num_operands) {
		case 0:
			ll_inst->srcA.kind = KIND_EMPTY;
			ll_inst->srcB.kind = KIND_EMPTY;
			ll_inst->dstA.kind = KIND_EMPTY;
			result = 0;
			break;
		case 1:
			ll_inst->dstA.kind = KIND_REG;
			ll_inst->dstA.operand[0].value = REG_AX;
			ll_inst->dstA.operand[0].size = ll_inst->dstA.size;
			ll_inst->dstA.operand[0].offset = 0;
			ll_inst->srcA.kind = KIND_REG;
			ll_inst->srcA.operand[0].value = REG_AX;
			ll_inst->srcA.operand[0].size = ll_inst->srcA.size;
			ll_inst->srcA.operand[0].offset = 0;
			debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 reg = al\n");
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				value = Operand->getImm();
				ll_inst->srcB.kind = KIND_IMM;
				ll_inst->srcB.operand[0].value = value;
				ll_inst->srcB.operand[0].size = dis_info->size[0] * 8;
				ll_inst->srcB.operand[0].offset = dis_info->offset[0];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Imm = 0x%lx\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[0], dis_info->size[0], Bytes[dis_info->offset[0]]);
			result = 0;
			}
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;
	case 2: // AddRegFrm
		switch (num_operands) {
		case 1:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				result = 0;
			}
			break;
		case 2:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->dstA.kind = KIND_REG;
				ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->dstA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcB.kind = KIND_IMM;
				ll_inst->srcB.operand[0].value = value;
				ll_inst->srcB.operand[0].size = dis_info->size[1] * 8;
				ll_inst->srcB.operand[0].offset = dis_info->offset[1];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 index multiplier Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[2]]);
			}
			result = 0;
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;
	case 3: // MRMDestReg
		switch (num_operands) {
		case 2:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->dstA.kind = KIND_REG;
				ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->dstA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcB.kind = KIND_REG;
				ll_inst->srcB.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcB.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcB.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			result = 0;
			break;
		case 3:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->dstA.kind = KIND_REG;
				ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->dstA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcB.kind = KIND_REG;
				ll_inst->srcB.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcB.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcB.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			result = 0;
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;
	case 4: //  MRMDestMem 
		ll_inst->srcA.kind = KIND_IND_SCALE;
		Operand = &Inst->getOperand(0);
		if (Operand->isValid() &&
			Operand->isReg() ) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
			ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
			ll_inst->srcA.operand[0].offset = 0;
			debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 pointer Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
				value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
		}
		Operand = &Inst->getOperand(1);
		if (Operand->isValid() &&
			Operand->isImm() ) {
			uint32_t value;
			value = Operand->getImm();
			ll_inst->srcA.operand[1].value = value;
			ll_inst->srcA.operand[1].size = dis_info->size[1] * 8;
			ll_inst->srcA.operand[1].offset = dis_info->offset[1];
			debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 index multiplier Imm = 0x%x\n", value);
			debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
				dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
		}
		Operand = &Inst->getOperand(2);
		if (Operand->isValid() &&
			Operand->isReg() ) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			ll_inst->srcA.operand[2].value = helper_reg_table[reg_index].reg_number;
			ll_inst->srcA.operand[2].size = helper_reg_table[reg_index].size;
			ll_inst->srcA.operand[2].offset = 0;
			debug_print(DEBUG_INPUT_DIS, 1, "SRC0.2 index Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
				value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
		}
		Operand = &Inst->getOperand(3);
		if (Operand->isValid() &&
			Operand->isImm() ) {
			int64_t value;
			value = Operand->getImm();
			ll_inst->srcA.operand[3].value = value;
			ll_inst->srcA.operand[3].size = dis_info->size[3] * 8;
			ll_inst->srcA.operand[3].offset = dis_info->offset[3];
			debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 offset Imm  = 0x%lx\n", value);
			debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
				dis_info->offset[3], dis_info->size[3], Bytes[dis_info->offset[3]]);
		}
		Operand = &Inst->getOperand(4);
		if (Operand->isValid() &&
			Operand->isReg() ) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			ll_inst->srcA.operand[4].value = helper_reg_table[reg_index].reg_number;
			ll_inst->srcA.operand[4].size = helper_reg_table[reg_index].size;
			ll_inst->srcA.operand[4].offset = 0;
			debug_print(DEBUG_INPUT_DIS, 1, "SRC0.4 unknown Reg  = 0x%x\n", value);
		}
		Operand = &Inst->getOperand(5);
		if (Operand->isValid() &&
			Operand->isReg() ) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			ll_inst->srcB.kind = KIND_REG;
			ll_inst->srcB.operand[0].value = helper_reg_table[reg_index].reg_number;
			ll_inst->srcB.operand[0].size = helper_reg_table[reg_index].size;
			ll_inst->srcB.operand[0].offset = 0;
			debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
				value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
		}
		copy_operand(&(ll_inst->srcA), &(ll_inst->dstA));
		debug_print(DEBUG_INPUT_DIS, 1, "DST0 = SRC0\n");
		result = 0;
		break;
	case 5: // MRMSrcReg
		switch (num_operands) {
		case 2:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->dstA.kind = KIND_REG;
				ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->dstA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcB.kind = KIND_REG;
				ll_inst->srcB.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcB.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcB.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			result = 0;
			break;
		case 3:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->dstA.kind = KIND_REG;
				ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->dstA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcB.kind = KIND_REG;
				ll_inst->srcB.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcB.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcB.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcA.kind = KIND_IMM;
				ll_inst->srcA.operand[0].value = value;
				ll_inst->srcA.operand[0].size = dis_info->size[2] * 8;
				ll_inst->srcA.operand[0].offset = dis_info->offset[2];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[2], dis_info->size[2], Bytes[dis_info->offset[2]]);
			}
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(2);
			result = 0;
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;
	case 6: // MRMSrcMem
		switch (num_operands) {
		case 6:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->dstA.kind = KIND_REG;
				ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->dstA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			if (ll_inst->opcode == H_LEA) {
				ll_inst->srcB.kind = KIND_SCALE;
			} else {
				ll_inst->srcB.kind = KIND_IND_SCALE;
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcB.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcB.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcB.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcB.operand[1].value = value;
				ll_inst->srcB.operand[1].size = dis_info->size[2] * 8;
				ll_inst->srcB.operand[1].offset = dis_info->offset[2];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.1 index multiplier Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[2], dis_info->size[2], Bytes[dis_info->offset[2]]);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcB.operand[2].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcB.operand[2].size = helper_reg_table[reg_index].size;
				ll_inst->srcB.operand[2].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.2 index Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				int64_t value;
				value = Operand->getImm();
				ll_inst->srcB.operand[3].value = value;
				ll_inst->srcB.operand[3].size = dis_info->size[4] * 8;
				ll_inst->srcB.operand[3].offset = dis_info->offset[4];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.3 offset Imm  = 0x%lx\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.3 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[4], dis_info->size[4], Bytes[dis_info->offset[4]]);
			}
			Operand = &Inst->getOperand(5);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcB.operand[4].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcB.operand[4].size = helper_reg_table[reg_index].size;
				ll_inst->srcB.operand[4].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.4 Segment Reg  = 0x%x\n", value);
			}
			result = 0;
			break;
		case 7:
			switch (ll_inst->opcode) {
			case IMUL:
				Operand = &Inst->getOperand(0);
				if (Operand->isValid() &&
					Operand->isReg()) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->dstA.kind = KIND_REG;
					ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
					ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
					ll_inst->dstA.operand[0].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
						value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				}
				ll_inst->srcB.kind = KIND_IND_SCALE;
				Operand = &Inst->getOperand(1);
				if (Operand->isValid() &&
					Operand->isReg() ) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->srcB.operand[0].value = helper_reg_table[reg_index].reg_number;
					ll_inst->srcB.operand[0].size = helper_reg_table[reg_index].size;
					ll_inst->srcB.operand[0].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 pointer Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
						value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				}
				Operand = &Inst->getOperand(2);
				if (Operand->isValid() &&
					Operand->isImm() ) {
					uint32_t value;
					value = Operand->getImm();
					ll_inst->srcB.operand[1].value = value;
					ll_inst->srcB.operand[1].size = dis_info->size[2] * 8;
					ll_inst->srcB.operand[1].offset = dis_info->offset[2];
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.1 index multiplier Imm = 0x%x\n", value);
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
						dis_info->offset[2], dis_info->size[2], Bytes[dis_info->offset[2]]);
				}
				Operand = &Inst->getOperand(3);
				if (Operand->isValid() &&
					Operand->isReg() ) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->srcB.operand[2].value = helper_reg_table[reg_index].reg_number;
					ll_inst->srcB.operand[2].size = helper_reg_table[reg_index].size;
					ll_inst->srcB.operand[2].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.2 index Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
						value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				}
				Operand = &Inst->getOperand(4);
				if (Operand->isValid() &&
					Operand->isImm() ) {
					int64_t value;
					value = Operand->getImm();
					ll_inst->srcB.operand[3].value = value;
					ll_inst->srcB.operand[3].size = dis_info->size[4] * 8;
					ll_inst->srcB.operand[3].offset = dis_info->offset[4];
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.3 offset Imm  = 0x%lx\n", value);
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.3 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
						dis_info->offset[5], dis_info->size[5], Bytes[dis_info->offset[5]]);
				}
				Operand = &Inst->getOperand(5);
				if (Operand->isValid() &&
					Operand->isReg() ) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->srcB.operand[4].value = helper_reg_table[reg_index].reg_number;
					ll_inst->srcB.operand[4].size = helper_reg_table[reg_index].size;
					ll_inst->srcB.operand[4].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.4 Segment Reg  = 0x%x\n", value);
				}
				Operand = &Inst->getOperand(6);
				if (Operand->isValid() &&
					Operand->isImm() ) {
					uint32_t value;
					value = Operand->getImm();
					ll_inst->srcA.kind = KIND_IMM;
					ll_inst->srcA.operand[0].value = value;
					ll_inst->srcA.operand[0].size = dis_info->size[6] * 8;
					ll_inst->srcA.operand[0].offset = dis_info->offset[6];
					debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 index multiplier Imm = 0x%x\n", value);
					debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
						dis_info->offset[6], dis_info->size[6], Bytes[dis_info->offset[6]]);
				}
				Operand = &Inst->getOperand(3);
				result = 0;
				break;
			default:
				Operand = &Inst->getOperand(0);
				if (Operand->isValid() &&
					Operand->isReg()) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->dstA.kind = KIND_REG;
					ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
					ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
					ll_inst->dstA.operand[0].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
						value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				}
				Operand = &Inst->getOperand(1);
				if (Operand->isValid() &&
					Operand->isReg()) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->srcA.kind = KIND_REG;
					ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
					ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
					ll_inst->srcA.operand[0].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
						value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				}
				ll_inst->srcB.kind = KIND_IND_SCALE;
				Operand = &Inst->getOperand(2);
				if (Operand->isValid() &&
					Operand->isReg() ) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->srcB.operand[0].value = helper_reg_table[reg_index].reg_number;
					ll_inst->srcB.operand[0].size = helper_reg_table[reg_index].size;
					ll_inst->srcB.operand[0].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 pointer Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
						value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				}
				Operand = &Inst->getOperand(3);
				if (Operand->isValid() &&
					Operand->isImm() ) {
					uint32_t value;
					value = Operand->getImm();
					ll_inst->srcB.operand[1].value = value;
					ll_inst->srcB.operand[1].size = dis_info->size[3] * 8;
					ll_inst->srcB.operand[1].offset = dis_info->offset[3];
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.1 index multiplier Imm = 0x%x\n", value);
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
						dis_info->offset[2], dis_info->size[2], Bytes[dis_info->offset[2]]);
				}
				Operand = &Inst->getOperand(4);
				if (Operand->isValid() &&
					Operand->isReg() ) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->srcB.operand[2].value = helper_reg_table[reg_index].reg_number;
					ll_inst->srcB.operand[2].size = helper_reg_table[reg_index].size;
					ll_inst->srcB.operand[2].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.2 index Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
						value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				}
				Operand = &Inst->getOperand(5);
				if (Operand->isValid() &&
					Operand->isImm() ) {
					int64_t value;
					value = Operand->getImm();
					ll_inst->srcB.operand[3].value = value;
					ll_inst->srcB.operand[3].size = dis_info->size[5] * 8;
					ll_inst->srcB.operand[3].offset = dis_info->offset[5];
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.3 offset Imm  = 0x%lx\n", value);
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.3 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
						dis_info->offset[5], dis_info->size[5], Bytes[dis_info->offset[5]]);
				}
				Operand = &Inst->getOperand(6);
				if (Operand->isValid() &&
					Operand->isReg() ) {
					uint32_t value;
					int reg_index = 0;
					int tmp;
					value = Operand->getReg();
					tmp = get_reg_size_helper(value, &reg_index);
					ll_inst->srcB.operand[4].value = helper_reg_table[reg_index].reg_number;
					ll_inst->srcB.operand[4].size = helper_reg_table[reg_index].size;
					ll_inst->srcB.operand[4].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.4 Segment Reg  = 0x%x\n", value);
				}
				result = 0;
				break;
			}
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;
	case 0x0a: // RawFrmDstSrc
		switch (num_operands) {
		case 3:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->dstA.kind = KIND_REG;
				ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->dstA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			/* Operand 2 not used yet */
			Operand = &Inst->getOperand(2);
			result = 0;
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;

	case 0x0f: // MRMXm
		switch (num_operands) {
		case 5:
			ll_inst->srcA.kind = KIND_IND_SCALE;
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 pointer Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcA.operand[1].value = value;
				ll_inst->srcA.operand[1].size = dis_info->size[1] * 8;
				ll_inst->srcA.operand[1].offset = dis_info->offset[1];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 index multiplier Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[2].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[2].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[2].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.2 index Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				int64_t value;
				value = Operand->getImm();
				ll_inst->srcA.operand[3].value = value;
				ll_inst->srcA.operand[3].size = dis_info->size[3] * 8;
				ll_inst->srcA.operand[3].offset = dis_info->offset[3];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 offset Imm  = 0x%lx\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[3], dis_info->size[3], Bytes[dis_info->offset[3]]);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[4].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[4].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[4].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.4 segment Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			result = 0;
			break;
		case 6:
			ll_inst->srcA.kind = KIND_IND_SCALE;
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 pointer Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcA.operand[1].value = value;
				ll_inst->srcA.operand[1].size = dis_info->size[1] * 8;
				ll_inst->srcA.operand[1].offset = dis_info->offset[1];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 index multiplier Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[2].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[2].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[2].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.2 index Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				int64_t value;
				value = Operand->getImm();
				ll_inst->srcA.operand[3].value = value;
				ll_inst->srcA.operand[3].size = dis_info->size[3] * 8;
				ll_inst->srcA.operand[3].offset = dis_info->offset[3];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 offset Imm  = 0x%lx\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[3], dis_info->size[3], Bytes[dis_info->offset[3]]);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[4].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[4].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[4].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.4 unknown Reg  = 0x%x\n", value);
			}
			Operand = &Inst->getOperand(5);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				int64_t value;
				value = Operand->getImm();
				ll_inst->srcB.kind = KIND_IMM;
				ll_inst->srcB.operand[0].value = value;
				ll_inst->srcB.operand[0].size = dis_info->size[5] * 8;
				ll_inst->srcB.operand[0].offset = dis_info->offset[5];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 offset Imm  = 0x%lx\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[5], dis_info->size[5], Bytes[dis_info->offset[5]]);
			}
			copy_operand(&(ll_inst->srcA), &(ll_inst->dstA));
			debug_print(DEBUG_INPUT_DIS, 1, "DST0 = SRC0\n");
			result = 0;
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;
	case 0x10: // MRM0r
	case 0x11: // MRM1r
	case 0x12: // MRM2r
	case 0x13: // MRM3r
	case 0x14: // MRM4r
	case 0x15: // MRM5r
	case 0x16: // MRM6r
	case 0x17: // MRM7r
		switch (num_operands) {
		case 1:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			result = 0;
			break;
		case 2:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcB.kind = KIND_IMM;
				ll_inst->srcB.operand[0].value = value;
				ll_inst->srcB.operand[0].size = dis_info->size[1] * 8;
				ll_inst->srcB.operand[0].offset = dis_info->offset[1];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 index multiplier Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
			}
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
				if (RegCL.equals(Name.substr(Name.size() - 2))) {
					ll_inst->srcB.kind = KIND_REG;
					ll_inst->srcB.operand[0].value = 0x10;
					ll_inst->srcB.operand[0].size = 0x8;
					ll_inst->srcB.operand[0].offset = 0;
					debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 Reg: value = 0x10, name = CL, size = 8\n");
				}
			}
			copy_operand(&(ll_inst->srcA), &(ll_inst->dstA));
			debug_print(DEBUG_INPUT_DIS, 1, "DST0 = SRC0\n");
			result = 0;
			break;
		case 3:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->dstA.kind = KIND_REG;
				ll_inst->dstA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->dstA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->dstA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "DST0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.kind = KIND_REG;
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcB.kind = KIND_IMM;
				ll_inst->srcB.operand[0].value = value;
				ll_inst->srcB.operand[0].size = dis_info->size[2] * 8;
				ll_inst->srcB.operand[0].offset = dis_info->offset[1];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 index multiplier Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[2], dis_info->size[2], Bytes[dis_info->offset[1]]);
			}
			result = 0;
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;
	case 0x18: // MRM0m
	case 0x19: // MRM1m
	case 0x1A: // MRM2m 
	case 0x1B: // MRM3m 
	case 0x1C: // MRM4m 
	case 0x1D: // MRM5m 
	case 0x1E: // MRM6m 
	case 0x1F: // MRM7m 
		switch (num_operands) {
		case 5:
			ll_inst->srcA.kind = KIND_IND_SCALE;
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 pointer Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcA.operand[1].value = value;
				ll_inst->srcA.operand[1].size = dis_info->size[1] * 8;
				ll_inst->srcA.operand[1].offset = dis_info->offset[1];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 index multiplier Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[2].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[2].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[2].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.2 index Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				int64_t value;
				value = Operand->getImm();
				ll_inst->srcA.operand[3].value = value;
				ll_inst->srcA.operand[3].size = dis_info->size[3] * 8;
				ll_inst->srcA.operand[3].offset = dis_info->offset[3];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 offset Imm  = 0x%lx\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[3], dis_info->size[3], Bytes[dis_info->offset[3]]);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[4].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[4].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[4].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.4 segment Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			result = 0;
			break;
		case 6:
			ll_inst->srcA.kind = KIND_IND_SCALE;
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[0].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[0].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[0].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.0 pointer Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				ll_inst->srcA.operand[1].value = value;
				ll_inst->srcA.operand[1].size = dis_info->size[1] * 8;
				ll_inst->srcA.operand[1].offset = dis_info->offset[1];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 index multiplier Imm = 0x%x\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[2].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[2].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[2].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.2 index Reg: value = 0x%x, name = %s, size = 0x%x, reg_number = 0x%x\n",
					value, helper_reg_table[reg_index].reg_name, helper_reg_table[reg_index].size, helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				int64_t value;
				value = Operand->getImm();
				ll_inst->srcA.operand[3].value = value;
				ll_inst->srcA.operand[3].size = dis_info->size[3] * 8;
				ll_inst->srcA.operand[3].offset = dis_info->offset[3];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 offset Imm  = 0x%lx\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.3 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[3], dis_info->size[3], Bytes[dis_info->offset[3]]);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				ll_inst->srcA.operand[4].value = helper_reg_table[reg_index].reg_number;
				ll_inst->srcA.operand[4].size = helper_reg_table[reg_index].size;
				ll_inst->srcA.operand[4].offset = 0;
				debug_print(DEBUG_INPUT_DIS, 1, "SRC0.4 unknown Reg  = 0x%x\n", value);
			}
			Operand = &Inst->getOperand(5);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				int64_t value;
				value = Operand->getImm();
				ll_inst->srcB.kind = KIND_IMM;
				ll_inst->srcB.operand[0].value = value;
				ll_inst->srcB.operand[0].size = dis_info->size[5] * 8;
				ll_inst->srcB.operand[0].offset = dis_info->offset[5];
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 offset Imm  = 0x%lx\n", value);
				debug_print(DEBUG_INPUT_DIS, 1, "SRC1.0 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n",
					dis_info->offset[5], dis_info->size[5], Bytes[dis_info->offset[5]]);
			}
			copy_operand(&(ll_inst->srcA), &(ll_inst->dstA));
			debug_print(DEBUG_INPUT_DIS, 1, "DST0 = SRC0\n");
			result = 0;
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			result = 1;
			break;
		}
		break;
	default:
		outs() << "Unrecognised form\n";
		result = 1;
		break;
	}


	for (n = 0; n < num_operands; n++) {
		Operand = &Inst->getOperand(n);
		/* FIXME Operand */
		debug_print(DEBUG_INPUT_DIS, 1, "Operand = 0x%" PRIx64 "\n", Operand);
		debug_print(DEBUG_INPUT_DIS, 1, "Valid = %d, isReg = %d, isImm = %d, isFPImm = %d, isExpr = %d, isInst = %d\n",
			Operand->isValid(), Operand->isReg(), Operand->isImm(), Operand->isFPImm(), Operand->isExpr(), Operand->isInst());
		//outs() << format("Operand.Kind = 0x%x\n", Operand->Kind);
		if (Operand->isImm()) {
			debug_print(DEBUG_INPUT_DIS, 1, "Imm = 0x%lx, ", Operand->getImm());
			int size_of_imm = X86II::getSizeOfImm(TSFlags);
			debug_print(DEBUG_INPUT_DIS, 1, "sizeof(Imm) = 0x%xi\n", size_of_imm);
		}
		if (Operand->isReg()) {
			uint32_t reg;
			reg = Operand->getReg();
			debug_print(DEBUG_INPUT_DIS, 1, "Reg = 0x%x\n", reg);
			if (reg) {
				std::string Buf2;
				raw_string_ostream OS2(Buf2);
				IP->printRegName(OS2, reg);
				OS2.flush();
				Reg = OS2.str();
				debug_print(DEBUG_INPUT_DIS, 1, "Reg: %s\n", Reg.data());
			}
		}
	}
	return result;
}

int llvm::DecodeAsmX86_64::PrintOperand(struct operand_low_level_s *operand) {
	switch (operand->kind) {
	case KIND_REG:
		debug_print(DEBUG_INPUT_DIS, 1, "REG:0x%lx:size = 0x%x\n", operand->operand[0].value, operand->operand[0].size);
		break;
	case KIND_IMM:
		debug_print(DEBUG_INPUT_DIS, 1, "IMM:0x%lx:symbol size = 0x%x, symbol offset = 0x%lx\n",
			operand->operand[0].value,
			operand->operand[0].size,
			operand->operand[0].offset);
		break;
	case KIND_SCALE:
		debug_print(DEBUG_INPUT_DIS, 1, "SCALE_POINTER_REG:0x%lx:size = 0x%x\n", operand->operand[0].value, operand->operand[0].size);
		debug_print(DEBUG_INPUT_DIS, 1, "SCALE_IMM_INDEX_MUL:0x%lx:symbol size = 0x%x, symbol offset = 0x%lx\n",
			operand->operand[1].value,
			operand->operand[1].size,
			operand->operand[1].offset);
		debug_print(DEBUG_INPUT_DIS, 1, "SCALE_INDEX_REG:0x%lx:size = 0lx%x\n", operand->operand[2].value, operand->operand[2].size);
		debug_print(DEBUG_INPUT_DIS, 1, "SCALE_IMM_OFFSET:0x%lx:symbol size = 0x%x, symbol offset = 0x%lx\n",
			operand->operand[3].value,
			operand->operand[3].size,
			operand->operand[3].offset);
		debug_print(DEBUG_INPUT_DIS, 1, "SCALE_SEGMENT_REG:0x%lx:size = 0x%x\n", operand->operand[4].value, operand->operand[4].size);
		break;
	case KIND_IND_REG:
		debug_print(DEBUG_INPUT_DIS, 1, "REG_IND:0x%lx:size = 0x%x\n", operand->operand[0].value, operand->operand[0].size);
		break;
	case KIND_IND_IMM:
		debug_print(DEBUG_INPUT_DIS, 1, "IMM_IND:0x%lx:symbol size = 0x%x, symbol offset = 0x%lx\n",
			operand->operand[0].value,
			operand->operand[0].size,
			operand->operand[0].offset);
		break;
	case KIND_IND_SCALE:
		debug_print(DEBUG_INPUT_DIS, 1, "IND_SCALE_POINTER_REG:0x%lx:size = 0x%x\n", operand->operand[0].value, operand->operand[0].size);
		debug_print(DEBUG_INPUT_DIS, 1, "IND_SCALE_IMM_INDEX_MUL:0x%lx:symbol size = 0x%x, symbol offset = 0x%lx\n",
			operand->operand[1].value,
			operand->operand[1].size,
			operand->operand[1].offset);
		debug_print(DEBUG_INPUT_DIS, 1, "IND_SCALE_INDEX_REG:0x%lx:size = 0x%x\n", operand->operand[2].value, operand->operand[2].size);
		debug_print(DEBUG_INPUT_DIS, 1, "IND_SCALE_IMM_OFFSET:0x%lx:symbol size = 0x%x, symbol offset = 0x%lx\n",
			operand->operand[3].value,
			operand->operand[3].size,
			operand->operand[3].offset);
		debug_print(DEBUG_INPUT_DIS, 1, "IND_SCALE_SEGMENT_REG:0x%lx:size = 0x%x\n", operand->operand[4].value, operand->operand[4].size);
		break;
	default:
		break;
	}
	return 0;
}

int llvm::DecodeAsmX86_64::PrintInstruction(struct instruction_low_level_s *ll_inst) {
	debug_print(DEBUG_INPUT_DIS, 1, "Opcode 0x%x:%s\n", ll_inst->opcode, helper_opcode_table[ll_inst->opcode]);
	debug_print(DEBUG_INPUT_DIS, 1, "srcA:size=0x%x\n", ll_inst->srcA.size);
	PrintOperand(&(ll_inst->srcA));
	debug_print(DEBUG_INPUT_DIS, 1, "srcB:size=0x%x\n", ll_inst->srcB.size);
	PrintOperand(&(ll_inst->srcB));
	debug_print(DEBUG_INPUT_DIS, 1, "dstA:size=0x%x\n", ll_inst->dstA.size);
	PrintOperand(&(ll_inst->dstA));
	return 0;
}

} // namespace llvm
