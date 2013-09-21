
#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

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
#include "decode_inst_helper.h"
#include "decode_asm_X86_64.h"

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

	outs() << TheTarget;

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
	DisAsm = TheTarget->createMCDisassembler(*STI);
	if (!DisAsm)
		return 1;

	OwningPtr<MCRelocationInfo> RelInfo(
		TheTarget->createMCRelocationInfo(TripleName, *Ctx));
	if (!RelInfo)
		return 1;

	OwningPtr<MCSymbolizer> Symbolizer(
		TheTarget->createMCSymbolizer(TripleName, GetOpInfo, SymbolLookUp, DisInfo,
			Ctx, RelInfo.take()));
	DisAsm->setSymbolizer(Symbolizer);
	DisAsm->setupForSymbolicDisassembly(GetOpInfo, SymbolLookUp, DisInfo, Ctx, RelInfo);

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
	StringRef reg_name;
	int helper_size = sizeof(helper_reg_table) / sizeof(struct helper_reg_table_s);
	int n;
	int tmp;
	raw_string_ostream OS(buf);
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




#define KIND_EMPTY 0
#define KIND_REG 1
#define KIND_IMM 2
#define KIND_IND_REG 3
#define KIND_IND_IMM 4
#define KIND_IND_SCALE 5


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
	// Wrap the pointer to the Bytes, BytesSize and PC in a MemoryObject.
	llvm::DecodeAsmMemoryObject MemoryObject2(Bytes, BytesSize, PC);

	outs() << "DECODE INST\n";
	uint64_t Size;
	struct dis_info_s *dis_info = (struct dis_info_s *) DisInfo;
	MCInst *Inst = dis_info->Inst;
	Inst->clear();
	for (n = 0; n < 16; n++) {
		dis_info->offset[n] = 0;
		dis_info->size[n] = 0;
	}
	MCDisassembler::DecodeStatus S;
	if (Bytes[0] == 0) {
		outs() << "Bytes reset to 0\n";
		exit(1);
	}
	S = DisAsm->getInstruction(*Inst, Size, MemoryObject2, PC,
		/*REMOVE*/ nulls(), nulls());
	if (S != MCDisassembler::Success) {
	// case MCDisassembler::Fail:
	// case MCDisassembler::SoftFail:
		// FIXME: Do something different for soft failure modes?
		return 0;
	}

	// case MCDisassembler::Success: {
	StringRef Name;
	StringRef Reg;
	uint32_t value = 0;
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
	outs() << format("Opcode 0x%x:", opcode) << format("0x%x:", new_helper[opcode].opcode) << format("%s", opcode_name) << "\n";
	ll_inst->opcode = new_helper[opcode].opcode;
	int num_operands = Inst->getNumOperands();
	outs() << format("opcode_form = 0x%x", opcode_form) << format(", num_operands = 0x%x", num_operands) << "\n";
	MCOperand *Operand;
	switch (opcode_form) {
	case 1: // RawFrm
		switch (num_operands) {
		case 0:
			break;
		case 1:
			outs() << "DST0.1 reg = %al\n";
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				value = Operand->getImm();
				outs() << format("SRC0.1 index multiplier Imm = 0x%x\n", value);
				outs() << format("SRC0.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[0], dis_info->size[0], Bytes[dis_info->offset[0]]);
			}
			ll_inst->srcA.kind = KIND_EMPTY;
			ll_inst->srcB.kind = KIND_EMPTY;
			ll_inst->dstA.kind = KIND_IMM;
			ll_inst->dstA.operand[0].value = value;
			ll_inst->dstA.operand[0].size = dis_info->size[0];
			ll_inst->dstA.operand[0].offset = dis_info->offset[0];
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			break;
		}
		break;
	case 2: // AddRegFrm
		if (num_operands != 1) {
			outs() << "Unrecognised num_operands\n";
			break;
		}
		Operand = &Inst->getOperand(0);
		if (Operand->isValid() &&
			Operand->isReg()) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			outs() << format("SRC0.1 Reg: value = 0x%x, ", value);
			outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
			outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
			outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
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
				outs() << format("DST0.1 Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC0.1 Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
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
				outs() << format("DST0.1 Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC0.1 Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC1.1 Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			break;
		}
		break;
	case 5: // MRMSrcReg
		if (num_operands != 2) {
			outs() << "Unrecognised num_operands\n";
			break;
		}
		Operand = &Inst->getOperand(0);
		if (Operand->isValid() &&
			Operand->isReg()) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			outs() << format("DST0.1 Reg: value = 0x%x, ", value);
			outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
			outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
			outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
		}
		Operand = &Inst->getOperand(1);
		if (Operand->isValid() &&
			Operand->isReg()) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			outs() << format("SRC0.1 Reg: value = 0x%x, ", value);
			outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
			outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
			outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
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
				outs() << format("DST0.1 Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC0.1 pointer Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("SRC0.2 index multiplier Imm = 0x%x\n", value);
				outs() << format("SRC0.2 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[2], dis_info->size[2], Bytes[dis_info->offset[2]]);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC0.3 index Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("SRC0.4 offset Imm  = 0x%x\n", value);
				outs() << format("SRC0.4 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[4], dis_info->size[4], Bytes[dis_info->offset[4]]);
			}
			Operand = &Inst->getOperand(5);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				value = Operand->getReg();
				outs() << format("SRC0.5 Segment Reg  = 0x%x\n", value);
			}
			break;
		case 7:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("DST0.1 Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isReg()) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC0.1 Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC1.1 pointer Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("SRC1.2 index multiplier Imm = 0x%x\n", value);
				outs() << format("SRC1.2 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[2], dis_info->size[2], Bytes[dis_info->offset[2]]);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC1.3 index Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(5);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("SRC1.4 offset Imm  = 0x%x\n", value);
				outs() << format("SRC1.4 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[4], dis_info->size[4], Bytes[dis_info->offset[4]]);
			}
			Operand = &Inst->getOperand(6);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				value = Operand->getReg();
				outs() << format("SRC1.5 Segment Reg  = 0x%x\n", value);
			}
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			break;
		}
		break;
	case 0x10: //
		if (num_operands != 2) {
			outs() << "Unrecognised num_operands\n";
			break;
		}
		Operand = &Inst->getOperand(0);
		if (Operand->isValid() &&
			Operand->isReg()) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			outs() << format("DST0.1 Reg: value = 0x%x, ", value);
			outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
			outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
			outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
		}
		Operand = &Inst->getOperand(1);
		if (Operand->isValid() &&
			Operand->isImm() ) {
			uint32_t value;
			value = Operand->getImm();
			outs() << format("SRC0.1 index multiplier Imm = 0x%x\n", value);
			outs() << format("SRC0.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
		}
		break;
	case 0x14: // MRM4r
	case 0x17: // MRM7r
		if (num_operands != 3) {
			outs() << "Unrecognised num_operands\n";
			break;
		}
		Operand = &Inst->getOperand(0);
		if (Operand->isValid() &&
			Operand->isReg()) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			outs() << format("DST0.1 Reg: value = 0x%x, ", value);
			outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
			outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
			outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
		}
		Operand = &Inst->getOperand(1);
		if (Operand->isValid() &&
			Operand->isReg()) {
			uint32_t value;
			int reg_index = 0;
			int tmp;
			value = Operand->getReg();
			tmp = get_reg_size_helper(value, &reg_index);
			outs() << format("SRC0.1 Reg: value = 0x%x, ", value);
			outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
			outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
			outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
		}
		Operand = &Inst->getOperand(2);
		if (Operand->isValid() &&
			Operand->isImm() ) {
			uint32_t value;
			value = Operand->getImm();
			outs() << format("SRC1.1 offset Imm = 0x%x\n", value);
			outs() << format("SRC1.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[2], dis_info->size[2], Bytes[dis_info->offset[2]]);
		}
		break;
	case 0x18: // MRM2r
		switch (num_operands) {
		case 5:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC0.1 pointer Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("SRC0.2 index multiplier Imm = 0x%x\n", value);
				outs() << format("SRC0.2 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC0.3 index Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("SRC0.4 offset Imm  = 0x%x\n", value);
				outs() << format("SRC0.4 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[3], dis_info->size[3], Bytes[dis_info->offset[3]]);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("SRC0.5 segment Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			break;
		case 6:
			Operand = &Inst->getOperand(0);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("DST0.1 pointer Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(1);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("DST0.2 index multiplier Imm = 0x%x\n", value);
				outs() << format("DST0.2 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[1], dis_info->size[1], Bytes[dis_info->offset[1]]);
			}
			Operand = &Inst->getOperand(2);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				int reg_index = 0;
				int tmp;
				value = Operand->getReg();
				tmp = get_reg_size_helper(value, &reg_index);
				outs() << format("DST0.3 index Reg: value = 0x%x, ", value);
				outs() << format("name = %s, ", helper_reg_table[reg_index].reg_name);
				outs() << format("size = 0x%x, ", helper_reg_table[reg_index].size);
				outs() << format("reg_number = 0x%x\n", helper_reg_table[reg_index].reg_number);
			}
			Operand = &Inst->getOperand(3);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("DST0.4 offset Imm  = 0x%x\n", value);
				outs() << format("DST0.4 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[3], dis_info->size[3], Bytes[dis_info->offset[3]]);
			}
			Operand = &Inst->getOperand(4);
			if (Operand->isValid() &&
				Operand->isReg() ) {
				uint32_t value;
				value = Operand->getReg();
				outs() << format("DST0.5 unknown Reg  = 0x%x\n", value);
			}
			Operand = &Inst->getOperand(5);
			if (Operand->isValid() &&
				Operand->isImm() ) {
				uint32_t value;
				value = Operand->getImm();
				outs() << format("SRC0.1 offset Imm  = 0x%x\n", value);
				int size_of_imm = X86II::getSizeOfImm(TSFlags);
				outs() << format("SRC0.1 bytes at inst offset = 0x%x octets, size = 0x%x octets, value = 0x%x\n", dis_info->offset[5], dis_info->size[5], Bytes[dis_info->offset[5]]);
			}
			break;
		default:
			outs() << "Unrecognised num_operands\n";
			break;
		}
		break;
	default:
		outs() << "Unrecognised form\n";
		break;
	}


	for (n = 0; n < num_operands; n++) {
		Operand = &Inst->getOperand(n);
		outs() << "Operand = " << Operand << "\n";
		outs() << "Valid = " << Operand->isValid(); 
		outs() << ", isReg = " << Operand->isReg();
		outs() << ", isImm = " << Operand->isImm();
		outs() << ", isFPImm = " << Operand->isFPImm();
		outs() << ", isExpr = " << Operand->isExpr();
		outs() << ", isInst = " << Operand->isInst() << "\n";
		//outs() << format("Operand.Kind = 0x%x\n", Operand->Kind);
		if (Operand->isImm()) {
			outs() << format("Imm = 0x%lx, ", Operand->getImm());
			int size_of_imm = X86II::getSizeOfImm(TSFlags);
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
	return Size;
}

} // namespace llvm
