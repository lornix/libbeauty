/* Test creation of a .bc file for LLVM IR*/

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <global_struct.h>
#include <output.h>
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

		CmpInst::Predicate predicate_to_llvm_table[] =  {
			ICmpInst::FCMP_FALSE,  /// None
			ICmpInst::FCMP_FALSE,  /// FLAG_OVERFLOW
			ICmpInst::FCMP_FALSE,  /// FLAG_NOT_OVERFLOW
			ICmpInst::ICMP_ULT,  ///< unsigned less than. FLAG_BELOW
			ICmpInst::ICMP_UGE,  ///< unsigned greater or equal. FLAG_NOT_BELOW
			ICmpInst::ICMP_EQ,  ///< equal. FLAG_EQUAL
			ICmpInst::ICMP_NE,  ///< not equal. FLAG_NOT_EQUAL
			ICmpInst::ICMP_ULE,  ///< unsigned less or equal. FLAG_BELOW_EQUAL
			ICmpInst::ICMP_UGT,  ///< unsigned greater than. FLAG_ABOVE
			ICmpInst::FCMP_FALSE, /// FLAG_SIGNED
			ICmpInst::FCMP_FALSE, /// FLAG_NOT_SIGNED
			ICmpInst::FCMP_FALSE, /// FLAG_PARITY
			ICmpInst::FCMP_FALSE, /// FLAG_NOT_PARITY
			ICmpInst::ICMP_SLT,  ///< signed less than
			ICmpInst::ICMP_SGE,  ///< signed greater or equal
			ICmpInst::ICMP_SLE,  ///< signed less or equal
			ICmpInst::ICMP_SGT,  ///< signed greater than. 
		};

class LLVM_ir_export
{
	public:
		int find_function_member_node(struct self_s *self, struct external_entry_point_s *external_entry_point, int node_to_find, int *member_node);
		int add_instruction(struct self_s *self, Module *mod, Value **value, BasicBlock **bb, int node, int external_entry, int inst);
		int add_node_instructions(struct self_s *self, Module *mod, Value **value, BasicBlock **bb, int node, int external_entry);
		int fill_value(struct self_s *self, Value **value, int value_id, int external_entry);
		int output(struct self_s *self);


	private:
		LLVMContext Context;
};

int LLVM_ir_export::find_function_member_node(struct self_s *self, struct external_entry_point_s *external_entry_point, int node_to_find, int *member_node)
{
	int found = 1;
	int n;

	*member_node = 0;
	for (n = 0; n < external_entry_point->member_nodes_size; n++) {
		if (node_to_find == external_entry_point->member_nodes[n]) {
			found = 0;
			*member_node = n;
			break;
		}
	}
	return found;
}

int LLVM_ir_export::add_instruction(struct self_s *self, Module *mod, Value **value, BasicBlock **bb, int node, int external_entry, int inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1 = &inst_log_entry[inst];
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[external_entry]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;;
	Value *srcA;
	Value *srcB;
	Value *dstA;
	uint64_t srcA_size;
	uint64_t srcB_size;
	int value_id;
	int value_id_dst;
	struct label_s *label;
	int tmp;
	char buffer[1024];
	int node_true;
	int node_false;
	int result = 0;

	switch (inst_log1->instruction.opcode) {
	case 1:  // MOV
		/* 2 forms, 1) MOV REG,REG and 2) MOV IMM,REG
		 * (1) is a NOP in LLVM IR, (2) is a fill value but no OP.
		 */
		printf("LLVM 0x%x: OPCODE = 0x%x:MOV\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		printf("value_id1 = 0x%lx->0x%lx, value_id3 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].redirect);
		if (inst_log1->instruction.srcA.store == 0) {  /* IMM */
			value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
			if (!value[value_id]) {
				tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
				if (tmp) {
					printf("failed LLVM Value is NULL. dstA value_id = 0x%x\n", value_id);
					exit(1);
				}
			}
		}
		break;
	case 2:  // ADD
		printf("LLVM 0x%x: OPCODE = 0x%x:ADD\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		printf("value_id1 = 0x%lx->0x%lx, value_id2 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];
		printf("srcA = %p, srcB = %p\n", srcA, srcB);
		printf("srcA = %x, srcB = %x\n", srcA->getType(), srcB->getType());
		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = BinaryOperator::CreateAdd(srcA, srcB, buffer, bb[node]);
		value[inst_log1->value3.value_id] = dstA;
		break;
	case 4:  // SUB
		printf("LLVM 0x%x: OPCODE = 0x%x:SUB\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		printf("value_id1 = 0x%lx->0x%lx, value_id2 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		srcA_size = external_entry_point->labels[value_id].size_bits;
		printf("srcA: scope=0x%lx, type=0x%lx value=0x%lx size_bits=0x%lx pointer_type_size_bits=0x%lx lab_pointer=0x%lx lab_signed=0x%lx lab_unsigned=0x%lx name=%s\n",
			external_entry_point->labels[value_id].scope,
			external_entry_point->labels[value_id].type,
			external_entry_point->labels[value_id].value,
			external_entry_point->labels[value_id].size_bits,
			external_entry_point->labels[value_id].pointer_type_size_bits,
			external_entry_point->labels[value_id].lab_pointer,
			external_entry_point->labels[value_id].lab_signed,
			external_entry_point->labels[value_id].lab_unsigned,
			external_entry_point->labels[value_id].name);

		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];
		srcB_size = external_entry_point->labels[value_id].size_bits;
		printf("srcB: scope=0x%lx, type=0x%lx value=0x%lx size_bits=0x%lx pointer_type_size_bits=0x%lx lab_pointer=0x%lx lab_signed=0x%lx lab_unsigned=0x%lx name=%s\n",
			external_entry_point->labels[value_id].scope,
			external_entry_point->labels[value_id].type,
			external_entry_point->labels[value_id].value,
			external_entry_point->labels[value_id].size_bits,
			external_entry_point->labels[value_id].pointer_type_size_bits,
			external_entry_point->labels[value_id].lab_pointer,
			external_entry_point->labels[value_id].lab_signed,
			external_entry_point->labels[value_id].lab_unsigned,
			external_entry_point->labels[value_id].name);

		printf("srcA = %p, srcB = %p\n", srcA, srcB);
		printf("srcA_size = 0x%lx, srcB_size = 0x%lx\n", srcA_size, srcB_size);
		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = BinaryOperator::CreateSub(srcA, srcB, buffer, bb[node]);
		value[inst_log1->value3.value_id] = dstA;
		break;
	case 0xd:  // MUL
		printf("LLVM 0x%x: OPCODE = 0x%x:MUL\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		printf("value_id1 = 0x%lx->0x%lx, value_id2 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];
		printf("srcA = %p, srcB = %p\n", srcA, srcB);
		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = BinaryOperator::Create(Instruction::Mul, srcA, srcB, buffer, bb[node]);
		value[inst_log1->value3.value_id] = dstA;
		break;
	case 0xe:  // IMUL
		printf("LLVM 0x%x: OPCODE = 0x%x:IMUL\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		printf("value_id1 = 0x%lx->0x%lx, value_id2 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];
		printf("srcA = %p, srcB = %p\n", srcA, srcB);
		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = BinaryOperator::Create(Instruction::Mul, srcA, srcB, buffer, bb[node]);
		value[inst_log1->value3.value_id] = dstA;
		break;
	case 0x11:  // JMP
		printf("LLVM 0x%x: OPCODE = 0x%x:JMP node_end = 0x%x\n", inst, inst_log1->instruction.opcode, inst_log1->node_end);
		if (inst_log1->node_end) {
			node_true = nodes[node].link_next[0].node;
			BranchInst::Create(bb[node_true], bb[node]);
			result = 1;
		}
		break;
	case 0x1e:  // RET
		printf("LLVM 0x%x: OPCODE = 0x%x:RET\n", inst, inst_log1->instruction.opcode);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL\n");
				result = 2;
				//exit(1);
				break;
			}
		}
		srcA = value[value_id];
		ReturnInst::Create(Context, srcA, bb[node]);
		result = 1;
		break;
	case 0x1f:  // SEX
		printf("LLVM 0x%x: OPCODE = 0x%x:SEX\n", inst, inst_log1->instruction.opcode);
		printf("value_id1 = 0x%lx->0x%lx, value_id3 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].redirect;
		label = &external_entry_point->labels[value_id_dst];
		tmp = label_to_string(label, buffer, 1023);
		printf("label->size_bits = 0x%lx\n", label->size_bits);
		dstA = new SExtInst(srcA, IntegerType::get(mod->getContext(), label->size_bits), buffer, bb[node]);
		value[value_id_dst] = dstA;
		break;
	case 0x23:  // ICMP
		printf("LLVM 0x%x: OPCODE = 0x%x:ICMP\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		printf("ICMP predicate = 0x%x\n", inst_log1->instruction.predicate);
		printf("value_id1 = 0x%lx->0x%lx, value_id2 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				tmp = label_to_string(&external_entry_point->labels[value_id], buffer, 1023);
				printf("failed LLVM Value is NULL. srcA value_id = 0x%x:%s\n", value_id, buffer);
				exit(1);
			}
		}
		srcA = value[value_id];
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				tmp = label_to_string(&external_entry_point->labels[value_id], buffer, 1023);
				printf("failed LLVM Value is NULL. srcB value_id = 0x%x:%s\n", value_id, buffer);
				exit(1);
			}
		}
		srcB = value[value_id];
		printf("srcA = %p, srcB = %p\n", srcA, srcB);
		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		//dstA = new ICmpInst(*bb, ICmpInst::ICMP_EQ, srcA, srcB, buffer);
		dstA = new ICmpInst(*bb[node], predicate_to_llvm_table[inst_log1->instruction.predicate], srcA, srcB, buffer);
		value[inst_log1->value3.value_id] = dstA;
		break;
	case 0x24:  // BC
		printf("LLVM 0x%x: OPCODE = 0x%x:BC\n", inst, inst_log1->instruction.opcode);
		printf("value_id1 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				tmp = label_to_string(&external_entry_point->labels[value_id], buffer, 1023);
				printf("failed LLVM Value is NULL. srcA value_id = 0x%x:%s\n", value_id, buffer);
				exit(1);
			}
		}
		srcA = value[value_id];
		//BranchInst::Create(label_7, label_9, int1_11, label_6);
		node_true = nodes[node].link_next[0].node;
		node_false = nodes[node].link_next[1].node;
		BranchInst::Create(bb[node_true], bb[node_false], srcA, bb[node]);
		result = 1;
		break;
	case 0x25:  // LOAD
		printf("LLVM 0x%x: OPCODE = 0x%x:LOAD\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		switch (inst_log1->instruction.srcA.indirect) {
		case 1:  // Memory
			printf("value_id1 = 0x%lx->0x%lx, value_id3 = 0x%lx->0x%lx\n",
				inst_log1->value1.value_id,
				external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
				inst_log1->value3.value_id,
				external_entry_point->label_redirect[inst_log1->value3.value_id].redirect);
			value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
			value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].redirect;
			label = &external_entry_point->labels[value_id_dst];
			if (value_id) {
				srcA = value[value_id];
				tmp = label_to_string(label, buffer, 1023);
				LoadInst* dstA_load = new LoadInst(srcA, buffer, false, bb[node]);
				dstA_load->setAlignment(label->size_bits >> 3);
				dstA = dstA_load;
			} else {
				printf("LLVM 0x%x: FIXME: Invalid srcA value_id\n", inst);
				printf("inst indirect = 0x%x\n", inst_log1->instruction.srcA.indirect);
			}

			if (value_id_dst) {
				value[value_id_dst] = dstA;
			} else {
				printf("LLVM 0x%x: FIXME: Invalid value_id\n", inst);
			}
			break;
		case 2:  // Stack
			printf("value_id1 = 0x%lx->0x%lx, value_id3 = 0x%lx->0x%lx\n",
				inst_log1->value1.indirect_value_id,
				external_entry_point->label_redirect[inst_log1->value1.indirect_value_id].redirect,
				inst_log1->value3.value_id,
				external_entry_point->label_redirect[inst_log1->value3.value_id].redirect);
			value_id = external_entry_point->label_redirect[inst_log1->value1.indirect_value_id].redirect;
			value_id_dst = external_entry_point->label_redirect[inst_log1->value3.value_id].redirect;
			label = &external_entry_point->labels[value_id_dst];
			if (value_id) {
				srcA = value[value_id];
				tmp = label_to_string(label, buffer, 1023);
				LoadInst* dstA_load = new LoadInst(srcA, buffer, false, bb[node]);
				dstA_load->setAlignment(label->size_bits >> 3);
				dstA = dstA_load;
			} else {
				printf("LLVM 0x%x: FIXME: Invalid srcA value_id\n", inst);
				printf("inst indirect = 0x%x\n", inst_log1->instruction.srcA.indirect);
			}

			if (value_id_dst) {
				value[value_id_dst] = dstA;
			} else {
				printf("LLVM 0x%x: FIXME: Invalid value_id\n", inst);
			}
			break;
		default:
			printf("FIXME: LOAD Indirect = 0x%x not yet handled\n", inst_log1->instruction.srcA.indirect);
			break;
		}
		break;
	case 0x26:  // STORE
		printf("LLVM 0x%x: OPCODE = 0x%x:STORE\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		printf("value_id1 = 0x%lx->0x%lx, value_id3 = 0x%lx->0x%lx indirect_value_id3 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].redirect,
			inst_log1->value3.indirect_value_id,
			external_entry_point->label_redirect[inst_log1->value3.indirect_value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (value_id) {
			printf("LLVM 0x%x: srcA value_id 0x%x\n", inst, value_id);
			srcA = value[value_id];
		} else {
			printf("LLVM 0x%x: FIXME: Invalid srcA value_id\n", inst);
			break;
		}
		value_id = external_entry_point->label_redirect[inst_log1->value3.indirect_value_id].redirect;
		if (value_id) {
			printf("LLVM 0x%x: srcB value_id 0x%x\n", inst, value_id);
			srcB = value[value_id];
		} else {
			printf("LLVM 0x%x: FIXME: Invalid srcB value_id\n", inst);
			break;
		}
		printf("srcA = %p, srcB = %p\n", srcA, srcB);
		// FIXME: temporary comment out.
		//dstA = new StoreInst(srcA, srcB, false, bb[node]);
		break;
	case 0x2F:  // GEP1
		printf("LLVM 0x%x: OPCODE = 0x%x:GEP1\n", inst, inst_log1->instruction.opcode);
//		if (inst_log1->instruction.dstA.index == 0x28) {
//			/* Skip the 0x28 reg as it is the SP reg */
//			break;
//		}
		printf("value_id1 = 0x%lx->0x%lx, value_id2 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
			inst_log1->value2.value_id,
			external_entry_point->label_redirect[inst_log1->value2.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcA value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcA = value[value_id];
		value_id = external_entry_point->label_redirect[inst_log1->value2.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL. srcB value_id = 0x%x\n", value_id);
				exit(1);
			}
		}
		srcB = value[value_id];
		printf("srcA = %p, srcB = %p\n", srcA, srcB);
		tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
		dstA = GetElementPtrInst::Create(srcA, srcB, buffer, bb[node]);
		value[inst_log1->value3.value_id] = dstA;
		break;
	default:
		printf("LLVM 0x%x: OPCODE = 0x%x. Not yet handled.\n", inst, inst_log1->instruction.opcode);
		exit(1);
		result = 1;
		break;
	}

	return result;
} 

int LLVM_ir_export::add_node_instructions(struct self_s *self, Module *mod, Value** value, BasicBlock **bb, int node, int external_entry) 
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[external_entry]);
	struct control_flow_node_s *nodes = external_entry_point->nodes;
	int nodes_size = external_entry_point->nodes_size;
	int l,m,n;
	int inst;
	int inst_next;
	int tmp;
	int node_true;
	int block_end;

	printf("LLVM Node 0x%x\n", node);
	inst = nodes[node].inst_start;
	inst_next = inst;

	do {
		inst = inst_next;
		inst_log1 =  &inst_log_entry[inst];
		printf("LLVM node end: inst_end = 0x%x, next_size = 0x%x, node_end = 0x%x\n",
			nodes[node].inst_end, inst_log1->next_size, inst_log1->node_end);
		tmp = add_instruction(self, mod, value, bb, node, external_entry, inst);
		if (inst_log1->next_size > 0) {
			inst_next = inst_log1->next[0];
		}
		printf("tmp = 0x%x\n", tmp);
		/* FIXME: is tmp really needed for block_end detection? */
		block_end = (inst_log1->node_end || !(inst_log1->next_size) || tmp);
		//block_end = (inst_log1->node_end || !(inst_log1->next_size));
	} while (!block_end);

	if (!tmp) {
		/* Only output the extra branch if the node did not do any branches or returns itself. */
		printf("LLVM node end: node = 0x%x, inst_end = 0x%x, next_size = 0x%x\n",
			node, nodes[node].inst_end, nodes[node].next_size);
		node_true = nodes[node].link_next[0].node;
		BranchInst::Create(bb[node_true], bb[node]);
	}
	return 0;
}

int LLVM_ir_export::fill_value(struct self_s *self, Value **value, int value_id, int external_entry)
{
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[external_entry]);
	struct label_s *label = &(external_entry_point->labels[value_id]);
	int labels_size = external_entry_point->variable_id;

	if ((label->scope == 3) &&
		(label->type == 3)) {
		if (label->size_bits == 32) {
			value[value_id] = ConstantInt::get(Type::getInt32Ty(Context), label->value);
		} else if (label->size_bits == 64) {
			value[value_id] = ConstantInt::get(Type::getInt64Ty(Context), label->value);
		} else {
			printf("LLVM fill_value() failed with size_bits = 0x%lx\n", label->size_bits);
			return 1;
		}
		return 0;
	} else {
		printf("LLVM fill_value(): value_id = 0x%x, label->scope = 0x%lx, label->type = 0x%lx\n",
			value_id,
			label->scope,
			label->type);
	}

	return 1;
}

int LLVM_ir_export::output(struct self_s *self)
{
	const char *function_name = "test123";
	char output_filename[512];
	int n;
	int m;
	int l;
	int tmp;
	struct control_flow_node_s *nodes;
	int nodes_size;
	int node;
	struct label_s *labels;
	int labels_size;
	struct label_redirect_s *label_redirect;
	struct label_s *label;
	char buffer[1024];
	int index;
	
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	
	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if ((external_entry_points[n].valid != 0) &&
			(external_entry_points[n].type == 1) && 
			(external_entry_points[n].nodes_size)) {
			Value** value = (Value**) calloc(external_entry_points[n].variable_id, sizeof(Value*));
			nodes = external_entry_points[n].nodes;
			nodes_size = external_entry_points[n].nodes_size;
			labels = external_entry_points[n].labels;
			labels_size = external_entry_points[n].variable_id;
			label_redirect = external_entry_points[n].label_redirect;
			Module *mod = new Module("test_llvm_export", Context);
 			mod->setDataLayout("e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v64:64:64-v128:128:128-a0:0:64-s0:64:64-f80:128:128-n8:16:32:64-S128");
			mod->setTargetTriple("x86_64-pc-linux-gnu");

			/* Add globals */
			for (m = 0; m < labels_size; m++) {
				label = &labels[label_redirect[m].redirect];
				if ((3 == label->scope) && (2 == label->type)) {
					printf("Label:0x%x: &data found. size=0x%lx\n", m, label->size_bits);
					GlobalVariable* gvar_int32_mem1 = new GlobalVariable(/*Module=*/*mod,
						/*Type=*/IntegerType::get(mod->getContext(), label->size_bits),
						/*isConstant=*/false,
						/*Linkage=*/GlobalValue::InternalLinkage,
						/*Initializer=*/0, // has initializer, specified below
						/*Name=*/"data0");
					gvar_int32_mem1->setAlignment(label->size_bits >> 3);
					value[m] = gvar_int32_mem1;
				}
			}


			function_name = external_entry_points[n].name;
			snprintf(output_filename, 500, "./llvm/%s.bc", function_name);
			std::vector<Type*>FuncTy_0_args;
			for (m = 0; m < external_entry_points[n].params_size; m++) {
				index = external_entry_points[n].params[m];
				if (labels[index].lab_pointer > 0) {
					int size = labels[index].pointer_type_size_bits;
					printf("Param=0x%x: Pointer Label 0x%x, size_bits = 0x%x\n", m, index, size);
					if (size < 8) {
						printf("FIXME: size too small\n");
						size = 8;
					}
					FuncTy_0_args.push_back(PointerType::get(IntegerType::get(mod->getContext(), size), 0));
				} else {	
					int size = labels[index].size_bits;
					printf("Param=0x%x: Label 0x%x, size_bits = 0x%x\n", m, index, size);
					FuncTy_0_args.push_back(IntegerType::get(mod->getContext(), size));
				}
			}

			FunctionType *FT =
				FunctionType::get(Type::getInt32Ty(Context),
					FuncTy_0_args,
					false); /*not vararg*/

			Function *F = Function::Create(FT, Function::ExternalLinkage, function_name, mod);

			Function::arg_iterator args = F->arg_begin();
			printf("Function: %s()  param_size = 0x%x\n", function_name, external_entry_points[n].params_size);
			for (m = 0; m < external_entry_points[n].params_size; m++) {
				index = external_entry_points[n].params[m];
				value[index] = args;
				args++;
				tmp = label_to_string(&(labels[index]), buffer, 1023);
				printf("Adding param:%s:value index=0x%x\n", buffer, index);
				value[index]->setName(buffer);
			}

			/* Create all the nodes/basic blocks */
			BasicBlock **bb = (BasicBlock **)calloc(nodes_size + 1, sizeof (BasicBlock *));
			for (m = 1; m < nodes_size; m++) {
				std::string node_string;
				std::stringstream tmp_str;
				tmp_str << "Node_0x" << std::hex << m;
				node_string = tmp_str.str();
				printf("LLVM2: %s\n", node_string.c_str());
				bb[m] = BasicBlock::Create(Context, node_string, F);
			}

			/* Create the AllocaInst's */
			for (m = 0; m < labels_size; m++) {
				int size_bits;
				/* param_stack or local_stack */
				if (((labels[m].scope == 1) || 
					(labels[m].scope == 2)) &&
					(labels[m].type == 2)) {
					size_bits = labels[m].size_bits;
					/* FIXME: Make size_bits set correctly in the label */
					//if (!size_bits) size_bits = 32;
					printf("Creating alloca for label 0x%x, size_bits = 0x%x\n", m, size_bits);
					tmp = label_to_string(&labels[m], buffer, 1023);
					AllocaInst* ptr_local = new AllocaInst(IntegerType::get(mod->getContext(), size_bits), buffer, bb[1]);
					ptr_local->setAlignment(size_bits >> 3);
					value[m] = ptr_local;
				}
			}
				
			/* FIXME: this needs the node to follow paths so the value[] is filled in the correct order */
			printf("LLVM: starting nodes\n");
			for (m = 1; m < nodes_size; m++) {
				printf("JCD12: node:0x%x: next_size = 0x%x\n", m, nodes[m].next_size);
			};
			for (node = 1; node < nodes_size; node++) {
				printf("LLVM: node=0x%x\n", node);

				/* Output PHI instructions first */
				for (m = 0; m < nodes[node].phi_size; m++) {
					int size_bits = labels[nodes[node].phi[m].value_id].size_bits;
					printf("LLVM:phi 0x%x\n", m);
					tmp = label_to_string(&labels[nodes[node].phi[m].value_id], buffer, 1023);
					printf("LLVM phi base size = 0x%x\n", size_bits);
					PHINode* phi_node = PHINode::Create(IntegerType::get(mod->getContext(), size_bits),
						nodes[node].phi[m].phi_node_size,
						buffer, bb[node]);
					/* The rest of the PHI instruction is added later */
					value[nodes[node].phi[m].value_id] = phi_node;
				}
				LLVM_ir_export::add_node_instructions(self, mod, value, bb, node, n);
			}

			for (node = 1; node < nodes_size; node++) {
				printf("LLVM: node=0x%x\n", node);

				for (m = 0; m < nodes[node].phi_size; m++) {
					int size_bits = labels[nodes[node].phi[m].value_id].size_bits;
					printf("LLVM:phi 0x%x\n", m);
					printf("LLVM phi base size = 0x%x\n", size_bits);
					PHINode* phi_node = (PHINode*)value[nodes[node].phi[m].value_id];
					for (l = 0; l < nodes[node].phi[m].phi_node_size; l++) {
						int value_id;
						int redirect_value_id;
						int first_previous_node;
						value_id = nodes[node].phi[m].phi_node[l].value_id;
						redirect_value_id = label_redirect[value_id].redirect;
						first_previous_node = nodes[node].phi[m].phi_node[l].first_prev_node;
						printf("LLVM:phi 0x%x:0x%x FPN=0x%x, SN=0x%x, value_id=0x%x, redirected_value_id=0x%x, size=0x%lx\n",
							m, l,
							nodes[node].phi[m].phi_node[l].first_prev_node,
							nodes[node].phi[m].phi_node[l].node,
							value_id,
							redirect_value_id,
							labels[redirect_value_id].size_bits);
						if (value_id > 0) {
							phi_node->addIncoming(value[redirect_value_id], bb[first_previous_node]);
						}
					}
				}
			}
			std::string ErrorInfo;
			raw_fd_ostream OS(output_filename, ErrorInfo, sys::fs::F_Binary);

			if (!ErrorInfo.empty())
				return -1;

			WriteBitcodeToFile(mod, OS);
			delete mod;
		}
	}

	return 0;
}

int LLVM_ir_export_entry(struct self_s *self)
{
	int tmp;
	LLVM_ir_export object;
	tmp = object.output(self);
	return tmp;
}

extern "C" int llvm_export(struct self_s *self)
{
	int tmp;
	tmp = LLVM_ir_export_entry(self);
	return tmp;
}

