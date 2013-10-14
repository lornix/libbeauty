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

class LLVM_ir_export
{
	public:
		int find_function_member_node(struct self_s *self, struct external_entry_point_s *external_entry_point, int node_to_find, int *member_node);
		int add_instruction(struct self_s *self, Value **value, BasicBlock *bb, int external_entry, int inst);
		int add_node_instructions(struct self_s *self, Value **value, BasicBlock *bb, int node, int external_entry);
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

int LLVM_ir_export::add_instruction(struct self_s *self, Value **value, BasicBlock *bb, int external_entry, int inst)
{
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct inst_log_entry_s *inst_log1 = &inst_log_entry[inst];
	struct external_entry_point_s *external_entry_point = &(self->external_entry_points[external_entry]);
	Value *srcA;
	Value *srcB;
	Value *dstA;
	int value_id;
	int tmp;
	char buffer[1024];

	switch (inst_log1->instruction.opcode) {
	case 1:  // MOV
		/* 2 forms, 1) MOV REG,REG and 2) MOV IMM,REG
		 * (1) is a NOP in LLVM IR, (2) is a fill value but no OP.
		 */
		printf("LLVM 0x%x: OPCODE = 0x%x:MOV\n", inst, inst_log1->instruction.opcode);
		if (inst_log1->instruction.dstA.index == 0x28) {
			/* Skip the 0x28 reg as it is the SP reg */
			break;
		}
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
		if (inst_log1->instruction.dstA.index == 0x28) {
			/* Skip the 0x28 reg as it is the SP reg */
			break;
		}
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
		dstA = BinaryOperator::CreateAdd(srcA, srcB, buffer, bb);
		value[inst_log1->value3.value_id] = dstA;
		break;
	case 4:  // SUB
		printf("LLVM 0x%x: OPCODE = 0x%x:SUB\n", inst, inst_log1->instruction.opcode);
		if (inst_log1->instruction.dstA.index == 0x28) {
			/* Skip the 0x28 reg as it is the SP reg */
			break;
		}
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
		dstA = BinaryOperator::CreateSub(srcA, srcB, buffer, bb);
		value[inst_log1->value3.value_id] = dstA;
		break;
	case 0x1e:  // RET
		printf("LLVM 0x%x: OPCODE = 0x%x:RET\n", inst, inst_log1->instruction.opcode);
		value_id = external_entry_point->label_redirect[inst_log1->value1.value_id].redirect;
		if (!value[value_id]) {
			tmp = LLVM_ir_export::fill_value(self, value, value_id, external_entry);
			if (tmp) {
				printf("failed LLVM Value is NULL\n");
				exit(1);
			}
		}
		srcA = value[value_id];
		ReturnInst::Create(Context, srcA, bb);
		break;
	case 0x25:  // LOAD
		printf("LLVM 0x%x: OPCODE = 0x%x:LOAD\n", inst, inst_log1->instruction.opcode);
		if (inst_log1->instruction.dstA.index == 0x28) {
			/* Skip the 0x28 reg as it is the SP reg */
			break;
		}
		printf("value_id1 = 0x%lx->0x%lx, value_id3 = 0x%lx->0x%lx\n",
			inst_log1->value1.indirect_value_id,
			external_entry_point->label_redirect[inst_log1->value1.indirect_value_id].redirect,
			inst_log1->value3.value_id,
			external_entry_point->label_redirect[inst_log1->value3.value_id].redirect);
		value_id = external_entry_point->label_redirect[inst_log1->value1.indirect_value_id].redirect;
		if (value_id) {
			srcA = value[value_id];
			tmp = label_to_string(&external_entry_point->labels[inst_log1->value3.value_id], buffer, 1023);
			dstA = new LoadInst(srcA, buffer, false, bb);
		} else {
			printf("LLVM 0x%x: FIXME: Invalid srcA value_id\n", inst);
		}

		value_id = external_entry_point->label_redirect[inst_log1->value3.value_id].redirect;
		if (value_id) {
			value[value_id] = dstA;
		} else {
			printf("LLVM 0x%x: FIXME: Invalid value_id\n", inst);
		}
		break;
	case 0x26:  // STORE
		printf("LLVM 0x%x: OPCODE = 0x%x:STORE\n", inst, inst_log1->instruction.opcode);
		if (inst_log1->instruction.dstA.index == 0x28) {
			/* Skip the 0x28 reg as it is the SP reg */
			break;
		}
		printf("value_id1 = 0x%lx->0x%lx, value_id3 = 0x%lx->0x%lx\n",
			inst_log1->value1.value_id,
			external_entry_point->label_redirect[inst_log1->value1.value_id].redirect,
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
		dstA = new StoreInst(srcA, srcB, false, bb);
		break;
	default:
		printf("LLVM 0x%x: OPCODE = 0x%x. Not yet handled.\n", inst, inst_log1->instruction.opcode);
		break;
	}

	return 0;
} 

int LLVM_ir_export::add_node_instructions(struct self_s *self, Value** value, BasicBlock *bb, int node, int external_entry) 
{
	struct inst_log_entry_s *inst_log1;
	struct inst_log_entry_s *inst_log_entry = self->inst_log_entry;
	struct control_flow_node_s *nodes = self->nodes;
	int nodes_size = self->nodes_size;
	int l,m,n;
	int inst;
	int inst_next;

	printf("LLVM Node 0x%x\n", node);
	inst = nodes[node].inst_start;
	inst_next = inst;

	do {
		inst = inst_next;
		inst_log1 =  &inst_log_entry[inst];
		add_instruction(self, value, bb, external_entry, inst);
		if (inst_log1->next_size > 0) {
			inst_next = inst_log1->next[0];
		}
	} while ((inst != nodes[node].inst_end) && (inst_log1->next_size != 0));

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
			exit(1);
		}
		return 0;
	} else {
		printf("LLVM fill_value(): label->scope = 0x%lx, label->type = 0x%lx\n",
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
			Module *M = new Module("test_llvm_export", Context);
 			M->setDataLayout("e-p:64:64:64-i1:8:8-i8:8:8-i16:16:16-i32:32:32-i64:64:64-f32:32:32-f64:64:64-v64:64:64-v128:128:128-a0:0:64-s0:64:64-f80:128:128-n8:16:32:64-S128");
			M->setTargetTriple("x86_64-pc-linux-gnu");

			function_name = external_entry_points[n].name;
			snprintf(output_filename, 500, "./llvm/%s.bc", function_name);
			std::vector<Type*>FuncTy_0_args;
			for (m = 0; m < external_entry_points[n].params_size; m++) {
				index = external_entry_points[n].params[m];
				int size = labels[index].size_bits;
				printf("Label 0x%x: size_bits = 0x%x\n", index, size);
				FuncTy_0_args.push_back(IntegerType::get(M->getContext(), size));
			}

			FunctionType *FT =
				FunctionType::get(Type::getInt32Ty(Context),
					FuncTy_0_args,
					false); /*not vararg*/

			Function *F = Function::Create(FT, Function::ExternalLinkage, function_name, M);

			Function::arg_iterator args = F->arg_begin();
			for (m = 0; m < external_entry_points[n].params_size; m++) {
				index = external_entry_points[n].params[m];
				value[index] = args;
				args++;
				tmp = label_to_string(&(labels[index]), buffer, 1023);
				printf("Adding param:%s:value index=0x%x\n", buffer, index);
				value[index]->setName(buffer);
			}

			BasicBlock **bb = (BasicBlock **)calloc(nodes_size + 1, sizeof (BasicBlock *));
			for (m = 1; m < nodes_size; m++) {
				std::string node_string;
				std::stringstream tmp_str;
				tmp_str << "Node_0x" << std::hex << m;
				node_string = tmp_str.str();
				printf("LLVM2: %s\n", node_string.c_str());
				bb[m] = BasicBlock::Create(Context, node_string, F);
			}

			Value *Two = ConstantInt::get(Type::getInt32Ty(Context), 2);
			Value *Three = ConstantInt::get(Type::getInt32Ty(Context), 3);
			Value *Four = value[external_entry_points[n].params[0]];

			/* Create the AllocaInst's */
			for (m = 0; m < labels_size; m++) {
				int size_bits;
				/* param_stack or local_stack */
				if (((labels[m].scope == 1) || 
					(labels[m].scope == 2)) &&
					(labels[m].type == 2)) {
					size_bits = labels[m].size_bits;
					/* FIXME: Make size_bits set correctly in the label */
					if (!size_bits) size_bits = 32;
					printf("Creating alloca for lable 0x%x, size_bits = 0x%x\n", m, size_bits);
					tmp = label_to_string(&labels[m], buffer, 1023);
					AllocaInst* ptr_local = new AllocaInst(IntegerType::get(M->getContext(), size_bits), buffer, bb[1]);
					ptr_local->setAlignment(size_bits >> 3);
					value[m] = ptr_local;
				}
			}
				
			/* FIXME: this needs the node to follow paths so the value[] is filled in the correct order */
			for (node = 1; node < nodes_size; node++) {
				printf("LLVM: node=0x%x\n", node);
				/* FIXME: Output PHI instructions first */
				/* FIXME: Output instuctions within the node */
				LLVM_ir_export::add_node_instructions(self, value, bb[node], node, n);
#if 0
				/* FIXME: Output terminator instructions */
				if (nodes[node].next_size == 0) {
					printf("NEXT0 FOUND Add, Ret3\n");
					//Value *Add = BinaryOperator::CreateAdd(Two, value[external_entry_points[n].params[0]], "addresult3", bb[node]);
					Value *Add = BinaryOperator::CreateAdd(Two, Four, "addresult3", bb[node]);
					/* FIXME: get the return correct, using value[]. */
					ReturnInst::Create(Context, Add, bb[node]);
				} else if (nodes[node].next_size == 1) {
					int found = 0;
					int branch_to_node = nodes[node].link_next[0].node;
					printf("NEXT1 FOUND add ret2 branch_to_node = 0x%x\n", branch_to_node);
					//tmp = find_function_member_node(self, &(external_entry_points[n]), branch_to_node, &l);
					//if (!tmp) {
					printf("Branch1 create: branch_to_node = 0x%x, node = 0x%x\n", branch_to_node, node);
					Value *Add = BinaryOperator::CreateAdd(Two, Three, "addresult2", bb[node]);
					BranchInst::Create(bb[branch_to_node], bb[node]);
					//} else {
					//	printf("NEXT NOT FOUND\n");
					//}
				} else if (nodes[node].next_size == 2) {
					int node_false;
					int node_true;
					int found1 = 0;
					int found2 = 0;
					int branch_to_node;
					branch_to_node = nodes[node].link_next[0].node;
					node_false = branch_to_node;
					//found1 = find_function_member_node(self, &(external_entry_points[n]), branch_to_node, &node_false);
					branch_to_node = nodes[node].link_next[1].node;
					node_true = branch_to_node;
					//found2 = find_function_member_node(self, &(external_entry_points[n]), branch_to_node, &node_true);
					//if ((!found1) && (!found2)) {
					//	printf("Branch1 create: l = 0x%x, m = 0x%x\n", l, m);
					//	printf("NEXT2 FOUND add ret1\n");
					Value *cmpInst = BinaryOperator::CreateAdd(Two, Three, "addresult1", bb[node]);
					BranchInst::Create(bb[node_false], bb[node_true], cmpInst, bb[node]);
					//} else {
					//	printf("NEXT2 NOT FOUND\n");
					//}
				} else {
					int found1 = 0;
					int branch_to_node;
					int node_case;
					branch_to_node = nodes[node].link_next[0].node;
					printf("NEXT3+ HANDLED YET\n");
					branch_to_node = nodes[node].link_next[0].node;
					node_case = branch_to_node;
					//found1 = find_function_member_node(self, &(external_entry_points[n]), branch_to_node, &node_case);
					Value *Add = BinaryOperator::CreateAdd(Two, Three, "addresult", bb[1]);
					Value *cmpInst = BinaryOperator::CreateAdd(Two, Three, "addresult1", bb[node]);
					SwitchInst *switch_inst = SwitchInst::Create(cmpInst, bb[node_case], nodes[node].next_size, bb[node]);
					for (l = 0; l < nodes[node].next_size; l++) {
						branch_to_node = nodes[node].link_next[l].node;
						node_case = branch_to_node;
						//found1 = find_function_member_node(self, &(external_entry_points[n]), branch_to_node, &node_case);
						const APInt ap_int1 = APInt::APInt(32, l, false);
						ConstantInt *const_int1 = ConstantInt::get(Context, ap_int1);
						switch_inst->addCase(const_int1, bb[node_case]);
					}
				}
#endif
			}
			std::string ErrorInfo;
			raw_fd_ostream OS(output_filename, ErrorInfo, sys::fs::F_Binary);

			if (!ErrorInfo.empty())
				return -1;

			WriteBitcodeToFile(M, OS);
			delete M;

			//Value *Add = BinaryOperator::CreateAdd(Two, Three, "addresult", bb[1]);
			//BranchInst::Create(bb[2], bb[1]);			
			//ReturnInst::Create(Context, Add, bb[2]);
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

