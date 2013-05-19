/* Test creation of a .bc file for LLVM IR*/

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <stdlib.h>
#include <stdio.h>
//#include "llvm.h"
//#include <rev.h>
#include <string>
#include <sstream>
#include <global_struct.h>
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Constants.h"
#include "llvm/Instructions.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

extern "C" int llvm_export(struct self_s *self) {
	LLVMContext Context;
	const char *Path = "test_llvm_export.bc";
	const char *function_name = "test123";
	int n;
	int m;
	int l;
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	struct control_flow_node_s *nodes = self->nodes;
	int nodes_size = self->nodes_size;
	
	Module *M = new Module("test_llvm_export", Context);

	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if ((external_entry_points[n].valid != 0) &&
			(external_entry_points[n].member_nodes_size)) {
			function_name = external_entry_points[n].name;
			FunctionType *FT =
				FunctionType::get(Type::getInt32Ty(Context), /*not vararg*/false);

			Function *F = Function::Create(FT, Function::ExternalLinkage, function_name, M);

			BasicBlock **bb = (BasicBlock **)calloc(external_entry_points[n].member_nodes_size + 1, sizeof (BasicBlock *));
			for (m = 0; m < external_entry_points[n].member_nodes_size; m++) {
				std::string node_string;
				std::stringstream tmp_str;
				tmp_str << "Node_0x" << std::hex << external_entry_points[n].member_nodes[m];
				node_string = tmp_str.str();
				printf("LLVM: %s\n", node_string.c_str());
				bb[m] = BasicBlock::Create(Context, node_string, F);
			}

			Value *Two = ConstantInt::get(Type::getInt32Ty(Context), 2);
			Value *Three = ConstantInt::get(Type::getInt32Ty(Context), 3);

			for (m = 0; m < external_entry_points[n].member_nodes_size; m++) {
				int node = external_entry_points[n].member_nodes[m];
				printf("LLVM: node=0x%x, m=0x%x\n", node, m);
				if (nodes[node].next_size == 0) {
					printf("NEXT0 FOUND Add, Ret3\n");
					Value *Add = BinaryOperator::CreateAdd(Two, Three, "addresult3", bb[m]);
					ReturnInst::Create(Context, Add, bb[m]);
				} else if (nodes[node].next_size == 1) {
					int found = 0;
					int branch_to_node = nodes[node].link_next[0].node;
					printf("NEXT1 FOUND add ret2 branch_to_node = 0x%x\n", branch_to_node);
					for (l = 0; l < external_entry_points[n].member_nodes_size; l++) {
						if (branch_to_node == external_entry_points[n].member_nodes[l]) {
							found = 1;
							break;
						}
					}
					if (found) {
						printf("Branch1 create: l = 0x%x, m = 0x%x\n", l, m);
						Value *Add = BinaryOperator::CreateAdd(Two, Three, "addresult2", bb[m]);
						BranchInst::Create(bb[l], bb[m]);
					} else {
						printf("NEXT NOT FOUND\n");
					}
				} else if (nodes[node].next_size == 2) {
					int node_false;
					int node_true;
					int found1 = 0;
					int found2 = 0;
					int branch_to_node;
					branch_to_node = nodes[node].link_next[0].node;
					for (l = 0; l < external_entry_points[n].member_nodes_size; l++) {
						if (branch_to_node == external_entry_points[n].member_nodes[l]) {
							found1 = 1;
							node_false = l;
							break;
						}
					}
					branch_to_node = nodes[node].link_next[1].node;
					for (l = 0; l < external_entry_points[n].member_nodes_size; l++) {
						if (branch_to_node == external_entry_points[n].member_nodes[l]) {
							found2 = 1;
							node_true = l;
							break;
						}
					}
					if (found1 && found2) {
						printf("Branch1 create: l = 0x%x, m = 0x%x\n", l, m);
						printf("NEXT2 FOUND add ret1\n");
						Value *cmpInst = BinaryOperator::CreateAdd(Two, Three, "addresult1", bb[m]);
						BranchInst::Create(bb[node_false], bb[node_true], cmpInst, bb[m]);
					} else {
						printf("NEXT2 NOT FOUND\n");
					}
				}
			}

			//Value *Add = BinaryOperator::CreateAdd(Two, Three, "addresult", bb[1]);
			//BranchInst::Create(bb[2], bb[1]);			
			//ReturnInst::Create(Context, Add, bb[2]);
		}
	}

	std::string ErrorInfo;
	raw_fd_ostream OS(Path, ErrorInfo, raw_fd_ostream::F_Binary);

	if (!ErrorInfo.empty())
		return -1;

	WriteBitcodeToFile(M, OS);
	delete M;
	return 0;
}
