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
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	
	Module *M = new Module("test_llvm_export", Context);

	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if ((external_entry_points[n].valid != 0) &&
			(external_entry_points[n].member_nodes_size)) {
			function_name = external_entry_points[n].name;
			FunctionType *FT =
				FunctionType::get(Type::getInt32Ty(Context), /*not vararg*/false);

			Function *F = Function::Create(FT, Function::ExternalLinkage, function_name, M);

			BasicBlock **bb = (BasicBlock **)calloc(external_entry_points[n].member_nodes_size + 1, sizeof (BasicBlock *));
			for (m = 1; m <= external_entry_points[n].member_nodes_size; m++) {
				std::string node_string;
				std::stringstream tmp_str;
				tmp_str << "Node_0x" << std::hex << m;
				node_string = tmp_str.str();
				bb[m] = BasicBlock::Create(Context, node_string, F);
			}
			Value *Two = ConstantInt::get(Type::getInt32Ty(Context), 2);
			Value *Three = ConstantInt::get(Type::getInt32Ty(Context), 3);

			Value *Add = BinaryOperator::CreateAdd(Two, Three, "addresult", bb[1]);
			BranchInst::Create(bb[2], bb[1]);			
			ReturnInst::Create(Context, Add, bb[2]);
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
