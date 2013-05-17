/* Test creation of a .bc file for LLVM IR*/

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <stdlib.h>
#include <stdio.h>
//#include "llvm.h"
//#include <rev.h>
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
	struct external_entry_point_s *external_entry_points = self->external_entry_points;
	
	Module *M = new Module("test_llvm_export", Context);

	for (n = 0; n < EXTERNAL_ENTRY_POINTS_MAX; n++) {
		if (external_entry_points[n].valid != 0) {
			function_name = external_entry_points[n].name;
			FunctionType *FT =
				FunctionType::get(Type::getInt32Ty(Context), /*not vararg*/false);

			Function *F = Function::Create(FT, Function::ExternalLinkage, function_name, M);

			BasicBlock *BB = BasicBlock::Create(Context, "EntryBlock", F);

			Value *Two = ConstantInt::get(Type::getInt32Ty(Context), 2);
			Value *Three = ConstantInt::get(Type::getInt32Ty(Context), 3);

			Value *Add = BinaryOperator::CreateAdd(Two, Three,
				"addresult", BB);
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
