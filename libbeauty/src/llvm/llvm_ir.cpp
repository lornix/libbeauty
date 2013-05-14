/* Test creation of a .bc file for LLVM IR*/

#define __STDC_LIMIT_MACROS
#define __STDC_CONSTANT_MACROS

#include <stdlib.h>
#include <stdio.h>
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Constants.h"
#include "llvm/Instructions.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Support/raw_ostream.h"
using namespace llvm;

extern "C" int llvm_export(struct external_entry_point_s *external_entry_point) {
  LLVMContext Context;
	const char *Path = "test_llvm_export.bc";
//	const char *function_name = external_entry_point->name;
	const char *function_name = "test123";
//	llvm::raw_ostream *OutFile;

  // Create the "module" or "program" or "translation unit" to hold the
  // function
  Module *M = new Module("test_llvm_export", Context);

  // Create the main function: first create the type 'int ()'
  FunctionType *FT =
    FunctionType::get(Type::getInt32Ty(Context), /*not vararg*/false);

  // By passing a module as the last parameter to the Function constructor,
  // it automatically gets appended to the Module.
  Function *F = Function::Create(FT, Function::ExternalLinkage, function_name, M);

  // Add a basic block to the function... again, it automatically inserts
  // because of the last argument.
  BasicBlock *BB = BasicBlock::Create(Context, "EntryBlock", F);

  // Get pointers to the constant integers...
  Value *Two = ConstantInt::get(Type::getInt32Ty(Context), 2);
  Value *Three = ConstantInt::get(Type::getInt32Ty(Context), 3);

  // Create the add instruction... does not insert...
//  Instruction *Add = BinaryOperator::Create(Instruction::Add, Two, Three,
//                                            "addresult");
  Value *Sum = BinaryOperator::CreateAdd(Two, Three,
                                         "addresult", BB);
  // explicitly insert it into the basic block...
//  BB->getInstList().push_back(Add);

  // Create the return instruction and add it to the basic block
//  BB->getInstList().push_back(ReturnInst::Create(Context, Add));

  // Output the bitcode file 
//	std::string Err;
//	OutFile = new llvm::raw_fd_ostream("test_llvm_export", Err);
//	WriteBitcodeToFile(M, *OutFile);
  std::string ErrorInfo;
  raw_fd_ostream OS(Path, ErrorInfo,
                    raw_fd_ostream::F_Binary);

  if (!ErrorInfo.empty())
    return -1;

	WriteBitcodeToFile(M, OS);
//	WriteBitcodeToFile(M, outs());
  // Delete the module and all of its contents.
  delete M;
  return 0;
}
