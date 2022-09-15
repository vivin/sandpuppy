#include "basevvfeedback.hpp"
#include "../include/vvdump.h"

using namespace fuzzfactory;

class BasicBlockPrintFeedback : public BaseVariableValueFeedback<BasicBlockPrintFeedback> {

    Function* printBasicBlockNameFunction;
    int basicBlockNumber = 0;

public:
    explicit BasicBlockPrintFeedback(llvm::Module& M) : BaseVariableValueFeedback<BasicBlockPrintFeedback>(M, "bbprint", "__afl_bbprint_dsf") {
        printBasicBlockNameFunction = this->resolveFunction(
            "__print_basic_block_name",
            this->getVoidTy(),
            {
                this->getIntTy(8)
            }
        );
    }

protected:
    bool shouldProcess(Function &function) override {
        return false;
    }

    void processFunction(Function &function) override {

    }

public:
    void visitBasicBlock(llvm::BasicBlock &basicBlock) {
        std::string sanitizedFilename = std::regex_replace(
            std::regex_replace(basicBlock.getModule()->getSourceFileName(), std::regex("^\\./"), ""),
            std::regex("[/]"),
            "_"
        );
        std::string basicBlockName = sanitizedFilename + "_" + basicBlock.getName().str() + "_" + std::to_string(basicBlockNumber);
        std::string basicBlockNameVariableName = "__bbname_" + basicBlockName;
        Value *basicBlockNameValue = getOrCreateGlobalStringVariable(
            basicBlock.getModule(),
            basicBlockNameVariableName,
            basicBlockName
        );

        std::cout << "#BB#:" << basicBlockName << std::endl;

        auto irb = insert_before(basicBlock);

        std::vector<Value *> args;
        args.push_back(basicBlockNameValue);

        irb->CreateCall(printBasicBlockNameFunction, args);
        basicBlockNumber++;
    }
};

FUZZFACTORY_REGISTER_DOMAIN(BasicBlockPrintFeedback);
