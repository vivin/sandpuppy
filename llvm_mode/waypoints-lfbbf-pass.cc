#include "basefeedback.hpp"

using namespace fuzzfactory;

class LibraryFunctionBasicBlockFeedback : public BaseLibraryFunctionFeedback<LibraryFunctionBasicBlockFeedback> {

public:
    LibraryFunctionBasicBlockFeedback(Module& M) : BaseLibraryFunctionFeedback<LibraryFunctionBasicBlockFeedback>(M, "lfbbf", "__afl_lfbbf_dsf") { }

    void visitBasicBlock(BasicBlock& basicBlock) {
        // Compared to "lff", "lfbbf" is different. It keeps track of the basic block in which the function is called.
        // So this means that given these two paths:
        //  o bb1.alloc->bb2.alloc->bb2.alloc->bb4.free->bb4.free->bb4.free
        //  o bb1.alloc->bb1.alloc->bb2.alloc->bb4.free->bb4.free->bb4.free
        // they are treated differently even though the total number of heap ops are the same.
        //
        // todo: take order into account. so given: bb1.a->bb2.a and bb2.a->bb1.a, it treats it as different because
        // todo: order matters. this is the same as the basic block transition count.
        auto irb = insert_before(basicBlock);
        auto key = createProgramLocation(); // static random value

        for (Instruction &instruction : basicBlock) {
            if (isa<CallInst>(instruction)) {
                auto &call = cast<CallInst>(instruction);
                Function *function = call.getCalledFunction();
                if (!function) {
                    continue;
                }

                if (shouldInterceptFunction(function)) {
                    auto fIrb = insert_before(call);
                    fIrb.CreateCall(DsfIncrementFunction, {DsfMapVariable, key, getConst(1)});
                }
            }
        }
    }
};

FUZZFACTORY_REGISTER_DOMAIN(LibraryFunctionBasicBlockFeedback);
