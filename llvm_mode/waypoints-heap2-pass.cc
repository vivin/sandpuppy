#include "basefeedback.hpp"

using namespace fuzzfactory;

class HeapOp2Feedback : public BaseLibFuncFeedback<HeapOp2Feedback> {

    int bbCounter = 0;

public:
    HeapOp2Feedback(Module& M) : BaseLibFuncFeedback<HeapOp2Feedback>(M, "heap2", "__afl_heap2_dsf") { }

    void visitBasicBlock(BasicBlock& basicBlock) {
        // Compared to "heap", "heap2" is different. It keeps track of the basic block in which the heap-op function
        // is called. So this means that given these two paths:
        //  o bb1.alloc->bb2.alloc->bb2.alloc->bb4.free->bb4.free->bb4.free
        //  o bb1.alloc->bb1.alloc->bb2.alloc->bb4.free->bb4.free->bb4.free
        // they are treated differently even though the total number of heap ops are the same.
        //
        // todo: take order into account. so given: bb1.a->bb2.a and bb2.a->bb1.a, it treats it as different because
        // todo: order matters. this is the same as the basic block transition count.
        auto irb = insert_before(basicBlock);
        createCreateTraceFileIfNotExistsCall(irb);

        auto key = createProgramLocation(); // static random value

        for (Instruction &instruction : basicBlock) {
            if (isa<CallInst>(instruction)) {
                auto &call = cast<CallInst>(instruction);
                Function *function = call.getCalledFunction();
                if (!function) {
                    continue;
                }

                if (function->getName() == "malloc" || function->getName() == "calloc" || function->getName() == "free") {
                    auto functionIrb = insert_before(call);
                    functionIrb.CreateCall(DsfIncrementFunction, {DsfMapVariable, key, getConst(1)});

                    std::string text = (function->getName().str() + "." + std::to_string(bbCounter));
                    createAppendTraceCall(functionIrb, text);
                }
            }
        }

        bbCounter++;
    }
};

FUZZFACTORY_REGISTER_DOMAIN(HeapOp2Feedback);
