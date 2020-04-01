#include "fuzzfactory.hpp"

using namespace fuzzfactory;

class HeapOp2Feedback : public DomainFeedback<HeapOp2Feedback> {
public:
    HeapOp2Feedback(Module& M) : DomainFeedback<HeapOp2Feedback>(M, "__afl_heap2_dsf") { }

    void visitBasicBlock(BasicBlock& basicBlock) {
        // Compared to "heap", "heap2" is different. It keeps track of the basic block in which the heap-op function
        // is called. So this means that given these two paths:
        //  o bb1.alloc->bb2.alloc->bb2.alloc->bb4.free->bb4.free->bb4.free
        //  o bb1.alloc->bb1.alloc->bb2.alloc->bb4.free->bb4.free->bb4.free
        // they are treated differently even though the total number of heap ops are the same.
        //
        // todo: take order into account. so given: bb1.a->bb2.a and bb2.a->bb1.a, it treats it as different because
        // todo: order matters. this is the same as the basic block transition count.

        auto key = createProgramLocation(); // static random value

        for (Instruction &instruction : basicBlock) {
            if (isa<CallInst>(instruction)) {
                auto &call = cast<CallInst>(instruction);
                Function *function = call.getCalledFunction();
                if (!function) {
                    continue;
                }

                if (function->getName() == "malloc" || function->getName() == "calloc" || function->getName() == "free") {
                    auto irb = insert_before(call);
                    irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, key, getConst(1)});
                }
            }
        }
    }
};

FUZZFACTORY_REGISTER_DOMAIN(HeapOp2Feedback);
