#include "fuzzfactory.hpp"

using namespace fuzzfactory;

class HeapOpAsanFeedback : public DomainFeedback<HeapOpAsanFeedback> {
public:
    HeapOpAsanFeedback(Module& M) : DomainFeedback<HeapOpAsanFeedback>(M, "__afl_heapasan_dsf") { }

    void visitBasicBlock(BasicBlock& basicBlock) {
        for (Instruction &instruction : basicBlock) {
            if (isa<CallInst>(instruction)) {
                auto &call = cast<CallInst>(instruction);
                Function *function = call.getCalledFunction();
                if (!function) {
                    continue;
                }

                if (function->getName() == "malloc" || function->getName() == "calloc" || function->getName() == "free") {
                    auto irb = insert_before(call);
                    irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, getConst(0), getConst(1)});
                }
            }
        }
    }
};

FUZZFACTORY_REGISTER_DOMAIN(HeapOpAsanFeedback);
