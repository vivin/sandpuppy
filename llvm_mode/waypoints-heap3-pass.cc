#include "fuzzfactory.hpp"

using namespace fuzzfactory;

class HeapOp3Feedback : public DomainFeedback<HeapOp3Feedback> {

    GlobalVariable* previousLocation = NULL;

public:
    HeapOp3Feedback(Module& M) : DomainFeedback<HeapOp3Feedback>(M, "__afl_heap3_dsf") {
        // Create reference to previous location. __afl_heap3_prev_loc is a thread local.
        previousLocation = new GlobalVariable(
            M,
            Int32Ty,
            false,
            GlobalValue::ExternalLinkage,
            0,
            "__afl_heap3_prev_loc",
            0,
            GlobalVariable::GeneralDynamicTLSModel,
            0,
            false
        );
    }

    void visitBasicBlock(BasicBlock& basicBlock) {
        // Like heap2, but takes order into account. so bb1.alloc -> bb2.alloc is different from bb2.alloc -> bb1.alloc.

        // Create static random value for current location
        uint32_t currentLocationHash = generateRandom31();
        auto currentLocation = getConst(currentLocationHash);

        auto irb = insert_before(basicBlock);

        // Load previousLocation
        LoadInst *loadPreviousLocation = irb.CreateLoad(previousLocation);
        loadPreviousLocation->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *previousLocationCasted = irb.CreateZExt(loadPreviousLocation, Int32Ty);

        // XOR previousLocation with currentLocation
        Value *xored = irb.CreateXor(previousLocationCasted, currentLocation);

        for (Instruction &instruction : basicBlock) {
            if (isa<CallInst>(instruction)) {
                auto &call = cast<CallInst>(instruction);
                Function *function = call.getCalledFunction();
                if (!function) {
                    continue;
                }

                if (function->getName() == "malloc" || function->getName() == "calloc" || function->getName() == "free") {
                    auto functionIrb = insert_before(call);

                    // Increment map using index which is prevLoc XOR currLoc
                    functionIrb.CreateCall(DsfIncrementFunction, {DsfMapVariable, xored, getConst(1)});
                }
            }
        }

        // Now set previousLocation to currentLocation >> 1 (this is so that transitions A->B and B->A
        // will be considered distinct)
        StoreInst *storePreviousLocation = irb.CreateStore(
            ConstantInt::get(Int32Ty, currentLocationHash >> 1),
            previousLocation
        );
        storePreviousLocation->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
    }
};

FUZZFACTORY_REGISTER_DOMAIN(HeapOp3Feedback);
