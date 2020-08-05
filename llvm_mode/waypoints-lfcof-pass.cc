#include <iostream>
#include "basefeedback.hpp"

using namespace fuzzfactory;

class LibraryFunctionCallOrderFeedback : public BaseLibraryFunctionFeedback<LibraryFunctionCallOrderFeedback> {

    GlobalVariable* previousLocation = NULL;
    int bbCounter = 0;

public:
    LibraryFunctionCallOrderFeedback(Module& M) : BaseLibraryFunctionFeedback<LibraryFunctionCallOrderFeedback>(M, "lfcof", "__afl_lfcof_dsf") {
        // Create reference to previous location. __afl_lfcof_prev_loc is a thread local.
        previousLocation = new GlobalVariable(
            M,
            Int32Ty,
            false,
            GlobalValue::ExternalLinkage,
            0,
            "__afl_lfcof_prev_loc",
            0,
            GlobalVariable::GeneralDynamicTLSModel,
            0,
            false
        );
    }

    void visitBasicBlock(BasicBlock& basicBlock) {
        // Like lfbbf, but takes order into account. so bb1.alloc -> bb2.alloc is different from bb2.alloc -> bb1.alloc.
        auto irb = insert_before(basicBlock);

        // Create static random value for current location
        uint32_t currentLocationHash = generateRandom31();
        auto currentLocation = getConst(currentLocationHash);

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

                if (shouldInterceptFunction(function)) {
                    auto fIrb = insert_before(call);

                    // Increment map using index which is prevLoc XOR currLoc
                    fIrb.CreateCall(DsfIncrementFunction, {DsfMapVariable, xored, getConst(1)});
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

        bbCounter++;
    }
};

FUZZFACTORY_REGISTER_DOMAIN(LibraryFunctionCallOrderFeedback);
