#include <iostream>
#include <fstream>
#include <unistd.h>
#include "fuzzfactory.hpp"

using namespace fuzzfactory;

cl::opt<std::string> TraceDirectory(
    "trace_directory",
    cl::desc("Output directory for traces."),
    cl::value_desc("trace_directory"));

class HeapOpTraceFeedback : public DomainFeedback<HeapOpTraceFeedback> {
public:
    HeapOpTraceFeedback(Module& M) : DomainFeedback<HeapOpTraceFeedback>(M, "__afl_heap_dsf") {
        if (TraceDirectory.empty()) {
            std::cerr << "Need to specify -trace_directory!\n";
            errs() << "-trace_directory not specified\n";
            return;
        }
    }

    void visitBasicBlock(BasicBlock& basicBlock) {
        for (Instruction &instruction : basicBlock) {
            if (isa<CallInst>(instruction)) {
                auto &call = cast<CallInst>(instruction);
                Function *function = call.getCalledFunction();
                if (!function) {
                    continue;
                } // todo: only increment if we see a free called after at least 1 alloc. this exercises alloc-free paths.
                  // todo: incorporate asan in some way. basically we want to prioritize paths with buff overflows. so we
                  // todo: want to check if something reads/writes outside a buff area. how to do that? use implementation
                  // todo: like asan? poisoned bytes?? then if we write to loc that has poisoned bytes we increment counter
                  // todo: by 2 maybe? or maybe a separate counter for overflows? then we can combine both heap and this
                  // todo: domain-specific fuzzer. guides coverage towards paths that maximize heap ops and buff overflows.

                if (function->getName() == "malloc" || function->getName() == "calloc" || function->getName() == "free") {
                    auto irb = insert_before(call);
                    irb.CreateCall(DsfIncrementFunction, {DsfMapVariable, getConst(0), getConst(1)});

                    Function* traceFunction = resolveFunction("__append_trace", getVoidTy(), { getIntTy(8), getIntTy(8), getIntTy(8) });

                    Value* traceDirectory = irb.CreateGlobalString(StringRef(TraceDirectory), "traceDirectory");
                    Value* prefix = irb.CreateGlobalString(StringRef("heaptrace"));
                    Value* functionName = irb.CreateGlobalString(function->getName());

                    irb.CreateCall(traceFunction, {traceDirectory, prefix, functionName});
                }
            }
        }
    }
};

FUZZFACTORY_REGISTER_DOMAIN(HeapOpTraceFeedback);
