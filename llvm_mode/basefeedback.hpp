//
// Created by vivin on 3/31/20.
//
#define AFL_LLVM_PASS

#include "fuzzfactory.hpp"

#ifndef BASEFEEDBACK_H
#define BASEFEEDBACK_H

using namespace fuzzfactory;

cl::opt<std::string> TraceDirectory(
        "trace_directory",
        cl::desc("Output directory for traces."),
        cl::value_desc("trace_directory"));

bool hasTraceDirectory() {
    return !TraceDirectory.empty();
}

/** Base class for library function feedback instrumentation **/
template<class V>
class BaseLibFuncFeedback : public DomainFeedback<V> {

private:

    StringRef domainName;
    Function* appendTraceFunction;
    Function* createTraceFileIfNotExistsFunction;

public:

    BaseLibFuncFeedback<V>(Module &M, const StringRef &domainName, const StringRef &dsfVarName) : DomainFeedback<V>(M, dsfVarName) {
        this->appendTraceFunction = this->resolveFunction(
            "__append_trace",
            this->getVoidTy(),
            {this->getIntTy(8), this->getIntTy(8), this->getIntTy(8)}
        );
        this->createTraceFileIfNotExistsFunction = this->resolveFunction(
            "__create_trace_file_if_not_exists",
            this->getVoidTy(),
            {this->getIntTy(8), this->getIntTy(8)}
        );
        this->domainName = domainName;
    }

protected:

    void createAppendTraceCall(IRBuilder<> &irb, const StringRef &text) {
        if (!hasTraceDirectory()) {
            return;
        }

        Value* traceDirectory = irb.CreateGlobalString(
            StringRef(TraceDirectory),
            "traceDirectory"
        );
        Value* prefix = irb.CreateGlobalString(
            StringRef(domainName),
            "feedbackClass"
        );
        Value* textValue = irb.CreateGlobalString(text);

        irb.CreateCall(appendTraceFunction, {traceDirectory, prefix, textValue});
    }

    void createCreateTraceFileIfNotExistsCall(IRBuilder<> &irb) {
        if (!hasTraceDirectory()) {
            return;
        }

        Value* traceDirectory = irb.CreateGlobalString(
                StringRef(TraceDirectory),
                "traceDirectory"
        );
        Value* prefix = irb.CreateGlobalString(
                StringRef(domainName),
                "feedbackClass"
        );

        irb.CreateCall(createTraceFileIfNotExistsFunction, {traceDirectory, prefix});
    }
};
#endif //BASEFEEDBACK_H
