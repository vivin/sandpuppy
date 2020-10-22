#include "basefeedback.hpp"
#include <iostream>

using namespace fuzzfactory;

cl::opt<std::string> TraceDirectory(
    "trace_directory",
    cl::desc("Output directory for library function traces."),
    cl::value_desc("trace_directory")
);

bool hasTraceDirectory() {
    return !TraceDirectory.empty();
}

class TraceLibraryFunctionFeedback : public BaseLibraryFunctionFeedback<TraceLibraryFunctionFeedback> {

    Function *appendTraceFunction;
    Function *createTraceFileIfNotExistsFunction;
    Value* traceDirectory = NULL;
    int bbCounter = 0;

    void createAppendTraceCall(CallInst& call) {
        auto irb = insert_after(call);

        std::string format = getFunctionSignatureFormat(call);
        Value *formatStringValue = irb.CreateGlobalString(
            StringRef(format),
            "formatString"
        );

        Value *sourceFileNameValue = irb.CreateGlobalString(call.getModule()->getSourceFileName());
        Function *function = call.getCalledFunction();
        Value *functionNameValue = irb.CreateGlobalString(function->getName());
        Value *bbNumber = getConst(bbCounter);

        // Start setting up args for __append_trace
        std::vector<Value *> appendTraceArgs;

        appendTraceArgs.push_back(traceDirectory); // first concrete argument is dirname (name of trace directory)
        appendTraceArgs.push_back(formatStringValue); // second concrete argument is format (format string)

        // now we will set up the varargs
        appendTraceArgs.push_back(sourceFileNameValue); // first %s of %s: %s.%d
        appendTraceArgs.push_back(functionNameValue); // second %s of %s: %s.%d
        appendTraceArgs.push_back(bbNumber); // %d part of %s: %s.%d

        // push in all the operand values we have
        for (unsigned int i = 0; i < call.getNumArgOperands(); i++) {
            Value* op = call.getOperand(i);
            appendTraceArgs.push_back(op);
        }

        // If return type is not void, we need to add the return value for the '= %s' at the end of the format string
        if (!function->getReturnType()->isVoidTy()) {
            appendTraceArgs.push_back(&call);
        }

        irb.CreateCall(appendTraceFunction, appendTraceArgs);
    }

    void createCreateTraceFileIfNotExistsCall(IRBuilder<> &irb) {
        if (!hasTraceDirectory()) {
            return;
        }

        if (traceDirectory == NULL) {
            traceDirectory = irb.CreateGlobalString(
                StringRef(TraceDirectory),
                "traceDirectory"
            );
        }

        irb.CreateCall(createTraceFileIfNotExistsFunction, {traceDirectory});
    }

    static std::string getFormatSpecifierForType(Type* type) {
        //std::string str;
        //llvm::raw_string_ostream rso(str);
        //type->print(rso);

        if (type->isIntegerTy()) {
            return "%d";
        } else if (type->isFloatTy()) {
            return "%.9g";
        } else if (type->isDoubleTy()) {
            return "%.17g";
        } else {
            return "%p";
        }
    }

    std::string getFunctionSignatureFormat(CallInst& call) {
        Function *function = call.getCalledFunction();
        std::string nameFormat = "%s: %s.%d"; // name format contains source filename as well!

        //std::cout << " function " << function->getName().str() << " has num operands " << function->getNumOperands() << " call num operands " << call.getNumArgOperands() << "\n";

        std::vector<std::string> argFormats;
        for (unsigned int i = 0; i < call.getNumArgOperands(); i++) {
            Type* type = call.getOperand(i)->getType();
            argFormats.emplace_back(getFormatSpecifierForType(type));
        }

        std::stringstream stream;
        copy(argFormats.begin(), argFormats.end(), std::ostream_iterator<std::string>(stream, ", "));
        std::string paramsFormat = stream.str();

        // Remove trailing ', '
        paramsFormat.pop_back();
        paramsFormat.pop_back();

        Type* returnType = function->getReturnType();
        std::string returnTypeFormat = getFormatSpecifierForType(returnType);

        std::string format = nameFormat + "(" + paramsFormat + ")";
        if (!returnType->isVoidTy()) {
            format += " = " + returnTypeFormat;
        }
// TODO: change your damn perl script to use trace now. you don't need to recompile all the libpng stuff.
// TODO: you can just build a trace version of it and then run it against all the generated inputs.
        //std::cout << "for function " << function->getName().str() << " i got format string: " << format << "\n";
        return format;
    }

public:
    TraceLibraryFunctionFeedback(Module &M) : BaseLibraryFunctionFeedback<TraceLibraryFunctionFeedback>(M, "trace", "__afl_trace_dsf") {
        if (!hasTraceDirectory()) {
            std::cerr << "Trace directory must be provided using -trace_directory option.\n";
            return;
        }

        appendTraceFunction = this->resolveFunction(
            "__append_trace",
            this->getVoidTy(),
            {this->getIntTy(8), this->getIntTy(8)},
            true
        );
        createTraceFileIfNotExistsFunction = this->resolveFunction(
            "__create_trace_file_if_not_exists",
            this->getVoidTy(),
            {this->getIntTy(8)}
        );
    }

    void visitBasicBlock(BasicBlock &basicBlock) {
        auto irb = insert_before(basicBlock);
        createCreateTraceFileIfNotExistsCall(irb);

        for (Instruction &instruction : basicBlock) {
            if (isa<CallInst>(instruction)) {
                auto &call = cast<CallInst>(instruction);
                Function *function = call.getCalledFunction();
                if (!function) {
                    continue;
                }

                if (shouldInterceptFunction(function)) {
                    //std::cout << "The function is " << function->getName().str()  << "\n";
                    createAppendTraceCall(call);
                }
            }
        }

        bbCounter++;
    }
};

// TODO: get libpng 1.5.8 -- it has a buffer overflow that is maybe easier to trigger. 1.5.9 also has an overflow but
// TODO: it only comes from text chunks... so harder to trigger. for 1.5.9, see if you can generate a test image with
// TODO: a text chunk and then fuzz using that.
// TODO:
// TODO: ALSO, take a look at the testbed used in the paper that @fish sent you. use those programs.

FUZZFACTORY_REGISTER_DOMAIN(TraceLibraryFunctionFeedback);
