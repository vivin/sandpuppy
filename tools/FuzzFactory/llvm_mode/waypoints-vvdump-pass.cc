#include "basevvfeedback.hpp"
#include "../include/vvdump.h"

using namespace fuzzfactory;

/**
 * This ONLY works with -O0 -g -gfull! We look for debug declares to find out where vars are declared. We also maintain
 * a cache of variable names. Then we look for all store insts and check to see if any operands are variables that we
 * have seen. if so we report that as a change of the variable's value. We also deal with struct fields.
 */
class VariableValueDumpFeedback : public BaseVariableValueFeedback<VariableValueDumpFeedback> {
    Value *sourceFileNameValue;
    Value *functionNameValue;

    std::map<std::string, Value*> variableNameToValue;
    std::map<std::string, Value*> formatStringToValue;
    std::set<std::string> ignoredFunctions;

    Function *dumpVariableValueFunction;

    static bool modifiesIntegerVariable(StoreInst* store) {
        return store->getDebugLoc() && store->getValueOperand()->getType()->isIntegerTy();
    }

    bool initializesIntegerFunctionArgument(StoreInst* store, const std::string& variableName) {
        Type* valueType = store->getValueOperand()->getType();
        /*std::cout << variableName << "is function arg: " << isFunctionArgument(variableName) << "\n"
                  << "value operand is integer type: " << valueType->isIntegerTy() << "\n"
                  << "value operand is pointer type: " << valueType->isPointerTy() << "\n";
        if (valueType->isPointerTy()) {
            std::cout << "resolves to integer: " << isPointerTypeResolvingToIntegerType(cast<PointerType>(valueType)) << "\n";
        }*/

        // We will ignore ints with width 8, meaning that we will ignore bytes and pointers to bytes. This is because
        // we currently ignore char* pointers which are usually strings.
        bool result = isFunctionArgument(variableName)
                 && (valueType->isIntegerTy()
                     || (valueType->isPointerTy()
                         && isPointerTypeResolvingToIntegerType(valueType)
                         && unwrapPointerTypeToIntegerType(valueType)->getIntegerBitWidth() > 8));

        //std::cout << "result is " << result << "\n";
        return result;
    }

    void instrumentIfNecessary(Function* function, StoreInst *store) {
        std::string sourceFileName= store->getModule()->getSourceFileName();
        std::string functionName = function->getName();

        Value* variable = store->getPointerOperand();
        std::string variableName = getVariableName(variable);

        // Only instrument if we could get a variable name and if the variable is not involved in pointer arithmetic
        // (doesn't make sense to log the value because the pointer could be to a set of value likes an array) and if
        // the store instruction is modifying an integer variable or if the store instruction is initializing an integer
        // function argument (we want to log those values).
        if (!variableName.empty() && !isInvolvedInPointerArithmetic(variableName)
            && (modifiesIntegerVariable(store) || initializesIntegerFunctionArgument(store, variableName))) {
                createDumpVariableValueCall(function, store, variableName);
        }
    }

    void createDumpVariableValueCall(Function* function, StoreInst* store, const std::string& variableName) {
        auto irb = insert_after(*store);

        // If this is a function argument and it is a pointer, we need to safely dereference (i.e., with null checks)
        // its value so that we can print it.
        Value* value = store->getValueOperand();
        if (isFunctionArgument(variableName) && value->getType()->isPointerTy()) {
            value = safelyDereferenceStoreValueOperand(store, variableName, irb);
        }

        Value *variableNameValue = variableNameToValue[variableName];
        if (!variableNameValue) {
            std::string variableVariableName = "__vvdump_variable_" + getQualifiedVariableName(function, variableName);
            variableNameValue = getOrCreateGlobalStringVariable(
                function->getParent(),
                variableVariableName,
                variableName
            );
            variableNameToValue[variableName] = variableNameValue;
        }

        Value *declaredLineValue = getConst(varToDeclaredLine[variableName]);
        Value *modifiedLineValue = store->getDebugLoc() ? getConst((int) store->getDebugLoc()->getLine())
                                                        : getConst(varToDeclaredLine[variableName]);

        std::string valueFormatString = getFormatSpecifierForValue(value);
        Value *formatStringValue = formatStringToValue[valueFormatString];
        if (!formatStringValue) {
            formatStringValue = getOrCreateGlobalStringVariable(
                function->getParent(),
                "__vvdump_format_string_" + std::regex_replace(valueFormatString, std::regex("[:%\\.]"), "_"),
                valueFormatString
            );
            formatStringToValue[valueFormatString] = formatStringValue;
        }

        // Start setting up args for __dump_variable_value
        std::vector<Value *> dumpVariableValueArgs;

        dumpVariableValueArgs.push_back(sourceFileNameValue); // first argument is source filename
        dumpVariableValueArgs.push_back(functionNameValue); // second argument is function name
        dumpVariableValueArgs.push_back(variableNameValue); // third argument is variable name
        dumpVariableValueArgs.push_back(declaredLineValue); // fourth argument is declared line
        dumpVariableValueArgs.push_back(modifiedLineValue); // fifth argument is modified line
        dumpVariableValueArgs.push_back(formatStringValue); // sixth argument is format string for value (includes type)
        dumpVariableValueArgs.push_back(value); // last argument is value

        irb.CreateCall(dumpVariableValueFunction, dumpVariableValueArgs);
    }

    static std::string getFormatSpecifierForValue(Value* value) {
        auto *type = value->getType();
        if (type->isIntegerTy()) {
            return "int:%d";
        } else if (type->isFloatTy()) {
            return "float:%.9g";
        } else if (type->isDoubleTy()) {
            return "double:%.17g";
        } else if (type->isPointerTy()) {
            // This code also from LLVM-Tracer
            if (auto *integerType = dyn_cast<IntegerType>(type->getPointerElementType())) {
                if (integerType->getBitWidth() == 8) {
                    if (auto *constantExpr = dyn_cast<ConstantExpr>(value)) {
                        if (auto *globalVariable = dyn_cast<GlobalVariable>(constantExpr->getOperand(0))) {
                            if (globalVariable->hasInitializer() && dyn_cast<ConstantDataArray>(globalVariable->getInitializer())) {
                                return "string:%s";
                            }
                        }
                    }
                }
            }
        }

        return "pointer:%p";
    }

protected:
    bool shouldProcess(Function &function) override {
        return ignoredFunctions.find(function.getName().str()) == ignoredFunctions.end();
    }

    void processFunction(Function &function) override {
        Module* module = function.getParent();
        std::string functionNameVariableName = "__vvdump_function_" + getQualifiedFunctionName(&function);
        functionNameValue = getOrCreateGlobalStringVariable(
            module,
            functionNameVariableName,
            function.getName().str()
        );

        // Instrument store instructions to log variable values
        for (auto *storeInstruction : storeInstructions) {
            instrumentIfNecessary(&function, storeInstruction);
        }

        variableNameToValue.clear();
    }

public:
    explicit VariableValueDumpFeedback(Module& M) : BaseVariableValueFeedback<VariableValueDumpFeedback>(M, "vvdump", "__afl_vvdump_dsf") {
        dumpVariableValueFunction = this->resolveFunction(
            "__dump_variable_value",
            this->getVoidTy(),
            {
                this->getIntTy(8),
                this->getIntTy(8),
                this->getIntTy(8),
                this->getIntTy(8),
                this->getIntTy(8),
                this->getIntTy(8)
             },
            true
        );
    }

    void visitModule(Module& module) {
        std::string sourceFileNameVariableName = "__vvdump_file_" + std::regex_replace(
            module.getSourceFileName(),
            std::regex("[/]"),
            "_"
        );
        sourceFileNameValue = getOrCreateGlobalStringVariable(
            &module,
            sourceFileNameVariableName,
            module.getSourceFileName()
        );

        // Process global annotations to see if there are any functions we should ignore.
        // adapted from: https://stackoverflow.com/a/47881182/263004

        // First check to see if we have any global annotations. If not, just return.
        auto *globalAnnotations = module.getGlobalVariable("llvm.global.annotations");
        if (!globalAnnotations) {
            return;
        }

        // Metadata about annotated functions is in the first operand. It is a constant array of structs.
        auto *entries = dyn_cast<ConstantArray>(globalAnnotations->getOperand(0));
        for (auto entry = entries->op_begin(); entry != entries->op_end(); ++entry) {
            auto *entry_struct = dyn_cast<ConstantStruct>(entry->get());

            // Get the data we need from the struct. First we will get the annotation value to see if it is something
            // we care about. We only care about annotations that contain the string "vvdump_ignore", which tells us
            // which functions we shouldn't instrument for collecting variable-value traces.
            auto *annotationVariable = dyn_cast<GlobalVariable>(entry_struct->getOperand(1)->getOperand(0));
            auto annotationValue = dyn_cast<ConstantDataArray>(annotationVariable->getInitializer())->getAsCString();
            if (annotationValue.str() == "vvdump_ignore") {
                auto *function = dyn_cast<Function>(entry_struct->getOperand(0)->getOperand(0));
                ignoredFunctions.emplace(function->getName().str());
            }
        }
    }
};

FUZZFACTORY_REGISTER_DOMAIN(VariableValueDumpFeedback);
