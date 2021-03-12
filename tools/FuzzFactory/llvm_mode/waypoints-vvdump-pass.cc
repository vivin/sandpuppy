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
            std::cout << "resolves to integer: " << doesPointerTypeResolveToInteger(cast<PointerType>(valueType)) << "\n";
        }*/

        bool result = isFunctionArgument(variableName)
                 && (valueType->isIntegerTy()
                     || (valueType->isPointerTy() && doesPointerTypeResolveToInteger(cast<PointerType>(valueType))));

        //std::cout << "result is " << result << "\n";
        return result;
    }

    void instrumentIfNecessary(Function* function, StoreInst *store) {
        std::string sourceFileName= store->getModule()->getSourceFileName();
        std::string functionName = function->getName();

        Value* value = store->getValueOperand();
        Value* variable = store->getPointerOperand();
        std::string variableName = getVariableName(variable);

        // Only instrument if we could get a variable name and if the store instruction is modifying an integer variable
        // or if the store instruction is initializing an integer function argument (we want to log those values).
        if (!variableName.empty() && !isInvolvedInPointerArithmetic(variableName)
            && (modifiesIntegerVariable(store) || initializesIntegerFunctionArgument(store, variableName))) {
                createDumpVariableValueCall(function, store, variableName, value);
        }
    }

    void createDumpVariableValueCall(Function* function, StoreInst* store, const std::string& variableName, Value* value) {
        auto irb = insert_after(*store);

        if (isFunctionArgument(variableName) && store->getValueOperand()->getType()->isPointerTy()) {
            auto *type = store->getValueOperand()->getType();
            int indirection = 0;
            while (type->isPointerTy()) {
                indirection++;
                type = type->getPointerElementType();
            }

            // We can assume that at this point the type is an integer type because in instrumentIfNecessary we made
            // sure that the function argument eventually resolves to an integer type even if it is a pointer. What
            // we will do next is insert as many load statements as necessary in order to dereference the pointer. This
            // depends on the level of indirection, which we have calculated.
            Value* load = value;
            unsigned int bitWidth = type->getIntegerBitWidth();
            while (indirection > 0) {
                load = (indirection == 1) ? irb.CreateLoad(getIntTy(bitWidth), load)
                                          : irb.CreateLoad(getPointerToIntegerType(indirection - 1, bitWidth), load);
                --indirection;
            }

            value = load;
        }

        Value *variableNameValue = variableNameToValue[variableName];
        if (!variableNameValue) {
            std::string variableVariableName = "__vvdump_variable_" + function->getName().str() + "." + variableName;
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

        // only need to do this if you need to load the value explicitly given a reference to the variable
        //auto loadedValue = irb.CreateLoad(variable->getType()->getPointerElementType(), variable, variable->getName().str() + std::to_string(store->getDebugLoc()->getLine()));

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

    static GlobalVariable* getOrCreateGlobalStringVariable(Module* module, const std::string& variableName, const std::string& variableValue) {
        GlobalVariable* globalVariable = module->getGlobalVariable(variableName);
        if (!globalVariable) {
            Constant* variableValueConstant = ConstantDataArray::getString(
                module->getContext(),
                variableValue
            );

            globalVariable = (GlobalVariable*) module->getOrInsertGlobal(
                variableName,
                variableValueConstant->getType()
            );
            globalVariable->setConstant(true);
            globalVariable->setLinkage(GlobalValue::PrivateLinkage);
            globalVariable->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
            globalVariable->setAlignment(Align(1));
            globalVariable->setInitializer(variableValueConstant);
        }

        return globalVariable;
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
        return true;
    }

    void processFunction(Function &function) override {
        Module* module = function.getParent();
        std::string functionNameVariableName = "__vvdump_function_" + std::regex_replace(
            module->getSourceFileName(),
            std::regex("[/]"),
            "_"
        ) + "_" + function.getName().str();
        functionNameValue = getOrCreateGlobalStringVariable(
            module,
            functionNameVariableName,
            function.getName().str()
        );

        // Instrument store instructions to log variable values
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (isa<StoreInst>(instruction)) {
                instrumentIfNecessary(&function, cast<StoreInst>(&instruction));
            }
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
    }
};

FUZZFACTORY_REGISTER_DOMAIN(VariableValueDumpFeedback);
