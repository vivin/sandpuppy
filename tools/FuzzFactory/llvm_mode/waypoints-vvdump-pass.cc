#include "fuzzfactory.hpp"
#include "../include/vvdump.h"

using namespace fuzzfactory;

// TODO: in afl-fuzz you need to write to /tmp/vvdump when the program crashes or hangs. i think you should also write
// TODO: out the size of the program input. you could do the entire input but with named pipes there is a limit on the
// TODO: size of data you can send before which there may be interleaving between multiple processes. so if you have
// TODO: multiple afl-fuzz instances there may be issues because program input is likely greater than 512. i guess you
// TODO: could save all files and then pass in the name of the file. but for right now let us only use size of the input.

/**
 * This ONLY works with -O0 -g -gfull! We look for debug declares to find out where vars are declared. We also maintain
 * a cache of variable names. Then we look for all store insts and check to see if any operands are variables that we
 * have seen. if so we report that as a change of the variable's value.
 */
class VariableValuePermuteFeedback : public fuzzfactory::DomainFeedback<VariableValuePermuteFeedback> {

    std::map<StringRef, int> varToDeclaredLine;
    std::map<StringRef, Value*> varToValueFormatString;

    Function *dumpVariableValueFunction;

    void processLocalVariableDeclaration(DbgDeclareInst* declare) {
        Value *arg = declare->getAddress();
        DILocalVariable *var = declare->getVariable();

        if (isa<UndefValue>(arg) || !var) {
            return;
        }

        if (var->isArtificial()) {
            // TODO: this won't work. so what you actually need to do is, you also need to look at getelementptr
            // TODO: instructions. this is what works on arrays. using this you could print out the string value maybe
            // TODO: but anyways maybe don't worry about it, because as of now you have gotten the named pipe stuff working
            // TODO: aww yiss. you just need to throw it into the database.
            //std::cout << "artificial var " << var->getName().str() << " may actually be " << declare->getOperand(1)->getName().str() << "\n";
            return;
        }

        if (varToDeclaredLine.find(var->getName()) == varToDeclaredLine.end()) {
            varToDeclaredLine[var->getName()] = var->getLine();
        }
    }

    void instrumentIfNecessary(Function* function, StoreInst *store) {
        std::string sourceFileName= store->getModule()->getSourceFileName();
        std::string functionName = function->getName();

        for (int i = 0; i < store->getNumOperands(); i++) {
            Value* variable = store->getOperand(i);
            Value* value = store->getValueOperand();
            StringRef varName = variable->getName();

            if (!varName.empty() && varToDeclaredLine.find(varName) != varToDeclaredLine.end()) {
                createDumpVariableValueCall(function, store, variable, value);
            }
        }
    }

    void createDumpVariableValueCall(Function* function, StoreInst* store, Value* variable, Value* value) {
        auto irb = insert_after(*store);

        Value *sourceFileNameValue = irb.CreateGlobalString(store->getModule()->getSourceFileName());
        Value *functionNameValue = irb.CreateGlobalString(function->getName());
        Value *variableNameValue = irb.CreateGlobalString(variable->getName());
        Value *declaredLineValue = getConst(varToDeclaredLine[variable->getName()]);
        Value *modifiedLineValue = getConst((int) store->getDebugLoc()->getLine());

        Value *valueFormatStringValue = varToValueFormatString[variable->getName()];
        if (!valueFormatStringValue) {
            std::string valueFormatString = getFormatSpecifierForValue(variable, value);
            valueFormatStringValue = irb.CreateGlobalString(
                StringRef(valueFormatString),
                variable->getName().str() + "FormatString"
            );

            varToValueFormatString[variable->getName()] = valueFormatStringValue;
            //std::cout << function->getName().str() << ": " << variable->getName().str() << ", " << valueFormatString << "\n";
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
        dumpVariableValueArgs.push_back(valueFormatStringValue); // fifth argument is format string for value
        dumpVariableValueArgs.push_back(value); // last argument is value

        irb.CreateCall(dumpVariableValueFunction, dumpVariableValueArgs);
    }

    static std::string getFormatSpecifierForValue(Value* variable, Value* value) {
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

public:
    VariableValuePermuteFeedback(llvm::Module& M) : fuzzfactory::DomainFeedback<VariableValuePermuteFeedback>(M, "__afl_vvdump_dsf") {
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

    // Uses code from:
    // https://github.com/harvard-acc/LLVM-Tracer/blob/master/full-trace/full_trace.cpp

    void visitFunction(llvm::Function &function) {
        // First we will collect all local variable info from this function.
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (isa<DbgDeclareInst>(instruction)) {
                auto &declare = cast<DbgDeclareInst>(instruction);
                processLocalVariableDeclaration(&declare);
            }
        }

        // Log local variable value after any store instruction that modifies it
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (instruction.hasMetadata() && isa<StoreInst>(instruction)) {
                instrumentIfNecessary(&function, cast<StoreInst>(&instruction));
            }
        }

        //std::cout << "\n";

        varToDeclaredLine.clear();
        varToValueFormatString.clear();
    }

};

FUZZFACTORY_REGISTER_DOMAIN(VariableValuePermuteFeedback);
