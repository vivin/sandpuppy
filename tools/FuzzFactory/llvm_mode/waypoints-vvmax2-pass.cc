#include <fstream>
#include <iostream>
#include "basevvfeedback.hpp"
#include "../include/vvdump.h"

using namespace fuzzfactory;

class TwoVariablesMaximizationConfiguration {
    const int NUM_COMPONENTS = 6;
    enum Components {
        filename = 0,
        functionName = 1,
        variableName1 = 2,
        declaredLine1 = 3,
        variableName2 = 4,
        declaredLine2 = 5
    };

    std::string targetedFilename;
    std::string targetedFunctionName;

    std::string firstVariable;
    int firstDeclaredLine = 0;

    std::string secondVariable;
    int secondDeclaredLine = 0;

    void initializeFromVariablesFile() {
        std::ifstream variablesFile(VariablesFile);
        if ((variablesFile.rdstate() & std::ifstream::failbit ) != 0 ){
            std::cerr << "Error opening " << VariablesFile << "\n";
            return;
        }

        bool error = false;
        std::string line;
        if (std::getline(variablesFile, line)) {
            std::vector<std::string> components = split(line, ':');
            if (components.size() == NUM_COMPONENTS) {
                targetedFilename = std::move(components[Components::filename]);
                targetedFunctionName = std::move(components[Components::functionName]);

                firstVariable = std::move(components[Components::variableName1]);
                firstDeclaredLine = std::stoi(components[Components::declaredLine1]);

                secondVariable = std::move(components[Components::variableName2]);
                secondDeclaredLine = std::stoi(components[Components::declaredLine2]);
            } else if (!components.empty()) {
                std::cerr << "Invalid number of components: " << components.size() << "\n";
                error = true;
            }
        }

        if (error) {
            std::cerr << "Pass will not do anything; there was an error while reading the variables file.\n";
        }

        variablesFile.close();
    }

public:
    TwoVariablesMaximizationConfiguration() {
        if (!VariablesFile.empty()) {
            initializeFromVariablesFile();
        }
    }

    bool targetsFile(const std::string& filename) const {
        return targetedFilename == filename;
    }

    bool targetsFunction(const std::string& functionName) const {
        return targetedFunctionName == functionName;
    }

    const std::string &getTargetedFilename() const {
        return targetedFilename;
    }

    const std::string &getTargetedFunctionName() const {
        return targetedFunctionName;
    }

    const std::string &getFirstVariable() const {
        return firstVariable;
    }

    int getFirstDeclaredLine() const {
        return firstDeclaredLine;
    }

    const std::string &getSecondVariable() const {
        return secondVariable;
    }

    int getSecondDeclaredLine() const {
        return secondDeclaredLine;
    }
};

/**
 * This ONLY works with -O0 -g -gfull! We look for debug declares to find out where vars are declared. We also maintain
 * a cache of variable names. Then we look for all store insts and check to see if any operands are variables that we
 * have seen.
 *
 * This only works on integer type variables (so longs are also counted).
 */
class TwoVariablesValueMaximizationFeedback : public BaseVariableValueFeedback<TwoVariablesValueMaximizationFeedback> {
    const TwoVariablesMaximizationConfiguration configuration;

    Function *dsfSetFunction;

    void instrument(StoreInst *storeInstVariable1, StoreInst *storeInstVariable2, bool variable1ModifiedFirst) {

        // We need to see which store inst comes last because we will be inserting our instrumentation after it.
        auto irb = variable1ModifiedFirst ? insert_after(*storeInstVariable2) : insert_after(*storeInstVariable1);

        // If either of these variables are function arguments and are pointers, we need to safely dereference their
        // values (i.e., with null checks) so that we can use them.
        auto variable1Name = getVariableName(storeInstVariable1->getPointerOperand());
        auto *valueVariable1 = storeInstVariable1->getValueOperand();
        if (isFunctionArgument(variable1Name) && valueVariable1->getType()->isPointerTy()) {
            valueVariable1 = safelyDereferenceStoreValueOperand(storeInstVariable1, variable1Name, irb);
        }

        // For now, we only deal with int variables. So if the value is not an int, print an error and return
        if (!valueVariable1->getType()->isIntegerTy()) {
            std::cerr << configuration.getTargetedFilename() << "::"
                      << configuration.getTargetedFunctionName() << "::"
                      << variable1Name << ":" << configuration.getFirstDeclaredLine()
                      << " is not an integer-like variable.\n";
            return;
        }

        // If value is greater than 32 bits, truncate.
        if (valueVariable1->getType()->getIntegerBitWidth() > 32) {
            valueVariable1 = irb.CreateTrunc(valueVariable1, Int32Ty);
        }

        auto variable2Name = getVariableName(storeInstVariable2->getPointerOperand());
        auto *valueVariable2 = storeInstVariable2->getValueOperand();
        if (isFunctionArgument(variable2Name) && valueVariable2->getType()->isPointerTy()) {
            valueVariable2 = safelyDereferenceStoreValueOperand(storeInstVariable2, variable2Name, irb);
        }

        // For now, we only deal with int variables. So if the value is not an int, print an error and return
        if (!valueVariable2->getType()->isIntegerTy()) {
            std::cerr << configuration.getTargetedFilename() << "::"
                      << configuration.getTargetedFunctionName() << "::"
                      << variable2Name << ":" << configuration.getSecondDeclaredLine()
                      << " is not an integer-like variable.\n";
            return;
        }

        // If value is greater than 32 bits, truncate.
        if (valueVariable2->getType()->getIntegerBitWidth() > 32) {
            valueVariable2 = irb.CreateTrunc(valueVariable2, Int32Ty);
        }

        // Maximize value of variable2 with respect to variable1. Meaning, we keep track of the max value of variable2
        // for every value of variable1
        irb.CreateCall(dsfSetFunction, { DsfMapVariable, valueVariable1, valueVariable2 });
    }

protected:
    bool shouldProcess(Function &function) override {
        const StringRef filename = function.getParent()->getSourceFileName();
        if (!configuration.targetsFile(filename.str())) {
            return false;
        }

        const StringRef functionName = function.getFunction().getName();
        if (!configuration.targetsFunction(functionName.str())) {
            return false;
        }

        return true;
    }

    void processFunction(Function &function) override {

        // Start iterating and look for store instructions that involve our variables. We are looking for
        // two store instructions at a time.
        StoreInst* storeInstVariable1 = nullptr;
        StoreInst* storeInstVariable2 = nullptr;

        bool firstStoreFound = false;
        bool variable1ModifiedFirst;
        for (auto *storeInstruction : storeInstructions) {
            if (isStoreInstForVariable(storeInstruction, configuration.getFirstVariable())) {
                storeInstVariable1 = storeInstruction;
                if (!firstStoreFound) {
                    variable1ModifiedFirst = true;
                    firstStoreFound = true;
                }
            } else if (isStoreInstForVariable(storeInstruction, configuration.getSecondVariable())) {
                storeInstVariable2 = storeInstruction;
                if (!firstStoreFound) {
                    variable1ModifiedFirst = false;
                    firstStoreFound = true;
                }
            }

            if (storeInstVariable1 && storeInstVariable2) {
                instrument(storeInstVariable1, storeInstVariable2, variable1ModifiedFirst);

                firstStoreFound = false;
                variable1ModifiedFirst = false;

                storeInstVariable1 = nullptr;
                storeInstVariable2 = nullptr;
            }
        }
    }

public:
    explicit TwoVariablesValueMaximizationFeedback(llvm::Module& M) : BaseVariableValueFeedback<TwoVariablesValueMaximizationFeedback>(M, "vvmax2", "__afl_vvmax2_dsf") {
        dsfSetFunction = this->resolveFunction(
            "__fuzzfactory_dsfp_set",
            VoidTy,
            {
                getIntPtrTy(32),
                Int32Ty,
                Int32Ty
            }
        );
    }
};

FUZZFACTORY_REGISTER_DOMAIN(TwoVariablesValueMaximizationFeedback);
