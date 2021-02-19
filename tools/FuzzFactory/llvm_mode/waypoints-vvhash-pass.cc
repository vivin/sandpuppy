#include <fstream>
#include <iostream>
#include "basevvfeedback.hpp"
#include "../include/vvdump.h"


using namespace fuzzfactory;

class VariablesHashConfiguration {
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
                targetedFilename = components[Components::filename];
                targetedFunctionName = components[Components::functionName];

                firstVariable = components[Components::variableName1];
                firstDeclaredLine = std::stoi(components[Components::declaredLine1]);

                secondVariable = components[Components::variableName2];
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
    VariablesHashConfiguration() {
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
class VariableValueHashFeedback : public BaseVariableValueFeedback<VariableValueHashFeedback> {
    const VariablesHashConfiguration configuration;

    Function *dsfSetFunction;
    Function *hashIntsFunction;
    Function *printValFunction;

    void instrument(StoreInst *storeInstVariable1, StoreInst *storeInstVariable2) {
        // We gotta see which store inst comes last because we will be inserting it after that one.
        unsigned int modifiedLineVariable1 = storeInstVariable1->getDebugLoc()->getLine();
        unsigned int modifiedLineVariable2 = storeInstVariable2->getDebugLoc()->getLine();

        auto irb = (modifiedLineVariable1 > modifiedLineVariable2) ?
            insert_after(*storeInstVariable1) : insert_after(*storeInstVariable2);

        auto *valueVariable1 = storeInstVariable1->getValueOperand();
        auto *valueVariable2 = storeInstVariable2->getValueOperand();
        auto *hash = irb.CreateCall(hashIntsFunction, { valueVariable1, valueVariable2 });
        //irb.CreateCall(printValFunction, { hash });

        irb.CreateCall(dsfSetFunction, { DsfMapVariable, hash, getConst(1) });
    }

    bool isStoreInstForVariable(StoreInst *store, const std::string& variableName) {
        return variableName == getVariableName(store->getPointerOperand());
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
        StoreInst* storeInstVariable1;
        StoreInst* storeInstVariable2;

        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (instruction.hasMetadata() && isa<StoreInst>(instruction)) {
                if (isStoreInstForVariable(cast<StoreInst>(&instruction), configuration.getFirstVariable())) {
                    storeInstVariable1 = cast<StoreInst>(&instruction);
                } else if (isStoreInstForVariable(cast<StoreInst>(&instruction), configuration.getSecondVariable())) {
                    storeInstVariable2 = cast<StoreInst>(&instruction);
                }

                if (storeInstVariable1 && storeInstVariable2) {
                    instrument(storeInstVariable1, storeInstVariable2);

                    storeInstVariable1 = nullptr;
                    storeInstVariable2 = nullptr;
                }
            }
        }
    }

public:
    explicit VariableValueHashFeedback(llvm::Module& M) : BaseVariableValueFeedback<VariableValueHashFeedback>(M, "vvhash", "__afl_vvhash_dsf") {
        dsfSetFunction = this->resolveFunction(
            "__fuzzfactory_dsfp_set",
            VoidTy,
            {
                getIntPtrTy(32),
                Int32Ty,
                Int32Ty
            }
        );
        hashIntsFunction = this->resolveFunction(
            "__hash_ints",
            Int32Ty,
            {
                Int32Ty,
                Int32Ty,
            }
        );
        printValFunction = this->resolveFunction(
            "__print_val",
            VoidTy,
            {
                Int32Ty
            }
        );
    }
};

FUZZFACTORY_REGISTER_DOMAIN(VariableValueHashFeedback);
