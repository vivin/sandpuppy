#include <fstream>
#include <iostream>
#include "basevvfeedback.hpp"
#include "../include/vvdump.h"


using namespace fuzzfactory;

class VariablePermutationConfiguration {
    const int NUM_COMPONENTS = 5;
    enum Components {
        filename = 0,
        functionName = 1,
        variableName = 2,
        declaredLine = 3,
        shiftWidth = 4 // TODO: we need something to tell us how big the permutation var needs to be. 32bit or 64bit.
                       // TODO: right now fix to 32. ok so we have another problem. the total number of map locations
                       // TODO: we can have are 2^18, and each one is 32 bit. but if we are shifting by 8, then each
                       // TODO: index is a 32-bit value. which means what we need is a 2^31 locations with 32 bits!!
                       // TODO: but that is way too big. so how do we avoid this? basically you need an array of bools
                       // TODO: or something. and then you need a special indexing function that can map your value
                       // TODO: into it. so this does mean you may span across indexes???. see the problem is that
                       // TODO: the key index is just 6 bytes. but the index you generate is 8. this means you get a
                       // TODO: collision. worst case 256 entries per 6-byte index. increases fuzzing time. so if you
                       // TODO: could even just have a 2^31 locations of bools that would be nice. like if you could
                       // TODO: set a bit...
                       //
                       // TODO: i think you basically need to create your own shared memory stuff or something... OR
                       // TODO: you have 2^18 locations right. which is actually 2^18 * 4 bytes. so what if you could
                       // TODO: index into a specific byte and set the value there. i guess you could use the MAX
                       // TODO: reducer. which is fine. but i think this would work... possibly. you will get collisions
                       // TODO: so... how is this different from the other situation? well i think since you are setting
                       // TODO: bytes to 01 or 00, you have less spurious outputs vs our current situation where we need
                       // TODO: to increment, because otherwise we end up not differentiating between say 3 1 2 2 and
                       // TODO: 2 1 2 2, because both map to index 122.
                       //
                       // TODO: try shifting only by 4 and setting instead of incrementing.
    };

    std::string targetedFilename;
    std::string targetedFunctionName;
    std::string targetedVariableName;
    int targetedVariableDeclaredLine = 0;
    int targetedVariableShiftWidth = 0;

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
                targetedVariableName = components[Components::variableName];
                targetedVariableDeclaredLine = std::stoi(components[Components::declaredLine]);
                targetedVariableShiftWidth = std::stoi(components[Components::shiftWidth]);
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
    VariablePermutationConfiguration() {
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

    const std::string &getTargetedVariableName() const {
        return targetedVariableName;
    }

    int getTargetedVariableDeclaredLine() const {
        return targetedVariableDeclaredLine;
    }

    int getTargetedVariableShiftWidth() const {
        return targetedVariableShiftWidth;
    }
};

class VariableValuePermuteFeedback : public BaseVariableValueFeedback<VariableValuePermuteFeedback> {
    const VariablePermutationConfiguration configuration;

    std::map<StringRef, Value*> varToValueFormatString;

    Function *dsfSetFunction;
    Function *shiftAddFunction;
    Function *printValFunction;

    void instrument(Function* function, StoreInst *store) {
        Value* variable = store->getPointerOperand();
        std::string variableName = getVariableName(variable);

        auto irb = insert_after(*store);

        // If this is a function argument and it is a pointer, we need to safely dereference (i.e., with null checks)
        // its value so that we can use it.
        Value* value = store->getValueOperand();
        if (isFunctionArgument(variableName) && value->getType()->isPointerTy()) {
            value = safelyDereferenceStoreValueOperand(store, variableName, irb);
        }

        // For now, we only deal with int variables. So if the value is not an int, print an error and return
        if (!value->getType()->isIntegerTy()) {
            std::cerr << function->getParent()->getSourceFileName() << "::"
                      << function->getName().str() << "::"
                      << variableName << ":" << configuration.getTargetedVariableDeclaredLine()
                      << " is not an integer-like variable.\n";
            return;
        }

        int declaredLine = varToDeclaredLine[variableName];

        // Check to see if there already is a global variable that keeps track of value permutations. If there
        // isn't, create one and initialize it to zero.
        Module* module = function->getParent();
        std::string permutationVariableName = getQualifiedVariableName(function, variableName) + "_" + std::to_string(declaredLine) + "_perm";
        GlobalVariable* permutationVariable = module->getNamedGlobal(permutationVariableName);
        if (!permutationVariable) {
            module->getOrInsertGlobal(permutationVariableName, Int32Ty);

            permutationVariable = module->getNamedGlobal(permutationVariableName);
            permutationVariable->setLinkage(GlobalValue::CommonLinkage);
            permutationVariable->setAlignment(MaybeAlign(4));
            permutationVariable->setInitializer(getConst(0));
        }

        // Load the current value of the global variable
        Value *permutationVariableValue = irb->CreateAlignedLoad(permutationVariable, MaybeAlign(4));

        //irb->CreateCall(printHashValFunction, { permutationVariableValue });

        // If value is greater than 32 bits, truncate.
        if (value->getType()->getIntegerBitWidth() > 32) {
            value = irb->CreateTrunc(value, Int32Ty);
        }

        // Make a call to the shift_add function to calculate (permutationVariable << shiftWidthValue) + value
        Value *shiftWidthValue = getConst(configuration.getTargetedVariableShiftWidth());
        auto shiftAddResult = irb->CreateCall(shiftAddFunction, {
            permutationVariableValue,
            shiftWidthValue,
            value
        });

        // Use the shifted and added value as an index into the dsf map and set the value at that location to 1
        irb->CreateCall(dsfSetFunction, {
            DsfMapVariable,
            shiftAddResult,
            getConst(1)
        });

        // Store the shifted and added result back into the global variable
        irb->CreateAlignedStore(shiftAddResult, permutationVariable, MaybeAlign(4), false);
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
        // Next we will instrument (if the variable is targeted) with permutation code, at every location that the
        // variable is modified.
        for (auto *storeInstruction : storeInstructions) {
            if (isStoreInstForVariable(storeInstruction, configuration.getTargetedVariableName())) {
                instrument(&function, storeInstruction);
            }
        }

        varToDeclaredLine.clear();
        varToValueFormatString.clear();
    }

public:
    explicit VariableValuePermuteFeedback(llvm::Module& M) : BaseVariableValueFeedback<VariableValuePermuteFeedback>(M, "vvperm", "__afl_vvperm_dsf") {
        dsfSetFunction = this->resolveFunction(
            "__fuzzfactory_dsfp_set",
            VoidTy,
            {
                getIntPtrTy(32),
                Int32Ty,
                Int32Ty
            }
        );
        shiftAddFunction = this->resolveFunction(
            "__shift_add",
            Int32Ty,
            {
                Int32Ty,
                Int32Ty,
                Int32Ty
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

FUZZFACTORY_REGISTER_DOMAIN(VariableValuePermuteFeedback);
