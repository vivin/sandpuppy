#include <fstream>
#include <iostream>
#include <utility>
#include "basevvfeedback.hpp"
#include "../include/vvdump.h"


using namespace fuzzfactory;

class TargetedVariable {
    std::string variableName;
    int declaredLine;

public:
    TargetedVariable(std::string variableName, int declaredLine) : variableName(std::move(variableName)),
                                                                   declaredLine(declaredLine) {}

    const std::string &getVariableName() const {
        return variableName;
    }

    int getDeclaredLine() const {
        return declaredLine;
    }
};

class TargetedFunction {
    std::string functionName;
    std::map<std::string, TargetedVariable*> targetedVariables;

    static std::string getKey(const std::string& variableName, int declaredLine) {
        return variableName + ":" + std::to_string(declaredLine);
    }

public:
    explicit TargetedFunction(std::string functionName) : functionName(std::move(functionName)) {}

    std::string getFunctionName() const {
        return functionName;
    }

    void addTargetedVariable(const std::string& variableName, int declaredLine) {
        std::string key = getKey(variableName, declaredLine);
        targetedVariables[key] = new TargetedVariable(variableName, declaredLine);
    }

    bool targetsVariable(const std::string& variableName, int declaredLine) const {
        std::string key = getKey(variableName, declaredLine);
        return targetedVariables.find(key) != targetedVariables.end();
    }
};

class TargetedFile {
    std::string filename;
    std::map<std::string, TargetedFunction*> targetedFunctions;

public:
    explicit TargetedFile(std::string filename) : filename(std::move(filename)) {}

    std::string getFilename() const {
        return filename;
    }

    TargetedFunction* addTargetedFunctionIfNotExists(const std::string& functionName) {
        if (!targetsFunction(functionName)) {
            targetedFunctions[functionName] = new TargetedFunction(functionName);
        }

        return targetedFunctions[functionName];
    }

    TargetedFunction *getTargetedFunction(const std::string& functionName) const {
        return targetedFunctions.at(functionName);
    }

    bool targetsFunction(const std::string& functionName) const {
        return targetedFunctions.find(functionName) != targetedFunctions.end();
    }
};

class VariableMaximizationConfiguration {
    const int NUM_COMPONENTS = 4;
    enum Components {
        filename = 0,
        functionName = 1,
        variableName = 2,
        declaredLine = 3
    };

    std::map<std::string, TargetedFile*> targetedFiles;

    void initializeFromVariablesFile() {
        std::ifstream variablesFile(VariablesFile);
        if ((variablesFile.rdstate() & std::ifstream::failbit ) != 0 ){
            std::cerr << "Error opening " << VariablesFile << "\n";
            return;
        }

        bool error = false;
        std::string line;
        while (std::getline(variablesFile, line) && !error) {
            std::vector<std::string> components = split(line, ':');

            if (components.size() == NUM_COMPONENTS) {
                const StringRef filename = components[Components::filename];
                //std::cout << "Adding filename |" << filename.str() << "|\n";

                TargetedFile* targetedFile = addTargetedFileIfNotExists(filename.str());

                const StringRef functionName = components[Components::functionName];
                TargetedFunction* targetedFunction = targetedFile->addTargetedFunctionIfNotExists(functionName.str());

                //std::cout << "Adding function " << functionName.str() << "\n";

                const StringRef variableName = components[Components::variableName];
                const int declaredLine = std::stoi(components[Components::declaredLine]);

                //std::cout << "Adding variable " << variableName.str() << ":" << declaredLine << "\n";

                targetedFunction->addTargetedVariable(variableName.str(), declaredLine);
            } else if(!components.empty()) {
                std::cerr << "Invalid number of components (" << components.size() << ") in line:\n  " << line << "\n";
                error = true;
            }
        }

        if (error) {
            std::cerr << "Pass will not do anything; there was an error while reading the variables file.\n";
            targetedFiles.clear();
        }

        variablesFile.close();
    }

public:
    VariableMaximizationConfiguration() {
        if (!VariablesFile.empty()) {
            initializeFromVariablesFile();
        }
    }

    TargetedFile* addTargetedFileIfNotExists(const std::string& filename) {
        if (!targetsFile(filename)) {
            targetedFiles[filename] = new TargetedFile(filename);
        }

        return targetedFiles[filename];
    }

    TargetedFile* getTargetedFile(const std::string& filename) const {
        return targetedFiles.at(filename);
    }

    bool targetsFile(const std::string& filename) const {
        /*std::cout << "total number of files " << targetedFiles.size() << "\n";
        std::cout << "is " << filename << " there:" << (targetedFiles.find(filename) != targetedFiles.end() ? "yes" : "no") << "\n";

        for(const auto &targetedFile : targetedFiles) {
            std::cout << "key is |" << targetedFile.first << "|\n";
        }*/

        return targetedFiles.find(filename) != targetedFiles.end();
    }
};

class VariableValueMaximizeFeedback : public BaseVariableValueFeedback<VariableValueMaximizeFeedback> {
    const VariableMaximizationConfiguration configuration;

    Function *dsfMaxFunction;
    std::map<std::string, Value*> variableToProgramLocation;

    void instrumentIfNecessary(const TargetedFunction* targetedFunction, Function* function, StoreInst *store) {
        std::string sourceFileName= store->getModule()->getSourceFileName();
        std::string functionName = function->getName().str();

        Value* variable = store->getPointerOperand();
        std::string variableName = getVariableName(variable);
        if (variableExists(variableName)) {
            int declaredLine = varToDeclaredLine[variableName];
            if (targetedFunction->targetsVariable(variableName, declaredLine)) {
                auto irb = insert_after(*store);

                // If this is a function argument and it is a pointer, we need to safely dereference (i.e., with null
                // checks) its value so that we can use it.
                Value* value = store->getValueOperand();
                if (isFunctionArgument(variableName) && value->getType()->isPointerTy()) {
                    value = safelyDereferenceStoreValueOperand(store, variableName, irb);
                }

                // For now, we only deal with int variables. So if the value is not an int, print an error and return
                if (!value->getType()->isIntegerTy()) {
                    std::cerr << function->getParent()->getSourceFileName() << "::"
                              << function->getName().str() << "::"
                              << variableName << ":" << declaredLine << " is not an integer-like variable.\n";
                    return;
                }

                if (variableToProgramLocation.find(variableName) == variableToProgramLocation.end()) {
                    variableToProgramLocation[variableName] = createProgramLocation(); // static random value
                }

                auto key = variableToProgramLocation[variableName];

                // If value is greater than 32 bits, truncate.
                if (value->getType()->getIntegerBitWidth() > 32) {
                    value = irb->CreateTrunc(value, Int32Ty);
                }

                irb->CreateCall(dsfMaxFunction, {DsfMapVariable, key, value});
            }
        }
    }

protected:
    bool shouldProcess(Function &function) override {
        const StringRef filename = function.getParent()->getSourceFileName();
        if (!configuration.targetsFile(filename.str())) {
            return false;
        }

        const TargetedFile* targetedFile = configuration.getTargetedFile(filename.str());
        const StringRef functionName = function.getFunction().getName();
        if (!targetedFile->targetsFunction(functionName.str())) {
            return false;
        }

        return true;
    }

    void processFunction(Function &function) override {
        const StringRef filename = function.getParent()->getSourceFileName();
        const TargetedFile* targetedFile = configuration.getTargetedFile(filename.str());

        const StringRef functionName = function.getFunction().getName();
        const TargetedFunction* targetedFunction = targetedFile->getTargetedFunction(functionName.str());

        // Instrument store instructions to keep track of maximum values for targeted variables in this function
        for (auto *storeInstruction : storeInstructions) {
            instrumentIfNecessary(targetedFunction, &function, storeInstruction);
        }
    }

public:
    explicit VariableValueMaximizeFeedback(llvm::Module& M) : BaseVariableValueFeedback<VariableValueMaximizeFeedback>(M, "vvmax", "__afl_vvmax_dsf") {
        dsfMaxFunction = this->resolveFunction(
            "__fuzzfactory_dsfp_max",
            VoidTy,
            {
                getIntPtrTy(32),
                Int32Ty,
                Int32Ty
            }
        );
    }
};

FUZZFACTORY_REGISTER_DOMAIN(VariableValueMaximizeFeedback);
