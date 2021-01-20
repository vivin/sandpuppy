#include <fstream>
#include <sstream>
#include <iostream>
#include <utility>
#include "fuzzfactory.hpp"
#include "../include/vvdump.h"


using namespace fuzzfactory;

template <typename T>
void split(const std::string &string, char delimiter, T result) {
    std::istringstream iss(string);
    std::string item;
    while (std::getline(iss, item, delimiter)) {
        *result++ = item;
    }
}

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> elements;
    split(s, delimiter, std::back_inserter(elements));
    return elements;
}

class TargetedVariable {

    std::string variableName;
    int declaredLine;
    int shiftWidth;

public:
    TargetedVariable(std::string variableName, int declaredLine, int shiftWidth) : variableName(std::move(variableName)),
                                                                                   declaredLine(declaredLine),
                                                                                   shiftWidth(shiftWidth) {}

    const std::string &getVariableName() const {
        return variableName;
    }

    int getDeclaredLine() const {
        return declaredLine;
    }

    int getShiftWidth() const {
        return shiftWidth;
    }
};

class TargetedFunction {
    std::string functionName;
    std::map<std::string, TargetedVariable*> targetedVariables;

    static std::string getKey(std::string variableName, int declaredLine) {
        return variableName + ":" + std::to_string(declaredLine);
    }

public:
    explicit TargetedFunction(std::string functionName) : functionName(std::move(functionName)) {}

    std::string getFunctionName() const {
        return functionName;
    }

    void addTargetedVariable(std::string variableName, int declaredLine, int shiftWidth) {
        std::string key = getKey(variableName, declaredLine);
        targetedVariables[key] = new TargetedVariable(variableName, declaredLine, shiftWidth);
    }

    int getShiftWidthForVariable(std::string variableName, int declaredLine) const {
        if (targetsVariable(variableName, declaredLine)) {
            std::string key = getKey(variableName, declaredLine);
            return targetedVariables.at(key)->getShiftWidth();
        }

        return 0;
    }

    bool targetsVariable(std::string variableName, int declaredLine) const {
        std::string key = getKey(std::move(variableName), declaredLine);
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

    TargetedFunction* addTargetedFunctionIfNotExists(std::string functionName) {
        if (!targetsFunction(functionName)) {
            targetedFunctions[functionName] = new TargetedFunction(functionName);
        }

        return targetedFunctions[functionName];
    }

    TargetedFunction *getTargetedFunction(std::string functionName) const {
        return targetedFunctions.at(functionName);
    }

    bool targetsFunction(std::string functionName) const {
        return targetedFunctions.find(functionName) != targetedFunctions.end();
    }
};

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
                std::cout << "Adding filename |" << filename.str() << "|\n";

                TargetedFile* targetedFile = addTargetedFileIfNotExists(filename.str());

                const StringRef functionName = components[Components::functionName];
                TargetedFunction* targetedFunction = targetedFile->addTargetedFunctionIfNotExists(functionName.str());

                std::cout << "Adding function " << functionName.str() << "\n";

                const StringRef variableName = components[Components::variableName];
                const int declaredLine = std::stoi(components[Components::declaredLine]);
                const int shiftWidth = std::stoi(components[Components::shiftWidth]);

                std::cout << "Adding variable " << variableName.str() << ":" << declaredLine << " sw: " << shiftWidth << "\n";

                targetedFunction->addTargetedVariable(variableName.str(), declaredLine, shiftWidth);
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
    VariablePermutationConfiguration() {
        if (!VariablesFile.empty()) {
            initializeFromVariablesFile();
        }
    }

    TargetedFile* addTargetedFileIfNotExists(std::string filename) {
        if (!targetsFile(filename)) {
            targetedFiles[filename] = new TargetedFile(filename);
        }

        return targetedFiles[filename];
    }

    TargetedFile* getTargetedFile(std::string filename) const {
        return targetedFiles.at(filename);
    }

    bool targetsFile(std::string filename) const {
        /*std::cout << "total number of files " << targetedFiles.size() << "\n";
        std::cout << "is " << filename << " there:" << (targetedFiles.find(filename) != targetedFiles.end() ? "yes" : "no") << "\n";

        for(auto p  = targetedFiles.begin(); p != targetedFiles.end(); ++p) {
            std::cout << "key is |" << p->first << "|\n";
        }*/

        return targetedFiles.find(filename) != targetedFiles.end();
    }
};

/**
 * This ONLY works with -O0 -g -gfull! We look for debug declares to find out where vars are declared. We also maintain
 * a cache of variable names. Then we look for all store insts and check to see if any operands are variables that we
 * have seen.
 *
 * This only works on integer type variables (so longs are also counted).
 */
class VariableValuePermuteFeedback : public fuzzfactory::DomainFeedback<VariableValuePermuteFeedback> {

    const VariablePermutationConfiguration configuration;

    std::map<StringRef, int> varToDeclaredLine;
    std::map<StringRef, Value*> varToValueFormatString;

    Function *dsfSetFunction;
    Function *shiftAddFunction;
    Function *printValFunction;

    void processLocalVariableDeclaration(DbgDeclareInst* declare) {
        Value *arg = declare->getAddress();
        DILocalVariable *var = declare->getVariable();

        if (isa<UndefValue>(arg) || !var) {
            return;
        }

        if (var->isArtificial()) {
            return;
        }

        // Kinda hokey, but this domain-specific fuzzing only works with int values anyways, so we're gonna ignore
        // anything that isn't int-like.
        StringRef type = var->getType()->getName();
        if (type.str().find("int") == std::string::npos) {
            return;
        }

        if (varToDeclaredLine.find(var->getName()) == varToDeclaredLine.end()) {
            varToDeclaredLine[var->getName()] = var->getLine();
        }
    }

    void instrumentIfNecessary(const TargetedFunction* targetedFunction, Function* function, StoreInst *store) {
        for (int i = 0; i < store->getNumOperands(); i++) {
            Value* variable = store->getOperand(i);
            Value* value = store->getValueOperand();
            StringRef varName = variable->getName();

            if (!varName.empty() && varToDeclaredLine.find(varName) != varToDeclaredLine.end()) {
                int declaredLine = varToDeclaredLine[variable->getName()];
                StringRef variableName = variable->getName();

                // Only instrument if we are targeting this variable
                if (targetedFunction->targetsVariable(variableName.str(), declaredLine)) {
                    auto irb = insert_after(*store);

                    // Check to see if there already is a global variable that keeps track of value permutations. If
                    // there isn't create one and initialize it to zero.
                    Module* module = function->getParent();
                    std::string permutationVariableName = variableName.str() + "_" + std::to_string(declaredLine) + "_perm";
                    GlobalVariable* permutationVariable = module->getNamedGlobal(permutationVariableName);
                    if (!permutationVariable) {
                        module->getOrInsertGlobal(permutationVariableName, Int32Ty);

                        permutationVariable = module->getNamedGlobal(permutationVariableName);
                        permutationVariable->setLinkage(GlobalValue::CommonLinkage);
                        permutationVariable->setAlignment(MaybeAlign(4));
                        permutationVariable->setInitializer(getConst(0));
                    }

                    // Load the current value of the global variable
                    Value *permutationVariableValue = irb.CreateAlignedLoad(permutationVariable, MaybeAlign(4));
                    irb.CreateCall(printValFunction, { permutationVariableValue });

                    // Make a call to the shift_add function to calculate (permutationVariable << shiftWidthValue) + value
                    Value *shiftWidthValue = getConst(targetedFunction->getShiftWidthForVariable(variableName.str(), declaredLine));
                    auto shiftAddResult = irb.CreateCall(shiftAddFunction, { permutationVariableValue, shiftWidthValue, value });

                    // Use the shifted and added value as an index into the dsf map and set the value at that location to 1
                    irb.CreateCall(dsfSetFunction, { DsfMapVariable, shiftAddResult, getConst(1) });

                    // Store the shifted and added result back into the global variable
                    irb.CreateAlignedStore(shiftAddResult, permutationVariable, MaybeAlign(4), false);
                }
            }
        }
    }

public:
    explicit VariableValuePermuteFeedback(llvm::Module& M) : fuzzfactory::DomainFeedback<VariableValuePermuteFeedback>(M, "__afl_vvperm_dsf") {
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

    // Uses code from:
    // https://github.com/harvard-acc/LLVM-Tracer/blob/master/full-trace/full_trace.cpp

    void visitFunction(llvm::Function &function) {
        const StringRef filename = function.getParent()->getSourceFileName();
        if (!configuration.targetsFile(filename.str())) {
            return;
        }

        const TargetedFile* targetedFile = configuration.getTargetedFile(filename.str());
        const StringRef functionName = function.getFunction().getName();
        if (!targetedFile->targetsFunction(functionName.str())) {
            return;
        }

        const TargetedFunction* targetedFunction = targetedFile->getTargetedFunction(functionName.str());

        // First we will collect all local variable info for int-like variables from this function.
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (isa<DbgDeclareInst>(instruction)) {
                auto &declare = cast<DbgDeclareInst>(instruction);
                processLocalVariableDeclaration(&declare);
            }
        }

        // Next we will instrument (if the variable is targeted) with permutation code, at every location
        // the variable is modified.
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (instruction.hasMetadata() && isa<StoreInst>(instruction)) {
                instrumentIfNecessary(targetedFunction, &function, cast<StoreInst>(&instruction));
            }
        }

        varToDeclaredLine.clear();
        varToValueFormatString.clear();
    }
};

FUZZFACTORY_REGISTER_DOMAIN(VariableValuePermuteFeedback);
