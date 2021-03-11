#include <utility>
#include <regex>
#include <unordered_set>

#include "fuzzfactory.hpp"

using namespace fuzzfactory;

class StructInfo {
    std::string name;
    std::vector<std::string> elements;

public:
    StructInfo(std::string name) : name(std::move(name)) {}

    const std::string &getName() const {
        return name;
    }

    const std::vector<std::string> &getElements() const {
        return elements;
    }

    void addElement(std::string name) {
        elements.emplace_back(name);
    }
};

/**
 * This ONLY works with -O0 -g -gfull! We look for debug declares to find out where vars are declared. We also maintain
 * a cache of variable names. Then we look for all store insts and check to see if any operands are variables that we
 * have seen. if so we report that as a change of the variable's value.
 *
 * This class does actually look for different
 */
class VariablePrintFeedback : public fuzzfactory::DomainFeedback<VariablePrintFeedback> {

    // TODO: maybe associate value with all the info of the variable like name and declared line. that way you could
    // TODO: look up quickly instead of walking up the chain. Don't set the value as DILocalVariable. Instead maybe
    // TODO: create custom class? dunno. explore later.
    std::map<Value*, DILocalVariable*> valueLocalVariableCache;
    std::map<std::string, int> varToDeclaredLine;
    std::map<std::string, StructInfo*> structInfoMap;

    bool variableExists(const std::string& variableName) {
        return varToDeclaredLine.find(variableName) != varToDeclaredLine.end();
    }

    bool structExists(const std::string& structName) {
        return structInfoMap.find(structName) != structInfoMap.end();
    }

    void processLocalVariableDeclaration(DbgDeclareInst* declare) {
        Value *arg = declare->getAddress();
        DILocalVariable *var = declare->getVariable();

        if (isa<UndefValue>(arg) || !var) {
            return;
        }

        if (var->isArtificial()) {
            return;
        }

        if (variableExists(var->getName().str())) {
            varToDeclaredLine[var->getName().str()] = var->getLine();

            std::cout << "  " << var->getName().str() << " declared on line " << var->getLine() << "\n";

            std::unordered_set<DIType*> visited;
            std::stack<DIType*> frontier;
            frontier.push(var->getType());

            while (!frontier.empty()) {
                auto *type = frontier.top();
                frontier.pop();
                visited.emplace(type);

                while (type && isa<DIDerivedType>(type)) {
                    type = cast<DIDerivedType>(type)->getBaseType();
                }

                if (type && isa<DICompositeType>(type)) {
                    std::cout << "    " << type->getName().str() << " is a composite type\n";

                    auto *compositeType = cast<DICompositeType>(type);
                    auto *structInfo = new StructInfo(type->getName().str());
                    DINodeArray elements = compositeType->getElements();
                    for (auto element : elements) {
                        if (auto *derivedType = dyn_cast<DIDerivedType>(element)) {
                            std::cout << "      Element name is " << derivedType->getName().str() << " with base type "
                                      << derivedType->getBaseType()->getName().str() << "\n";
                            structInfo->addElement(derivedType->getName().str());

                            if (visited.find(derivedType) == visited.end()) {
                                frontier.push(derivedType);
                            }
                        }
                    }

                    structInfoMap[type->getName().str()] = structInfo;
                }
            }
        }
    }

    void printVariableUsage(StoreInst *store, Function* function) {
        std::string sourceFileName= store->getModule()->getSourceFileName();
        std::string functionName = function->getName();

        if (store->getDebugLoc() && store->getValueOperand()->getType()->isIntegerTy()) {
            Value* variable = store->getPointerOperand();
            std::string variableName = getVariableName(variable);
            if (!variableName.empty()) {
                std::cout << "  Variable " << variableName << " modified on line " << store->getDebugLoc()->getLine()
                          << " (declared on line " << varToDeclaredLine[variableName] << ")\n";
            }
        }
    }

    std::string getVariableName(Value* variable) {
        std::string varName = variable->getName().str();
        if (auto *load = dyn_cast<LoadInst>(variable)) {
            // Handle case where we're actually working with a dereferenced pointer variable; we need to recursively
            // walk up until we get to a gep for a struct field or an alloca.
            return getVariableName(load->getPointerOperand());
        } else if (auto *gep = dyn_cast<GetElementPtrInst>(variable)) {
            if (gep->getSourceElementType()->isStructTy()) {
                // Handle case where we're modifying a struct field
                return getFullyQualifiedFieldName(gep);
            }
        } else if (variableExists(varName)) {
            // We're at an alloca instruction and so we should have the actual name of the variable.
            return varName;
        }

        return "";
    }

    static bool gepAppliesToStruct(StructInfo* structInfo, GetElementPtrInst* gep) {
        if (gep->getNumOperands() != 3) {
            return false;
        }

        auto elementIndex = cast<ConstantInt>(gep->getOperand(2))->getSExtValue();
        return elementIndex < structInfo->getElements().size();
    }

    std::string getFullyQualifiedFieldName(GetElementPtrInst* gep) {
        auto *structType = cast<StructType>(gep->getSourceElementType());
        std::string fullyQualifiedFieldName;
        std::string structName = std::regex_replace(
            structType->getStructName().str(),
            std::regex("^struct\\."),
            ""
        );

        // TODO: UGH anonymous structs are called struct.anon and struct.anon.0 and so on. but if you have a struct
        // TODO: called anon then it is also struct.anon ARGHHH. even worse, when it is a variable it may end up as
        // TODO: struct.anon.<some_number> because there may be some other anonymous structure struct.anon.
        // TODO: what do we do? Can't go by structure of the struct (i.e., types of elements) either. the problem is
        // TODO: that there is no way to associate, in reverse, the Type* we get here with a DIType*. So we have no
        // TODO: idea what the actual struct is. and in DIType* we get an empty name for anonymous structs.
        if (structExists(structName) && gepAppliesToStruct(structInfoMap[structName], gep)) {
            auto elementIndex = cast<ConstantInt>(gep->getOperand(2))->getSExtValue();

            StructInfo *structInfo = structInfoMap[structName];
            std::string element = structInfo->getElements()[elementIndex];

            // Operand might be a pointer to a struct, so walk up the load chain until we get to the actual struct
            Value *pointerOperand = gep->getPointerOperand();
            while (isa<LoadInst>(pointerOperand)) {
                pointerOperand = cast<LoadInst>(pointerOperand)->getPointerOperand();
            }

            // Recursively walk up the getelementptr chain to identify prefixes to this struct variable. This is
            // only necessary if this is a nested field access.
            bool onlyStructs = true;
            std::string prefix;
            while (isa<GetElementPtrInst>(pointerOperand) && onlyStructs) {
                auto *gepOperand = cast<GetElementPtrInst>(pointerOperand);
                onlyStructs = gepOperand->getSourceElementType()->isStructTy();
                if (onlyStructs) {
                    auto *_structType = cast<StructType>(gepOperand->getSourceElementType());
                    std::string name = std::regex_replace(
                        _structType->getStructName().str(),
                        std::regex("^struct\\."),
                        ""
                    );
                    if (structExists(name) && gepAppliesToStruct(structInfoMap[name], gepOperand)) {
                        auto _elementIndex = cast<ConstantInt>(gepOperand->getOperand(2))->getSExtValue();
                        StructInfo *_structInfo = structInfoMap[name];
                        std::string _element = _structInfo->getElements()[_elementIndex];

                        prefix = _element.append(".").append(prefix);
                        pointerOperand = gepOperand->getPointerOperand();
                    } else {
                        onlyStructs = false;
                    }
                }
            }

            if (onlyStructs) {
                // If the struct that this field belongs to is actually a pointer argument to a function, it is suffixed
                // with ".addr" (this is something LLVM does). We need to strip this out so that we can get the actual
                // name of the parameter.
                std::string structVarName = std::regex_replace(pointerOperand->getName().str(), std::regex("\\.addr"), "");
                fullyQualifiedFieldName = structVarName + "." + prefix + element;

                // Set the declared line of this struct field to the declared line of the struct itself.
                varToDeclaredLine[fullyQualifiedFieldName] = varToDeclaredLine[structVarName];
            }
        }

        return fullyQualifiedFieldName;
    }

public:
    explicit VariablePrintFeedback(llvm::Module& M) : fuzzfactory::DomainFeedback<VariablePrintFeedback>(M, "__afl_varprint_dsf") {

    }

    // Uses code from:
    // https://github.com/harvard-acc/LLVM-Tracer/blob/master/full-trace/full_trace.cpp

    void visitFunction(llvm::Function &function) {
        std::cout << "In function " << function.getName().str();
        if (function.getSubprogram()) {
            std::cout << " from file " << function.getSubprogram()->getFilename().str();
        }

        std::cout << "\n";

        // First we will collect and print all local variable info from this function.
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (isa<DbgDeclareInst>(instruction)) {
                auto &declare = cast<DbgDeclareInst>(instruction);
                processLocalVariableDeclaration(&declare);
            }
        }

        std::cout << "\n";

        // Now we will print out where the values of variables change.

        // We maintain two iterators because when we process the alloca instruction we iterate over instructions in
        // the function again until we find debug information
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (instruction.hasMetadata() && isa<StoreInst>(instruction)) {
                printVariableUsage(cast<StoreInst>(&instruction), &function);
            }
        }

        std::cout << "\n";

        varToDeclaredLine.clear();
        structInfoMap.clear();

        valueLocalVariableCache.clear();
    }
};

FUZZFACTORY_REGISTER_DOMAIN(VariablePrintFeedback);
