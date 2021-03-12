#define AFL_LLVM_PASS

#include "fuzzfactory.hpp"
#include <sstream>
#include <fstream>
#include <iostream>
#include <regex>
#include <set>

#ifndef BASEVVFEEDBACK_H
#define BASEVVFEEDBACK_H

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

    void addElement(std::string element) {
        elements.emplace_back(element);
    }
};

/**
 * Base class for variable value feedback instrumentation.
 *
 * This ONLY works with -O0 -g -gfull! We first look for llvm.dbg.declare instructions so that we can find out where
 * variables are declared. We also handle derived types (typedefs) and structs at this point; if a struct variable has
 * been declared, we identify all its elements. We also maintain a map of variable names to declared lines and a map of
 * struct name to struct information (StructInfo).
 */
template<class V>
class BaseVariableValueFeedback : public DomainFeedback<V> {
    StringRef domainName;

    void processLocalVariableDeclaration(DbgDeclareInst* declare) {
        Value *arg = declare->getAddress();
        DILocalVariable *var = declare->getVariable();

        if (isa<UndefValue>(arg) || !var) {
            return;
        }

        if (var->isArtificial()) {
            return;
        }

        if (!var->getName().str().empty() && !variableExists(var->getName().str())) {
            varToDeclaredLine[var->getName().str()] = var->getLine();

            // TODO: at some point we need to identify strings here as well. they start off
            // TODO: as a pointer type, but end up as char, so that should be enough for us
            // TODO: to identify strings. deal with them how you dealt with pointer to integer
            // TODO: variables.

            // We will recursively identify structs and their elements. This takes care of nested structs.
            std::set<DIType*> visited;
            std::stack<DIType*> frontier;
            frontier.push(var->getType());

            while (!frontier.empty()) {
                auto *type = frontier.top();
                frontier.pop();
                visited.emplace(type);

                // When structs are defined with typedef, the type ends up being a DIDerivedType that
                // will eventually resolve to a DICompositeType. So if this is a DIDerivedType, we will
                // keep unwrapping it until it is not.
                while (type && isa<DIDerivedType>(type)) {
                    type = cast<DIDerivedType>(type)->getBaseType();
                }

                if (type && isa<DICompositeType>(type)) {
                    auto *compositeType = cast<DICompositeType>(type);
                    auto *structInfo = new StructInfo(type->getName().str());
                    DINodeArray elements = compositeType->getElements();
                    for (auto element : elements) {
                        if (auto *derivedType = dyn_cast<DIDerivedType>(element)) {
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

    bool gepAppliesToStruct(StructInfo* structInfo, GetElementPtrInst* gep) {
        if (gep->getNumOperands() != 3) {
            return false;
        }

        auto elementIndex = cast<ConstantInt>(gep->getOperand(2))->getSExtValue();
        return elementIndex < structInfo->getElements().size();
    }

    std::string getFullyQualifiedFieldName(GetElementPtrInst* gep) {
        std::string fullyQualifiedFieldName;
        std::string structName = std::regex_replace(
            gep->getSourceElementType()->getStructName().str(),
            std::regex("^struct\\."),
            ""
        );

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
            bool validStructAccess = true;
            std::string prefix;
            while (isa<GetElementPtrInst>(pointerOperand) && validStructAccess) {
                auto *gepOperand = cast<GetElementPtrInst>(pointerOperand);
                if (gepOperand->getSourceElementType()->isStructTy()) {
                    std::string name = std::regex_replace(
                        gepOperand->getSourceElementType()->getStructName().str(),
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
                        validStructAccess = false;
                    }
                } else {
                    validStructAccess = false;
                }
            }

            if (validStructAccess) {
                // We're at an instruction that is not a GEP. It is probably either an alloca for the actual struct
                // variable in question, or a load that is loading the struct address from a pointer variable. We can
                // call getVariableName again to resolve the name.
                std::string structVarName = getVariableName(pointerOperand);
                if (!structVarName.empty()) {
                    fullyQualifiedFieldName = structVarName + "." + prefix + element;

                    // Set the declared line of this struct field to the declared line of the struct itself.
                    varToDeclaredLine[fullyQualifiedFieldName] = varToDeclaredLine[structVarName];
                }
            }
        }

        return fullyQualifiedFieldName;
    }

protected:
    std::map<std::string, int> varToDeclaredLine;
    std::set<std::string> arithmeticallyModifiedPointers;
    std::map<std::string, StructInfo*> structInfoMap;
    std::set<std::string> functionArguments;

    bool variableExists(const std::string& variableName) {
        return varToDeclaredLine.find(variableName) != varToDeclaredLine.end();
    }

    bool structExists(const std::string& structName) {
        return structInfoMap.find(structName) != structInfoMap.end();
    }

    bool isFunctionArgument(const std::string& variableName) {
        return functionArguments.find(variableName) != functionArguments.end();
    }

    bool isInvolvedInPointerArithmetic(const std::string& variableName) {
        return arithmeticallyModifiedPointers.find(variableName) != arithmeticallyModifiedPointers.end();
    }

    bool doesPointerTypeResolveToInteger(PointerType* pointerType) {
        Type* type = pointerType;
        while (isa<PointerType>(type)) {
            type = type->getPointerElementType();
        }

        return type->isIntegerTy();
    }

    Type* getPointerToIntegerType(int indirection, unsigned int bitWidth) {
        Type* type = DomainFeedback<V>::getIntTy(bitWidth);
        while (indirection > 0) {
            type = PointerType::get(type, 0);
            --indirection;
        }

        return type;
    }

    std::string getVariableName(Value* var) {
        // Strip away .addr; this happens with function arguments
        std::string varName = std::regex_replace(
            var->getName().str(),
            std::regex("\\.addr"),
            ""
        );

        if (isa<LoadInst>(var)) {
            // Handle case where we're actually working with a dereferenced pointer var; we need to recursively
            // walk up until we get to a gep for a struct field or an alloca.
            return getVariableName(cast<LoadInst>(var)->getPointerOperand());
        } else if (isa<GetElementPtrInst>(var) && cast<GetElementPtrInst>(var)->getSourceElementType()->isStructTy()) {
            // Handle case where we're modifying a struct field
            return getFullyQualifiedFieldName(cast<GetElementPtrInst>(var));
        } else if (variableExists(varName)) {
            // Variable exists and we are at an alloca instruction
            auto *alloca = cast<AllocaInst>(var);

            // While we're here, let's inspect the users of this var. If this is a pointer, we are particularly
            // interested in users that update the pointer value through pointer arithmetic. In these cases we never
            // want to report the derefenced value as the value of the var because the pointer actually represents
            // multiple values (like an array) instead of a single one. For example, assuming we have an integer pointer
            // *intptr, then *intptr = 10; and *(intptr++) = 10; are actually modifying two separate locations. We only
            // want to report the values of those pointers that have a one-to-one relationship between the pointer and
            // the value pointed to by it. In this situation it makes sense to report the dereferenced value as the
            // value of the pointer var. So if a pointer variable is ever involved in pointer arithmetic, we will add it
            // to the arithmeticallyModifiedPointers set. Base classes can then decide how they want to deal with such
            // pointers.
            if (alloca->getAllocatedType()->isPointerTy()) {
                bool involvedInArithmetic = false;
                auto it = alloca->user_begin();
                while (!involvedInArithmetic && it != alloca->user_end()) {
                    if (!isa<StoreInst>(*it)) {
                        // Only look for store instructions
                        it++;
                        continue;
                    }

                    auto *store = cast<StoreInst>(*it);
                    auto *value = store->getValueOperand();
                    if (!isa<GetElementPtrInst>(value)) {
                        // If pointer arithmetic is involved, a GEP instruction is used to calculate the result. So if
                        // this store instruction is not updating the pointer with the result of a GEP instruction, we
                        // can ignore it
                        it++;
                        continue;
                    }

                    // If the GEP instruction has two operands and the second operand is a constant integer, pointer
                    // arithmetic is being performed.
                    auto *gep = cast<GetElementPtrInst>(value);
                    involvedInArithmetic = gep->getNumOperands() == 2 && isa<ConstantInt>(gep->getOperand(1));

                    it++;
                }

                if (involvedInArithmetic) {
                    arithmeticallyModifiedPointers.emplace(varName);
                }
            }

            return varName;
        }

        return "";
    }

    virtual bool shouldProcess(llvm::Function &function) = 0;
    virtual void processFunction(llvm::Function &function) = 0;

public:
    BaseVariableValueFeedback<V>(Module &M, const StringRef &domainName, const StringRef &dsfVarName) : DomainFeedback<V>(M, dsfVarName) {
        this->domainName = domainName;
    }

    void visitFunction(llvm::Function &function) {
        if (function.getIntrinsicID() || function.empty()) {
            return;
        }

        if (!shouldProcess(function)) {
            return;
        }

        // Collect the names of the function arguments.
        for (auto &arg : function.args()) {
            functionArguments.emplace(arg.getName().str());
        }

        // Collect all local variable info from this function (includes arguments).
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (isa<DbgDeclareInst>(instruction)) {
                auto &declare = cast<DbgDeclareInst>(instruction);
                processLocalVariableDeclaration(&declare);
            }
        }

        processFunction(function);

        varToDeclaredLine.clear();
        arithmeticallyModifiedPointers.clear();
        structInfoMap.clear();
        functionArguments.clear();
    }
};
#endif //BASEVVFEEDBACK_H