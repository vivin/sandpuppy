#define AFL_LLVM_PASS

#include "fuzzfactory.hpp"
#include <sstream>
#include <fstream>
#include <iostream>
#include <regex>

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
    std::vector<std::pair<std::string, DIType*>> elements;

public:
    StructInfo(std::string name) : name(std::move(name)) {}

    const std::string &getName() const {
        return name;
    }

    const std::vector<std::pair<std::string, DIType *>> &getElements() const {
        return elements;
    }

    void addElement(std::string name, DIType* type) {
        elements.emplace_back(name, type);
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

        if (varToDeclaredLine.find(var->getName().str()) == varToDeclaredLine.end()) {
            varToDeclaredLine[var->getName().str()] = var->getLine();

            // TODO: at some point we need to identify strings here as well. they start off
            // TODO: as a pointer type, but end up as char, so that should be enough for us
            // TODO: to identify strings. deal with them how you dealt with pointer to integer
            // TODO: variables.

            // When structs are defined with typedef, the type ends up being a DIDerivedType that
            // will eventually resolve to a DICompositeType. So if this is a DIDerivedType, we will
            // keep unwrapping it until it is not.
            DIType* varType = var->getType();
            while (varType && isa<DIDerivedType>(varType)) {
                varType = cast<DIDerivedType>(varType)->getBaseType();
            }

            if (varType && isa<DICompositeType>(varType)) {
                auto *compositeType = cast<DICompositeType>(varType);
                auto *structInfo = new StructInfo(varType->getName().str());
                DINodeArray elements = compositeType->getElements();
                for (auto element : elements) {
                    if (auto derivedType = dyn_cast<DIDerivedType>(element)) {
                        structInfo->addElement(derivedType->getName().str(), derivedType->getBaseType());
                    }
                }

                structInfoMap[varType->getName().str()] = structInfo;
            }
        }
    }

    std::string getFullyQualifiedFieldName(GetElementPtrInst* gep) {
        std::string fullyQualifiedFieldName;
        std::string structName = std::regex_replace(
            gep->getSourceElementType()->getStructName().str(),
            std::regex("^struct\\."),
            ""
        );

        if (structInfoMap.find(structName) != structInfoMap.end() && gep->getNumOperands() == 3) {
            auto *elementIndex = cast<ConstantInt>(gep->getOperand(2));

            StructInfo *structInfo = structInfoMap[structName];
            std::pair<std::string, DIType*> elementAndType = structInfo->getElements()[elementIndex->getSExtValue()];

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
                    std::string name = std::regex_replace(
                        gepOperand->getSourceElementType()->getStructName().str(),
                        std::regex("^struct\\."),
                        ""
                    );
                    if (structInfoMap.find(name) != structInfoMap.end() && gepOperand->getNumOperands() == 3) {
                        auto *_elementIndex = cast<ConstantInt>(gepOperand->getOperand(2));
                        StructInfo *_structInfo = structInfoMap[name];
                        std::pair<std::string, DIType*> _elementAndType = _structInfo->getElements()[_elementIndex->getSExtValue()];

                        prefix = _elementAndType.first.append(".").append(prefix);
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
                fullyQualifiedFieldName = structVarName + "." + prefix + elementAndType.first;

                // Set the declared line of this struct field to the declared line of the struct itself.
                varToDeclaredLine[fullyQualifiedFieldName] = varToDeclaredLine[structVarName];
            }
        }

        return fullyQualifiedFieldName;
    }

protected:
    std::map<std::string, int> varToDeclaredLine;
    std::map<std::string, StructInfo*> structInfoMap;

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
        } else if (varToDeclaredLine.find(varName) != varToDeclaredLine.end()) {
            // We're at an alloca instruction and so we should have the actual name of the variable.
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
        structInfoMap.clear();
    }
};
#endif //BASEVVFEEDBACK_H