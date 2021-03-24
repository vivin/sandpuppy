#define AFL_LLVM_PASS

#include "llvm/Transforms/Utils/BasicBlockUtils.h"
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
                // variable in question, a load that is loading the struct address from a pointer variable, or just
                // a Value referring to the struct pointer (without a corresponding alloca). To resolve the name, we
                // call getVariableName again.
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
    std::vector<StoreInst*> storeInstructions;
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

    bool isPointerTypeResolvingToIntegerType(Type* type) {
        if (!type->isPointerTy()) {
            return false;
        }

        while (isa<PointerType>(type)) {
            type = type->getPointerElementType();
        }

        return type->isIntegerTy();
    }

    IntegerType* unwrapPointerTypeToIntegerType(Type* type) {
        if (!type->isPointerTy()) {
            std::cerr << "Cannot unwrap as provided type is not a pointer type.";
            abort();
        }

        while (isa<PointerType>(type)) {
            type = type->getPointerElementType();
        }

        if (!type->isIntegerTy()) {
            std::cerr << "Cannot unwrap to IntegerType as provided type is not a pointer to one.";
            abort();
        }

        return cast<IntegerType>(type);
    }

    bool isStoreInstForVariable(StoreInst *store, const std::string& variableName) {
        return variableName == getVariableName(store->getPointerOperand());
    }

    std::string getQualifiedFunctionName(Function* function) {
        return std::regex_replace(
            std::regex_replace(
                function->getParent()->getSourceFileName(),
                std::regex("^/"),
                ""
            ),
            std::regex("[/]"),
            "."
        ) + "." + function->getName().str();
    }

    std::string getQualifiedVariableName(Function* function, const std::string& variableName) {
        return getQualifiedFunctionName(function) + "." + variableName;
    }

    PointerType* getPointerToIntegerType(int indirection, unsigned int bitWidth) {
        if (indirection <= 0) {
            std::cerr << "Cannot create a pointer to integer type with zero or negative levels of indirection.\n";
            abort();
        }

        Type* type = DomainFeedback<V>::getIntTy(bitWidth);
        while (indirection > 0) {
            type = PointerType::get(type, 0);
            --indirection;
        }

        return cast<PointerType>(type);
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
        } else if (variableExists(varName) && isa<AllocaInst>(var)) {
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
        } else if (variableExists(varName)) {
            // There is no alloca; var is probably just a Value. This is seen in cases where a GEP uses as pointer
            // operand, a struct without a corresponding alloca.
            return varName;
        }

        return "";
    }

    Value* safelyDereferenceStoreValueOperand(StoreInst *store, const std::string &variableName, IRBuilder<> &irb) {
        Value* value = store->getValueOperand();
        if (!value->getType()->isPointerTy() || !isPointerTypeResolvingToIntegerType(value->getType())) {
            std::cerr << variableName << " is not a pointer that resolves to an integer.\n";
            abort();
        }

        std::string notNullVariableName = variableName + ".is.not.null";
        std::string ifVariableIsNotNullBlockName = "if." + notNullVariableName;
        std::string ifVariableIsNotNullEndBlockName = ifVariableIsNotNullBlockName + ".end";

        // Set insertion point to start at the next non-debug instruction.
        irb.SetInsertPoint(store->getNextNonDebugInstruction());

        // We need to generate an if-then so that we only use the variable value if the pointer is not null.
        // Otherwise we will get a SIGSEGV. We will split the block before the next non-debug instruction.
        auto *splitBeforeInstruction = store->getNextNonDebugInstruction();
        auto *pointerType = cast<PointerType>(store->getPointerOperandType()->getPointerElementType());
        auto *loadPointer = irb.CreateAlignedLoad(pointerType, store->getPointerOperand(), store->getAlign());
        auto *condition = irb.CreateICmpNE(loadPointer, ConstantPointerNull::get(pointerType), notNullVariableName);
        auto *thenBlock = SplitBlockAndInsertIfThen(condition, splitBeforeInstruction, false);

        thenBlock->getParent()->setName(ifVariableIsNotNullBlockName);
        splitBeforeInstruction->getParent()->setName(ifVariableIsNotNullEndBlockName);

        irb.SetInsertPoint(thenBlock);

        // Find how many levels of indirection are involved
        auto *type = store->getValueOperand()->getType();
        int indirection = 0;
        while (type->isPointerTy()) {
            indirection++;
            type = type->getPointerElementType();
        }

        // We will now insert as many load statements as necessary in order to dereference the pointer. This depends on
        // the level of indirection, which we have calculated. While we do that we will also guard these with null
        // checks as we did above. We can assume this is an integer type because we have checked for that earlier.
        unsigned int bitWidth = type->getIntegerBitWidth();
        Value* load = value;
        while (indirection > 1) {
            pointerType = getPointerToIntegerType(indirection - 1, bitWidth);
            load = irb.CreateAlignedLoad(pointerType, load, store->getAlign());
            condition = irb.CreateICmpNE(load, ConstantPointerNull::get(pointerType), notNullVariableName);
            splitBeforeInstruction = cast<Instruction>(condition)->getNextNonDebugInstruction();
            thenBlock = SplitBlockAndInsertIfThen(condition, splitBeforeInstruction, false);

            thenBlock->getParent()->setName(ifVariableIsNotNullBlockName);
            splitBeforeInstruction->getParent()->setName(ifVariableIsNotNullEndBlockName);

            irb.SetInsertPoint(thenBlock);

            --indirection;
        }

        return irb.CreateAlignedLoad(DomainFeedback<V>::getIntTy(bitWidth), load, store->getAlign());
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

        // Collect all store instructions
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; ++I) {
            Instruction& instruction = *I;
            if (isa<StoreInst>(instruction)) {
                storeInstructions.emplace_back(cast<StoreInst>(&instruction));
            }
        }

        processFunction(function);

        storeInstructions.clear();
        varToDeclaredLine.clear();
        arithmeticallyModifiedPointers.clear();
        structInfoMap.clear();
        functionArguments.clear();
    }
};
#endif //BASEVVFEEDBACK_H