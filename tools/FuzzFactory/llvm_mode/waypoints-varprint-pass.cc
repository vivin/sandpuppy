#include <utility>
#include <regex>

#include "fuzzfactory.hpp"

using namespace fuzzfactory;

/**
 * This ONLY works with -O0 -g -gfull! We look for debug declares to find out where vars are declared. We also maintain
 * a cache of variable names. Then we look for all store insts and check to see if any operands are variables that we
 * have seen. if so we report that as a change of the variable's value.
 *
 * This class does actually look for different
 */
class VariablePrintFeedback : public fuzzfactory::DomainFeedback<VariablePrintFeedback> {

    class CompositeType {
        std::string name;
        std::vector<std::pair<std::string, DIType*>> elements;

    public:
        CompositeType(std::string name) : name(std::move(name)) {}

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

    ModuleSlotTracker *moduleSlotTracker;
    std::map<Value*, DILocalVariable*> valueLocalVariableCache;
    std::map<StringRef, bool> varNameCache;
    std::map<std::string, CompositeType*> compositeTypes;
    std::map<std::string, int> structVarToDeclaredLine;

    void processLocalVariableDeclaration(DbgDeclareInst* declare) {
        Value *arg = declare->getAddress();
        DILocalVariable *var = declare->getVariable();

        if (isa<UndefValue>(arg) || !var)
            return;

        if (var->isArtificial()) {
            return;
        }

        if (varNameCache.find(var->getName()) == varNameCache.end()) {
            varNameCache[var->getName()] = true;
            std::cout << "  " << var->getName().str() << " declared on line " << var->getLine()
                      << " with type " << var->getType()->getName().str() << "\n";

            // TODO: identify typedef union struct. See TestHash in AlgorithmTests.c in libtpms.

            // TODO: at some point we need to identify strings here as well. they start off
            // TODO: as a pointer type, but end up as char, so that should be enough for us
            // TODO: to identify strings. but trouble happens when you look at how strings are
            // TODO: modified. this is easily seen with just an int pointer variable. if you had
            // TODO: int *p; and *p = 5;, then we see a load from *%p into a temp variable, and
            // TODO: then a store using the temp variable. so when looking at variable usage, we
            // TODO: may have to walk up a "load" chain to identify the actual pointer variable
            // TODO: being modified.
            bool done = false;
            DIType* varType = var->getType();
            while (!done && isa<DIDerivedType>(varType)) {
                //varType->print(llvm::outs());
                //std::cout << "\n";

                if (cast<DIDerivedType>(varType)->getBaseType()) {
                    varType = cast<DIDerivedType>(varType)->getBaseType();
                } else {
                    // Sometimes the base type is null. If so, let's just stop.
                    done = true;
                }
            }

            //std::cout << "ok final type is:\n";
            //varType->print(llvm::outs());

            if (auto *compositeType = dyn_cast<DICompositeType>(varType)) {
                std::cout << "    This is a composite type " << var->getName().str() << "\n";

                auto *composite = new CompositeType(varType->getName().str());
                DINodeArray elements = compositeType->getElements();
                for (auto element : elements) {
                    //element->print(llvm::outs(), nullptr, false);
                    //std::cout << "\n";
                    if (auto derivedType = dyn_cast<DIDerivedType>(element)) {
                        std::cout << "      Element name is " << derivedType->getName().str() << " with base type "
                                  << derivedType->getBaseType()->getName().str() << "\n";
                        composite->addElement(derivedType->getName().str(), derivedType->getBaseType());
                    }
                }

                structVarToDeclaredLine[var->getName().str()] = var->getLine();
                compositeTypes[varType->getName().str()] = composite;
            }

            std::cout << "\n";
        }
    }

    void printVariableUsage(StoreInst *store, Function* function) {
        std::string sourceFileName= store->getModule()->getSourceFileName();
        std::string functionName = function->getName();

        if (store->getDebugLoc() && store->getValueOperand()->getType()->isIntegerTy()) {
            identifyModifiedVariable(store, store->getPointerOperand());
        }
    }

    void identifyModifiedVariable(StoreInst *store, Value* variable) {
        StringRef varName = variable->getName();
        if (auto *load = dyn_cast<LoadInst>(variable)) {
            // Handle case where we're actually working with a dereferenced pointer variable; we need to recursively
            // walk up until we get to a gep for a struct field or an alloca.
            identifyModifiedVariable(store, load->getPointerOperand());
        } else if (auto *gep = dyn_cast<GetElementPtrInst>(variable)) {
            // Handle case where we're possibly modifying a struct field
            handleGep(store, gep);
        } else if (!varName.empty() && varNameCache.find(varName) != varNameCache.end()) {
            // We're at an alloca instruction and so we should have the actual name of the variable
            std::cout << "  " << varName.str() << " changed on line " << store->getDebugLoc()->getLine() << "\n\n";
        }
    }

    void handleGep(const StoreInst *store, GetElementPtrInst *gep) {
        if (gep->getSourceElementType()->isStructTy()) {
            std::string structName = std::regex_replace(gep->getSourceElementType()->getStructName().str(), std::regex("^struct\\."), "");

            if (compositeTypes.find(structName) != compositeTypes.end() && gep->getNumOperands() == 3) {
                auto *structElementIndex = cast<ConstantInt>(gep->getOperand(2));
                CompositeType *compositeType = compositeTypes[structName];

                //std::cout << " the struct name is " << structName << "\n";
                //std::cout << " composite type is " << compositeType << "\n";
                //std::cout << " sext value for index is " << structElementIndex->getSExtValue() << "\n";
                //std::cout << " num elements we know of " << compositeType->getElements().size() << "\n";

                std::pair<std::string, DIType *> elementAndType = compositeType->getElements()[structElementIndex->getSExtValue()];

                //auto *setype = gep->getSourceElementType()->getStructElementType(structElementIndex->getSExtValue());
                //std::cout << " printing struct element type...\n";
                //setype->print(outs());
                //std::cout << "\n";

                // At this point we have the name of the struct and the element we are modifying
                /*
                std::cout << "  Element " << structElementIndex->getSExtValue() << " of struct " << structName << " changed on line " << store->getDebugLoc()->getLine() << "\n";
                std::cout << "  There are " << gep->getNumIndices() << " indices and " << gep->getNumOperands() << " operands \n";

                std::cout << "  operand 1:\n";
                gep->getOperand(0)->print(llvm::outs());
                std::cout <<"\n  operand 2:\n";
                gep->getOperand(1)->print(llvm::outs());
                std::cout <<"\n  operand 3:\n";
                gep->getOperand(2)->print(llvm::outs());
                std::cout <<"\n";

                //store->print(llvm::outs());
                std::cout <<"Printing out the value itself whose name is " << v->getName().str() << ":\n";
                v->print(llvm::outs());
                std::cout <<"\nPrinting source type:\n";
                gep->getSourceElementType()->print(llvm::outs());

                std::cout <<"\nPrinting result type:\n";
                gep->getResultElementType()->print(llvm::outs());
                std::cout <<"\nPrinting pointer operand:\n";
                gep->getPointerOperand()->print(llvm::outs());
                std::cout <<"\nPrinting pointer operand type:\n";
                gep->getPointerOperandType()->print(llvm::outs());
                std::cout <<"\n\n";
                 */

                // If this is a pointer to the struct, walk up the load chain until it isn't one.
                Value *pointerOperand = gep->getPointerOperand();
                while (isa<LoadInst>(pointerOperand)) {
                    pointerOperand = cast<LoadInst>(pointerOperand)->getPointerOperand();
                }

                bool onlyStructs = true;
                std::string prefix = "";
                while (isa<GetElementPtrInst>(pointerOperand) && onlyStructs) {
                    auto *gepOperand = cast<GetElementPtrInst>(pointerOperand);
                    onlyStructs = gepOperand->getSourceElementType()->isStructTy();
                    if (onlyStructs) {
                        std::string name = std::regex_replace(
                            gepOperand->getSourceElementType()->getStructName().str(), std::regex("^struct\\."),
                            "");
                        if (compositeTypes.find(name) != compositeTypes.end() && gepOperand->getNumOperands() == 3) {
                            auto *elementIndex = cast<ConstantInt>(gepOperand->getOperand(2));
                            CompositeType *type = compositeTypes[name];
                            std::pair<std::string, DIType *> _elementAndType = type->getElements()[elementIndex->getSExtValue()];

                            prefix = _elementAndType.first + "." + prefix;
                            pointerOperand = gepOperand->getPointerOperand();
                        } else {
                            std::cerr << "Unknown struct " << name << "\n";
                            onlyStructs = false;
                        }
                    }
                }

                std::string structVarName = std::regex_replace(pointerOperand->getName().str(), std::regex("\\.addr"), "");
                std::string fullyQualifiedName = structVarName + "." + prefix + elementAndType.first;
                std::cout << "\n  " << fullyQualifiedName << " changed on line "
                          << store->getDebugLoc()->getLine() << " (struct declared on "
                          << structVarToDeclaredLine[structVarName] << ")\n\n";

            }
        }
    }

public:
    explicit VariablePrintFeedback(llvm::Module& M) : fuzzfactory::DomainFeedback<VariablePrintFeedback>(M, "__afl_varprint_dsf") {
        moduleSlotTracker = new ModuleSlotTracker(&M);
    }

    // Uses code from:
    // https://github.com/harvard-acc/LLVM-Tracer/blob/master/full-trace/full_trace.cpp

    void visitFunction(llvm::Function &function) {
        std::cout << "In function " << function.getName().str();
        if (function.getSubprogram()) {
            std::cout << " from file " << function.getSubprogram()->getFilename().str();
        }

        std::cout << "\n";

        moduleSlotTracker->incorporateFunction(function);

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

        varNameCache.clear();
        valueLocalVariableCache.clear();
        structVarToDeclaredLine.clear();
        compositeTypes.clear();
    }
};

FUZZFACTORY_REGISTER_DOMAIN(VariablePrintFeedback);
