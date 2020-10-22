#include "fuzzfactory.hpp"

using namespace fuzzfactory;

typedef std::pair<bool, StringRef> ValueNameLookup;

/**
 * This ONLY works with -O0 -g -gfull! We look for debug declares to find out where vars are declared. We also maintain
 * a cache of variable names. Then we look for all store insts and check to see if any operands are variables that we
 * have seen. if so we report that as a change of the variable's value.
 *
 * This class does actually look for different
 */
class VariablePrintFeedback : public fuzzfactory::DomainFeedback<VariablePrintFeedback> {

    ModuleSlotTracker *moduleSlotTracker;
    std::map<Value*, DILocalVariable*> valueLocalVariableCache;
    std::map<StringRef, bool> varNameCache;

public:
    VariablePrintFeedback(llvm::Module& M) : fuzzfactory::DomainFeedback<VariablePrintFeedback>(M, "__afl_varprint_dsf") {
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
        inst_iterator saved_itr;
        for (inst_iterator I = inst_begin(function), E = inst_end(function); I != E; I = saved_itr) {
            saved_itr = I;
            saved_itr++;

            Instruction& instruction = *I;
            /*if (instruction.hasMetadata() && !isa<PHINode>(instruction)) {
                // TODO: ignoring PHI nodes for the time being. not sure if we should be or not, but we are.
                // TODO: this gets rid of variable uses which report a line of 0 because the PHI node doesn't really
                // TODO: correspond to a location in the source, I don't think
                printVariableInformation(&instruction, &function, I);
            } */

            if (instruction.hasMetadata() && isa<StoreInst>(instruction)) {
                printVariableUsage(cast<StoreInst>(&instruction), &function);
            }
        }

        std::cout << "\n";

        varNameCache.clear();
        valueLocalVariableCache.clear();
    }

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
        }
    }

    void collectLocalVariableInfo(DbgInfoIntrinsic *debug) {
        Value *arg = nullptr;
        DILocalVariable *var = nullptr;
        if (auto *dbgDeclare = dyn_cast<DbgDeclareInst>(debug)) {
            arg = dbgDeclare->getAddress();
            var = dbgDeclare->getVariable();
            if (isa<UndefValue>(arg) || !var)
                return;
        } else if (auto *dbgValue = dyn_cast<DbgValueInst>(debug)) {
            arg = dbgValue->getValue();
            var = dbgValue->getVariable();
            if (isa<UndefValue>(arg) || !var)
                return;
        } else if (auto *dbgAddr = dyn_cast<DbgAddrIntrinsic>(debug)) {
            arg = dbgAddr->getAddress();
            var = dbgAddr->getVariable();
            if (isa<UndefValue>(arg) || !var)
                return;
        } else {
            return;
        }

        if (var->isArtificial()) {
            return;
        }

        if (!isa<DbgDeclareInst>(debug)) {
            valueLocalVariableCache[arg] = var;
        }

        if (varNameCache.find(var->getName()) == varNameCache.end()) {
            varNameCache[var->getName()] = true;
            std::cout << "  " << var->getName().str() << " declared on line " << var->getLine()
                      << " with type " << var->getType()->getName().str() << "\n";
        }
    }

    void printVariableUsage(StoreInst *store, Function* function) {
        std::string sourceFileName= store->getModule()->getSourceFileName();
        std::string functionName = function->getName();

        for (int i = 0; i < store->getNumOperands(); i++) {
            Value* v = store->getOperand(i);
            StringRef varName = v->getName();

            if (!varName.empty() && varNameCache.find(varName) != varNameCache.end()) {
                std::cout << "  " << varName.str() << " changed on line " << store->getDebugLoc()->getLine() << "\n";
            }
        }
    }

    void printVariableInformation(Instruction *instruction, Function* function, inst_iterator I) {
        std::string sourceFileName= instruction->getModule()->getSourceFileName();
        std::string functionName = function->getName();

        DILocalVariable *var = valueLocalVariableCache[instruction];
        if (!var) {
            // If we can't find the variable, we have to look for a llvm.dbg.value call
            // The debug value call is not guaranteed to come right after the instruction
            I++;
            while (!var && !I.atEnd()) {
                Instruction *inst = &*I;
                if (auto *debugValue = dyn_cast<DbgValueInst>(inst)) {
                    if (debugValue->getValue() == instruction && !debugValue->getVariable()->isArtificial()) {
                        var = debugValue->getVariable();
                    }
                }

                I++;
            }
        }

        for (int i = 0; i < instruction->getNumOperands(); i++) {
            Value* v = instruction->getOperand(i);
            if (v->getName() != "") {
                if (varNameCache.find(v->getName()) != varNameCache.end()) {
                    if(isa<StoreInst>(instruction)) {
                        std::cout << "Is a store\n";
                    }

                    std::cout << "Operand " << i << " is " << v->getName().str() << "\n";
                    std::cout << "Inst corresponds to line: " << instruction->getDebugLoc()->getLine() << "\n\n";
                }
            }
        }

        if (var) {
            std::string varname = var->getName().str();
            std::cout << "  " << varname << " changed on line " << instruction->getDebugLoc()->getLine() << "\n";
        }
    }
};

FUZZFACTORY_REGISTER_DOMAIN(VariablePrintFeedback);
