#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>

#include "llvm/Pass.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/ModuleSlotTracker.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/RandomNumberGenerator.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

#ifndef FUZZFACTORY_H
#define FUZZFACTORY_H

extern std::string VariablesFile;

namespace fuzzfactory {

using namespace llvm;

/** Hacky struct to get name of template type parameter X */
    template<typename X> struct TypeName;

/** Instrumentation pass for a fuzzing domain */
template<class D>
class RegisterDomain : public ModulePass {

public:
    static char ID; // This silly char is required by LLVM, which remembers its address (ugh)

    /** Registers this domain's instrumentation pass with LLVM's pass manager */
    static void registerPass(const PassManagerBuilder &, legacy::PassManagerBase &PM) {
      OKF("Registering pass for [%s].", TypeName<D>::name);
      PM.add(new RegisterDomain<D>());
    }

    /** Instatiates a new domain and immediately registered the instrumentation pass with LLVM */
    RegisterDomain() : ModulePass(RegisterDomain<D>::ID) { }

    /* Runs this instrumentation pass on a module */
    bool runOnModule(Module &M) override {
        D instrumentor(M);
        instrumentor.setRNG(M.createRNG(this));
        instrumentor.visit(M);
        instrumentor.done();
        return true;
    }
};

template<class D>
char RegisterDomain<D>::ID = 0; // This silly char is required by LLVM, which remembers its address (ugh)

/** Base class for domain-specific fuzzing instrumentation */
template<class V>
class DomainFeedback : public InstVisitor<V, void> {

public:

    DomainFeedback<V>(Module &M, StringRef dsfVarName) : M(M), C(M.getContext()) {
        // Create basic types
        this->Int32Ty = getIntTy(32);
        this->Int64Ty = getIntTy(64);
        this->VoidTy = getVoidTy();

        // Create a reference to global var containing DSF map
        this->DsfMapVariable = new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, dsfVarName);

        // Create references to standard DSF functions
        this->DsfIncrementFunction = resolveFunction("__fuzzfactory_dsfp_increment", VoidTy, {getIntPtrTy(32), Int32Ty, Int32Ty});
    }

    void setRNG(std::unique_ptr<RandomNumberGenerator> rng) {
        this->random = std::move(rng);
    }

    void done() {
        if (NumInstrumentationPoints) {
            OKF("[%s] Instrumented %lu locations.", TypeName<V>::name, NumInstrumentationPoints);
        } else {
            WARNF("[%s] No instrumentation targets found.", TypeName<V>::name);
        }
    }

protected: 
    Module& M;
    LLVMContext& C;
    std::unique_ptr<RandomNumberGenerator> random;
    IntegerType *Int32Ty;
    IntegerType *Int64Ty;
    Type *VoidTy;
    GlobalVariable* DsfMapVariable;
    Function* DsfIncrementFunction;
    unsigned long NumInstrumentationPoints = 0;

    Type* getVoidTy() {
        return Type::getVoidTy(C);
    } 

    IntegerType* getIntTy(unsigned bw) {
       return IntegerType::get(C, bw);
    }

    PointerType* getIntPtrTy(unsigned bw) {
        return PointerType::getUnqual(getIntTy(bw));
    }

    ConstantInt* getConst(int x) {
        return ConstantInt::get(Int32Ty, x);
    }

    /** Generates a random 31-bit unsigned integer */
    uint32_t generateRandom31() {
        uint32_t r = (*random)();
        return r >> 1;
    }

    /** Generates a random 31-bit unsigned integer and returns it as an LLVM constant */
    Value* createProgramLocation() {
        return getConst(generateRandom31());
    }


    /* Get declared function or else return NULL. */
    Function* getFunctionIfExists(StringRef name) {
        return M.getFunction(name);
    }

    /* Get declared function or else declare a new function. Never returns NULL. */
    Function* resolveFunction(StringRef name, Type* retType, ArrayRef<Type*> argTypes) {
        return resolveFunction(name, retType, argTypes, false);
    }

    /* Get declared function or else declare a new function. Never returns NULL. */
    Function* resolveFunction(StringRef name, Type* retType, ArrayRef<Type*> argTypes, bool isVarArg) {
        Function* f = M.getFunction(name);
        if (f) {
            return f;
        } else {
            return Function::Create(FunctionType::get(retType, argTypes, isVarArg), GlobalValue::ExternalLinkage, name, &M);
        }
    }

    /* Get declared function or else declare a new function. Never returns NULL. */
    Function* resolveFunction(StringRef name, FunctionType* funType) {
        Function* f = M.getFunction(name);
        if (f) {
            return f;
        } else {
            return Function::Create(funType, GlobalValue::ExternalLinkage, name, &M);
        }
    }

    IRBuilder<> insert_before(BasicBlock& bb) {
        // Preprend to basic block
        BasicBlock::iterator ip = bb.getFirstInsertionPt();
        IRBuilder<> irb(&bb, ip);
        NumInstrumentationPoints++;
        return irb;
    }

    IRBuilder<> insert_after(BasicBlock& bb){
        // Append to basic block
        IRBuilder<> irb(&bb);
        NumInstrumentationPoints++;
        return irb;
    }


    IRBuilder<> insert_before(Instruction& inst) {
        IRBuilder<> irb(&inst);
        NumInstrumentationPoints++;
        return irb;
    }

    IRBuilder<> insert_after(Instruction& inst){
        IRBuilder<> irb(inst.getNextNode());
        NumInstrumentationPoints++;
        return irb;
    }

    Value* loadDsfMapVariable(IRBuilder<> irb) {
        return irb.CreateLoad(DsfMapVariable);
    }

};

}

/* Called by client domains at the top-level using the instrumentation pass as typename D */
#define FUZZFACTORY_REGISTER_DOMAIN(D)  template <> struct fuzzfactory::TypeName<D> \
    { static const char* name; } ; const char* fuzzfactory::TypeName<D>::name = #D; \
    static fuzzfactory::RegisterDomain<D> D; \
    RegisterStandardPasses RegisterFuzzFactoryPass(PassManagerBuilder::EP_OptimizerLast, fuzzfactory::RegisterDomain<class D>::registerPass); \
    RegisterStandardPasses RegisterFuzzFactoryPass0(PassManagerBuilder::EP_EnabledOnOptLevel0, fuzzfactory::RegisterDomain<class D>::registerPass);

//NOTE: the above macro has been modified to register the pass. Previously, this was done via the constructor in
//RegisterDomain, which would register and then reference the static method. However this stopped working because
//the registerPass method would never be called. This might be due to a change in the LLVM API. Anyway, the macro
//above seems to work.

#endif // FUZZFACTORY_H
