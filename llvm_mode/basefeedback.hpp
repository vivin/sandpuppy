//
// Created by vivin on 3/31/20.
//
#define AFL_LLVM_PASS

#include "fuzzfactory.hpp"
#include <sstream>
#include <fstream>
#include <iostream>

#ifndef BASEFEEDBACK_H
#define BASEFEEDBACK_H

using namespace fuzzfactory;

bool hasFunctionsFile() {
    return !FunctionsFile.empty();
}

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

bool load_functions(std::vector<std::string>* functions) {
    if (!hasFunctionsFile()) {
        std::cerr << "No functions file provided through -functions_file option.\n";
        return false;
    }

    std::ifstream functionsFile(FunctionsFile);
    if ((functionsFile.rdstate() & std::ifstream::failbit ) != 0 ){
        std::cerr << "Error opening " << FunctionsFile << "\n";
        return false;
    }

    std::string line;
    while (std::getline(functionsFile, line)){
        functions->push_back(line);
    }

    return true;
}

/** Base class for library function feedback instrumentation **/
template<class V>
class BaseLibraryFunctionFeedback : public DomainFeedback<V> {

private:

    StringRef domainName;
    std::vector<std::string> functions;

public:

    BaseLibraryFunctionFeedback<V>(Module &M, const StringRef &domainName, const StringRef &dsfVarName) : DomainFeedback<V>(M, dsfVarName) {
        if (!load_functions(&functions)) {
            std::cerr << "Could not load functions to intercept.\n";
            return;
        }

        this->domainName = domainName;
    }

protected:

    bool shouldInterceptFunction(Function *function) {
        std::string functionName = function->getName();
        return std::find(functions.begin(), functions.end(), functionName) != functions.end();
    }
};
#endif //BASEFEEDBACK_H
