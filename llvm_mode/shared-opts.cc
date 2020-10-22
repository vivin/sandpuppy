//
// Created by vivin on 5/15/20.
//

#include "fuzzfactory.hpp"

std::string FunctionsFile;

using namespace fuzzfactory;

static cl::opt<std::string, true> FunctionsFileOption(
    "functions_file",
    cl::desc("File containing list of library functions to intercept."),
    cl::value_desc("functions_file"),
    cl::location(FunctionsFile)
);
