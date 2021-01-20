//
// Created by vivin on 5/15/20.
//

#include "fuzzfactory.hpp"

std::string VariablesFile;

using namespace fuzzfactory;

static cl::opt<std::string, true> VariablesFileOption(
    "variables_file",
    cl::desc("File containing list of variables to target for value permutation fuzzing"),
    cl::value_desc("variables_file"),
    cl::location(VariablesFile)
);
