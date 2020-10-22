#include "waypoints.h"
FUZZFACTORY_DSF_NEW(__afl_heapasan_dsf, 1, FUZZFACTORY_REDUCER_MAX, 0);

void __asan_on_error() {
    FUZZFACTORY_DSF_INC(__afl_heapasan_dsf, 0, 10); // weight errors more so paths with errors have higher priority
}