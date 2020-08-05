#include "waypoints.h"

__thread u32 __afl_lfcof_prev_loc;

FUZZFACTORY_DSF_NEW(__afl_lfcof_dsf, MAP_SIZE, FUZZFACTORY_REDUCER_MAX, 0);
