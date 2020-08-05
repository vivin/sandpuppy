//
// Created by vivin on 3/31/20.
//

#ifndef FUZZFACTORY_HEAPTRACE_H
#define FUZZFACTORY_HEAPTRACE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Conditionally declare external functions if compiling with AFL compiler */
#if defined(__AFL_COMPILER) || defined(AFL_PATH)

void __append_trace(const char* dirname, const char* text);
void __create_trace_file_if_not_exists(const char* dirname);

#else // Not compiling with AFL

#endif // __AFL_COMPILER || AFL_PATH

#ifdef __cplusplus
}
#endif

#endif //FUZZFACTORY_HEAPTRACE_H
