cmake_minimum_required(VERSION 3.15)
project(FuzzFactory)

set(CMAKE_CXX_STANDARD 14)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})


include_directories(tools/FuzzFactory)
include_directories(tools/FuzzFactory/include)
include_directories(tools/FuzzFactory/llvm_mode)

#set (LLVM_LIB_PATH
#        /usr/lib/llvm-6.0
#)

#set (search_paths
#        ${LLVM_LIB_PATH}/lib/cmake
#        ${LLVM_LIB_PATH}/lib/cmake/llvm
#        ${LLVM_LIB_PATH}/lib/cmake/clang
#        ${LLVM_LIB_PATH}/share/clang/cmake/
#        ${LLVM_LIB_PATH}/share/llvm/cmake/
#)

#find_package(LLVM REQUIRED CONFIG
#        PATHS ${search_paths}
#        NO_DEFAULT_PATH)

add_executable(PhD
        subjects/infantheap/infantheap.c
        tools/FuzzFactory/demo/demo-manual.c
        tools/FuzzFactory/demo/demo.c
        tools/FuzzFactory/include/afl_valid.h
        tools/FuzzFactory/include/reducers.h
        tools/FuzzFactory/include/waypoints.h
        tools/FuzzFactory/llvm_mode/afl-catch-dlclose.so.c
        tools/FuzzFactory/llvm_mode/afl-clang-fast.c
        tools/FuzzFactory/llvm_mode/afl-llvm-pass.so.cc
        tools/FuzzFactory/llvm_mode/afl-llvm-rt.o.c
        tools/FuzzFactory/llvm_mode/fuzzfactory.hpp
        tools/FuzzFactory/llvm_mode/basevvfeedback.hpp
        tools/FuzzFactory/llvm_mode/waypoints-cmp-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-cmp-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-diff-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-diff-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-mem-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-mem-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-perf-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-perf-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-slow-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-slow-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-valid-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-valid-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-varprint-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-varprint-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-vvdump-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-vvdump-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-vvperm-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-vvperm-rt.c
        tools/FuzzFactory/llvm_mode/waypoints-vvhash-pass.cc
        tools/FuzzFactory/llvm_mode/waypoints-vvhash-rt.c
        tools/FuzzFactory/afl-analyze.c
        tools/FuzzFactory/afl-as.c
        tools/FuzzFactory/afl-as.h
        tools/FuzzFactory/afl-fuzz.c
        tools/FuzzFactory/afl-gcc.c
        tools/FuzzFactory/afl-gotcpu.c
        tools/FuzzFactory/afl-showdsf.c
        tools/FuzzFactory/afl-showmap.c
        tools/FuzzFactory/afl-showmax.c
        tools/FuzzFactory/afl-tmin.c
        tools/FuzzFactory/afl_driver.cpp
        tools/FuzzFactory/alloc-inl.h
        tools/FuzzFactory/android-ashmem.h
        tools/FuzzFactory/config.h
        tools/FuzzFactory/debug.h
        tools/FuzzFactory/hash.h
        tools/FuzzFactory/reducers.c
        tools/FuzzFactory/test-instr.c
        tools/FuzzFactory/types.h
        tools/FuzzFactory/include/vvdump.h
        tools/FuzzFactory/llvm_mode/shared-opts.cc)

add_executable(rarebug
        subjects/rarebug/rarebug.c)

add_executable(maze
        subjects/maze/maze.c)
