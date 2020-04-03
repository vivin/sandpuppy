cmake_minimum_required(VERSION 3.15)
project(FuzzFactory)

set(CMAKE_CXX_STANDARD 14)

find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})


include_directories(.)
include_directories(include)
include_directories(llvm_mode)

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

add_executable(FuzzFactory
        demo/demo-manual.c
        demo/demo.c
        include/afl_valid.h
        include/reducers.h
        include/waypoints.h
        infantheap/infantheap.c
        llvm_mode/afl-catch-dlclose.so.c
        llvm_mode/afl-clang-fast.c
        llvm_mode/afl-llvm-pass.so.cc
        llvm_mode/afl-llvm-rt.o.c
        llvm_mode/fuzzfactory.hpp
        llvm_mode/waypoints-cmp-pass.cc
        llvm_mode/waypoints-cmp-rt.c
        llvm_mode/waypoints-diff-pass.cc
        llvm_mode/waypoints-diff-rt.c
        llvm_mode/waypoints-mem-pass.cc
        llvm_mode/waypoints-mem-rt.c
        llvm_mode/waypoints-perf-pass.cc
        llvm_mode/waypoints-perf-rt.c
        llvm_mode/waypoints-slow-pass.cc
        llvm_mode/waypoints-slow-rt.c
        llvm_mode/waypoints-valid-pass.cc
        llvm_mode/waypoints-valid-rt.c
        afl-analyze.c
        afl-as.c
        afl-as.h
        afl-fuzz.c
        afl-gcc.c
        afl-gotcpu.c
        afl-showdsf.c
        afl-showmap.c
        afl-showmax.c
        afl-tmin.c
        afl_driver.cpp
        alloc-inl.h
        android-ashmem.h
        config.h
        debug.h
        hash.h
        reducers.c
        test-instr.c
        types.h
        include/heaptrace.h
        llvm_mode/basefeedback.hpp)
