#include "waypoints.h"
#include <stdio.h>

typedef unsigned long uptr;
typedef unsigned long long uhwptr;

void __asan_report_load1(uptr addr) {
    printf("report load1");
}
void __asan_report_load2(uptr addr) {
    printf("report load2");
}

void __asan_report_load4(uptr addr) {
    printf("report load4");
}

void __asan_report_load8(uptr addr) {
    printf("report load8");
}

void __asan_report_load16(uptr addr) {
    printf("report load16");
}

void __asan_report_load_n(uptr addr, uptr size) {
    printf("report load_n");
}

void __asan_report_store1(uptr addr) {
    printf("report store1");
}
void __asan_report_store2(uptr addr) {
    printf("report store2");
}

void __asan_report_store4(uptr addr) {
    printf("report store4");
}

void __asan_report_store8(uptr addr) {
    printf("report store8");
}

void __asan_report_store16(uptr addr) {
    printf("report store16");
}

void __asan_report_store_n(uptr addr, uptr size) {
    printf("report store_n");
}