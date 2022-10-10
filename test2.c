#include "perf_pt/util.c"
#include "perf_pt/perf_pt_private.h"
#include "perf_pt/decode.c"
#include "perf_pt/collect.c"


int main(int argc, char **argv) {
 // dummy code to trigger branch taken/not taken events
    int a = 0;
    while(a < 4000) {
  
    a += 1;
    }

}
