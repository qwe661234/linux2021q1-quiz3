#include "xs.h"

void testfunction(xs prefix, xs suffix, xs str1){
    xs str2;
    xs_concat(&str1, &prefix, &suffix);
    xs_copy(&str2, &str1);
}
int main(int argc, char **argv){
    clock_t total = 0;
    for(int j = 0; j < 100000; j++){
        xs str1 = *xs_tmp("SAdasdsasdasdnlkan");
        xs prefix = *xs_tmp("((("), suffix = *xs_tmp(")))");
        TICK(start_t);
        testfunction(prefix, suffix, str1);
        total += TOCK(start_t); 
    }
    PTIME(total);
    return 0;
}