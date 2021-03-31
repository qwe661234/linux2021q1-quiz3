#include "xs.h"

void testfunction(xs prefix, xs suffix, xs str1){
    xs str2;
    xs_concat(&str1, &prefix, &suffix);
    xs_copy(&str2, &str1);
}
int main(int argc, char **argv){
    clock_t total = 0;
    srand(time(0));
    for(int j = 0; j < 1000; j++){
        char *str = malloc(sizeof(char) * 21);
        for(int i = 0; i < 20; i++){
            int a = rand() % 58 + 65;
            str[i] = (char)a;
        }
        str[20] = 0;
        xs str1;
        xs prefix = *xs_tmp("((("), suffix = *xs_tmp(")))");
        str1.ptr = str;
        str1.is_ptr = 1;
        TICK(start_t);
        testfunction(prefix, suffix, str1);
        total += TOCK(start_t); 
    }
    PTIME(total);
    return 0;
}