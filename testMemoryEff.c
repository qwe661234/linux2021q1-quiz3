#include "xs.h"

void test_function(xs str1){
    xs str2;
    *xs_copy(&str2, &str1);
}

int main(int argc, char *argv[])
{
    clock_t total = 0;
    srand(time(0));
    for(int j = 0; j < 1000; j++){
        char *str = malloc(sizeof(char) * 326);
        for(int i = 0; i < 325; i++){
            int a = rand() % 58 + 65;
            str[i] = (char)a;
        }
        str[325] = 0;
        xs str1;
        str1.ptr = str;
        str1.is_large_string = 1;
        TICK(start_t); 
        test_function(str1);
        total += TOCK(start_t); 
    }
    PTIME(total);
    return 0;
}