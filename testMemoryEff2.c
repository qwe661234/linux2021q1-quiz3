#include "xs.h"

void test_function(char* str1){
    char *str2;
    str2 = malloc(sizeof(str1));
    strncpy (str2, str1, sizeof(str1));
    printf("%s\n", str1);
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
        TICK(start_t); 
        test_function(str);
        total += TOCK(start_t); 
    }
    PTIME(total);
    return 0;
}