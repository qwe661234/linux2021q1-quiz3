#include "xs.h"

void test_function(){

}

int main(int argc, char *argv[])
{
    TICK(start_t);
    xs string = *xs_tmp("\n foobarbar \n\n\n");
    xs_trim(&string, "\n ");
    printf("[%s] : %2zu\n", xs_data(&string), xs_size(&string));

    xs prefix = *xs_tmp("((("), suffix = *xs_tmp(")))");
    xs_concat(&string, &prefix, &suffix);
    printf("[%s] : %2zu\n", xs_data(&string), xs_size(&string));
    TOCK(start_t);
    printf("%ld", CLOCKS_PER_SEC);
    printf("%ld", sizeof(char*));
    return 0;
}