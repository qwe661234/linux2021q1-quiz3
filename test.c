#include "xs.h"

int main(int argc, char **argv){
    xs str1 = *xs_tmp("(((xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx)))");
	xs str2 = *xs_tmp("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    xs prefix = *xs_tmp("((("), suffix = *xs_tmp(")))");
    str2 = *xs_concat(&str2, &prefix, &suffix);
    printf("[%s] : %2zu\n", xs_data(&str2), xs_size(&str2));
	return 0;
}

