#include "xs.h"

int main(int argc, char *argv[])
{
    TICK(start_t);
    char *str1, *str2;
    str1 = "foobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbar";
    str2 = malloc(sizeof(str1));
    strncpy (str2, str1, sizeof(str1)); 
    TOCK(start_t);
    return 0;
}