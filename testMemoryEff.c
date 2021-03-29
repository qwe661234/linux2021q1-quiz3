#include "xs.h"

int main(int argc, char *argv[])
{
    TICK(start_t);
    xs str1;
    xs str2;
    str1 = *xs_tmp("foobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbarfoobarbar");
    *xs_copy(&str2, &str1);
    TOCK(start_t);
    return 0;
}