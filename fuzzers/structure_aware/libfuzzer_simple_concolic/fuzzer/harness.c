#include <stdint.h>
#include <stdlib.h>


int foo(const uint8_t *data, char *ptr) {
    // Check for magic values that are hard to find via fuzzing
    // but easy for symbolic execution to solve
    if (data[4] == 0x42 && data[5] == 0x13 && data[6] == 0x37) {
        if (data[7] * data[8] == 0x1234 && data[9] + data[10] == 0xFF) {
            // Make program crash
            *ptr = 'A';
            return 1;
        }
    }
    return 0;
}


int bar(const uint8_t *data) {
    // Less interesting path - just some basic checks
    if (data[4] > 0x80 && data[5] < 0x20) {
        return 1;
    }
    return 0;
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 16) {
        return 0;
    }

    char *ptr = NULL;

    if (data[0] == 'Q' && data[1] == 'E' && data[2] == 'M' && data[3] == 'U') {
        return foo(data, ptr);
    }
    return bar(data);
}

