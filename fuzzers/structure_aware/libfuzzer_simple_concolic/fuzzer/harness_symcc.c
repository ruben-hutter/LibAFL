#include <stdint.h>
#include <stdio.h>
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


int main(int argc, char **argv) {
    if (argc < 2) {
        return -1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(size);
    if (!data) {
        fclose(f);
        return -1;
    }

    fread(data, 1, size, f);
    fclose(f);

    if (size < 16) {
        return 0;
    }

    char *ptr = NULL;
    if (data[0] == 'Q' && data[1] == 'E' && data[2] == 'M' && data[3] == 'U') {
        return foo(data, ptr);
    }

    int result = bar(data);
    free(data);
    return result;
}
