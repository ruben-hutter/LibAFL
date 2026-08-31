#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>


int foo(const uint8_t *data, char *ptr) {
    if (data[4] == 0x42 && data[5] == 0x13 && data[6] == 0x37) {
        if (data[7] * data[8] == 0x1234 && data[9] + data[10] == 0xFF) {
            *ptr = 'A';
            return 1;
        }
    }
    return 0;
}


int bar(const uint8_t *data) {
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

    LLVMFuzzerTestOneInput(data, size);

    free(data);
    return 0;
}
