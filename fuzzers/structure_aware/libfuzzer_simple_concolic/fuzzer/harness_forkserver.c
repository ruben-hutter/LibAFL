#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>


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


int main(int argc, char **argv) {
    raise(SIGSTOP);

    while (1) {
        pid_t pid = fork();
        if (pid < 0) {
            _exit(1);
        }

        if (pid == 0) {
            FILE *f = fopen("cur_input", "rb");
            if (!f) _exit(1);

            fseek(f, 0, SEEK_END);
            long size = ftell(f);
            fseek(f, 0, SEEK_SET);

            uint8_t *data = malloc(size);
            if (!data) { fclose(f); _exit(1); }

            fread(data, 1, size, f);
            fclose(f);

            if (size >= 16) {
                char *ptr = NULL;
                if (data[0] == 'Q' && data[1] == 'E' && data[2] == 'M' && data[3] == 'U') {
                    foo(data, ptr);
                } else {
                    bar(data);
                }
            }

            free(data);
            _exit(0);
        }

        waitpid(pid, NULL, 0);
        raise(SIGSTOP);
    }

    return 0;
}
