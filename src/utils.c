#include "utils.h"


char * NUMERICS = "0123456789abcdef";

#define hdigit(n) NUMERICS[n & 0xf]


unsigned char * bin_to_hex(unsigned char *from, unsigned char *to, size_t length) {
    to[(2 * length)] = 0;
    int n = 0;
    for(;n < length;n++) {
        to[(2 * n) + 1] = hdigit(from[n]);
        to[(2 * n)] = hdigit(from[n] >> 4);
    }
    return to;
}


void export_to_file(const char *filename, unsigned char *buf, size_t len) {
    printf("Export into %s\n", filename);
    FILE *fd = fopen(filename, "wb");
    fwrite(buf, len, 1, fd);
    fclose(fd);
}


void export_to_stdout(unsigned char *buf, size_t len) {
    unsigned char *hex;
    hex = malloc(len * 2 + 1);
    bin_to_hex(buf, hex, len);
    printf("%s\n", hex);
    free(hex);
}
