#include "utils.h"
#include "parg.h"

#define SET_CMD(x, Y)  \
    if(x != CMD_NIL) { \
        fprintf(stderr, "Only one cmd option allowed (unwanted -%c)\n", c); \
        return 1; \
    }; \
    x = Y;

static const struct parg_option params_config[] = {
    { "tcti",   PARG_REQARG, NULL, 'T' },
    { "random", PARG_NOARG,  NULL, 'r' },
    { "clear",  PARG_NOARG,  NULL, 'c' },
    { "pub",    PARG_NOARG,  NULL, 'p' },
    { "sign",   PARG_NOARG,  NULL, 's' },
    { "input",  PARG_OPTARG, NULL, 'i' },
    { "output", PARG_OPTARG, NULL, 'o' },
    { 0, 0, 0, 0 }
};


int demo_random(context *ctx, const char *output) {
    unsigned char buf[32] = {0};
    size_t len = 32;
    TPM2_RC rc;

    printf("Demo random\n");
    rc = get_random(ctx, (unsigned char **)&buf, &len);
    check_rc(rc);

    printf("TPM returned random bytes length %d:\n", (int)len);
    if(output[0]) {
        export_to_file(output, buf, len);
    } else {
        export_to_stdout(buf, len);
    }
    return 0;
}


int demo_sign(context *ctx, const char *filename, const char *output) {
    unsigned char data[1024], *buf;
    size_t data_len = 0, buf_len = 0;
    TPM2_RC rc;
    FILE *fp;

    printf("Demo sign\n");

    if(filename[0] != 0) {
        fp = fopen(filename, "rb");
        if(!fp) {
            fprintf(stderr, "Unable to open %s\n", filename);
            return 1;
        }
    } else {
        fp = stdin;
    }

    data_len = fread(data, 1, 1024, fp);

    if(filename) {
        fclose(fp);
    }

    rc = sign(ctx, data, data_len, &buf, &buf_len);
    check_rc(rc);

    printf("TPM returned signature length %d:\n", (int)buf_len);
    if(output[0]) {
        export_to_file(output, buf, buf_len);
    } else {
        export_to_stdout(buf, buf_len);
    }
    free(buf);
    return 0;
}


int demo_pub(context *ctx, const char *output) {
    unsigned char *buf = NULL;
    size_t len = 0;
    TPM2_RC rc;

    printf("Demo pub\n");
    rc = pub(ctx, (unsigned char **)&buf, &len);
    check_rc(rc);

    printf("TPM returned Public key in DER format\n");
    if(output[0]) {
        export_to_file(output, buf, len);
    } else {
        export_to_stdout(buf, len);
    }
    free(buf);
    return 0;
}


int demo_clear(context *ctx) {
    printf("Demo pub\n");
    return 0;
}


static void print_help(char *name) {
    fprintf(stderr, "Usage: %s [options]\n", name);
    fprintf(stderr, " -T or --tcti   Tcti device type\n");
    fprintf(stderr, " -r or --random Get 0x20 random bytes to stdout in hex\n");
    fprintf(stderr, " -s or --sign   Sign data from input or stdin and return signature to output\n");
    fprintf(stderr, " -c or --clear  Clear storage\n");
    fprintf(stderr, " -p or --pub    Get public key to output file or stdout\n");
    fprintf(stderr, " -o or --output Output file instead of stdout\n");
    fprintf(stderr, " -i or --input  Input file instead of stdin\n");
    fprintf(stderr, " -h or --help   Print this help\n");
}


int main(int argc, char *argv[]) {
    struct parg_state ps;
    int c, li;
    context ctx = {0};
    TPM2_RC rc = 0;
    char output[1024] = {0}, input[1024] = {0};
    enum CMD {
        CMD_RANDOM,
        CMD_SIGN,
        CMD_PUB,
        CMD_CLEAR,
        CMD_HELP,
        CMD_NIL
    } cmd = CMD_NIL;

    parg_init(&ps);

    while ((c = parg_getopt_long(&ps, argc, argv, "o:i:T:scprh", params_config, &li)) != -1) {
        switch (c) {
            case 'o':
                strncpy(output, ps.optarg, 1024);
                break;
            case 'i':
                strncpy(input, ps.optarg, 1024);
                break;
            case 'T':
                strncpy(ctx.device, ps.optarg, 1024);
                if(init_tpm_device(ps.optarg, &ctx) != TPM2_RC_SUCCESS) {
                    fprintf(stderr, "Invalid or unsupported tcti type '%s'\n", ps.optarg);
                    return 1;
                };
                break;
            case 'r':
                SET_CMD(cmd, CMD_RANDOM);
                break;
            case 's':
                SET_CMD(cmd, CMD_SIGN);
                break;
            case 'p':
                SET_CMD(cmd, CMD_PUB);
                break;
            case 'c':
                SET_CMD(cmd, CMD_CLEAR);
                break;
            case '?':
                fprintf(stderr, "Unknown argument or missing value for '%c'\n", ps.optopt);
                return 1;
            case 'h':
                break;
        }
    }
    switch(cmd) {
        case CMD_RANDOM:
            rc = demo_random(&ctx, output);
            break;
        case CMD_SIGN:
            rc = demo_sign(&ctx, input, output);
            break;
        case CMD_PUB:
            rc= demo_pub(&ctx, output);
            break;
        case CMD_CLEAR:
            rc = demo_clear(&ctx);
            break;
        default:
            print_help(argv[0]);
    }
    cleanup_tpm_device(&ctx);
    return rc;
}
