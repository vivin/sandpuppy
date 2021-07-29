#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <b64/cencode.h>
#include <b64/cdecode.h>

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

#define BUFFER_SIZE 255
#define EXIT_TEST_SKIP 77

#define vvdump_ignore __attribute__((annotate("vvdump_ignore")))

// Based on https://raw.githubusercontent.com/libb64/libb64/master/examples/c-example1.c

vvdump_ignore
__attribute__((no_sanitize("address")))
char* decode(const char* input, int* length) {
    /* set up a destination buffer large enough to hold the encoded data */
    char* output = (char*) malloc(BUFFER_SIZE);

    /* keep track of our decoded position */
    char* c = output;

    /* we need a decoder state */
    base64_decodestate s;

    /* initialise the decoder state */
    base64_init_decodestate(&s);

    /* decode the input data */
    *length = base64_decode_block(input, strlen(input), c, &s);
    return output;
}

vvdump_ignore
__attribute__((no_sanitize("address")))
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    unsigned char *rbuffer = NULL;
    uint32_t rlength;
    uint32_t rtotal = 0;
    TPM_RESULT res;
    unsigned char startup[] = {
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00
    };

    res = TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2);
    if (res != TPM_SUCCESS) {
        fprintf(stderr, "Error: TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2) failed\n");
        return 1;
    }

    res = TPMLIB_MainInit();
    if (res != TPM_SUCCESS) {
        fprintf(stderr, "Error: TPMLIB_MainInit() failed\n");
        return 1;
    }

    res = TPMLIB_Process(&rbuffer, &rlength, &rtotal, startup, sizeof(startup));
    if (res != TPM_SUCCESS) {
        fprintf(stderr, "Error: TPMLIB_Process(Startup) failed\n");
        return 1;
    }

    res = TPMLIB_Process(&rbuffer, &rlength, &rtotal, (unsigned char*)data, size);
    if (res != TPM_SUCCESS) {
        fprintf(stderr, "Error: TPMLIB_Process(fuzz-command) failed\n");
        return 1;
    }

    u_int16_t tag = ((u_int16_t)(rbuffer[0]) << 8) |
                    ((u_int16_t)(rbuffer[1]) << 0);

    u_int32_t response_size = ((u_int32_t)(rbuffer[2]) << 24) |
                              ((u_int32_t)(rbuffer[3]) << 16) |
                              ((u_int32_t)(rbuffer[4]) << 8) |
                              ((u_int32_t)(rbuffer[5]) << 0);

    u_int32_t response_code = ((u_int32_t)(rbuffer[6]) << 24) |
                              ((u_int32_t)(rbuffer[7]) << 16) |
                              ((u_int32_t)(rbuffer[8]) << 8) |
                              ((u_int32_t)(rbuffer[9]) << 0);

/*
    fprintf(stdout, "the tag is %d\n", tag);
    fprintf(stdout, "the size is %d\n", response_size);
    fprintf(stdout, "the response code is %d\n", response_code);

    for (int i = 0; i < rlength; i++) {
        printf("buffer[%d] = %02X\n", i, rbuffer[i]);
    }

    fprintf(stdout, "ok processed and response size is %d\n", rlength);
*/
    TPMLIB_Terminate();
    TPM_Free(rbuffer);

    return response_code == TPM_SUCCESS ? 0 : 1;
}

vvdump_ignore
__attribute__((no_sanitize("address")))
int main(int argc, char **argv)
{
    int exit_code = 0;

    char *name = argv[1];
    size_t len = 0;
    ssize_t read;
    FILE *f = fopen(name, "r");
    char *line;

    //fprintf(stdout, "%s...\n", name);
    if (f == NULL) {
        perror("fopen() failed");
        return 1;
    }

    while (exit_code == 0 && (read = getline(&line, &len, f)) != -1) {
        int command_length;
        char *command = decode(line, &command_length);
        exit_code = LLVMFuzzerTestOneInput((void *)command, (size_t) command_length);
    }

    fclose(f);
    if (line) {
        free(line);
    }

    return exit_code;
}
