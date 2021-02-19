#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "base64.h"

#include <libtpms/tpm_types.h>
#include <libtpms/tpm_library.h>
#include <libtpms/tpm_error.h>
#include <libtpms/tpm_memory.h>

#define EXIT_TEST_SKIP 77

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

int main(int argc, char **argv)
{
    int i;
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
        unsigned char *command = unbase64(line, read - 1, &command_length);
        exit_code = LLVMFuzzerTestOneInput((void *)command, (size_t) command_length);
    }

    fclose(f);
    if (line) {
        free(line);
    }

    return exit_code;
}

/*
int main(int argc, char **argv)
{
    int i;
    int exit_code;

    for (i = 1; i < argc; i++) {
        char *name = argv[i];
        ssize_t size;
        FILE *f = fopen(name, "rb");
        char *buf;

        fprintf(stdout, "%s...\n", name);
        if (f == NULL) {
            perror("fopen() failed");
            continue;
        }
        fseek(f, 0, SEEK_END);
        size = ftell(f);
        if (size < 0) {
            fclose(f);
            perror("ftell() failed");
            continue;
        }
        fseek(f, 0, SEEK_SET);
        buf = malloc(size + 1);
        if (fread(buf, 1, size, f) != (size_t)size) {
            fclose(f);
            perror("fread() failed");
            continue;
        }
        fclose(f);
        buf[size] = 0;

        exit_code = LLVMFuzzerTestOneInput((void *)buf, size);
        free(buf);
    }

    return exit_code;
}
*/
