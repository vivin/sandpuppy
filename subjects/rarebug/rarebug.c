#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// This program has a rare bug.

#define WIDTH    8u
#define CUSTOM_CRASH 1

struct message_struct {
    int other;
    int* mtype;
};

struct very_cool {
    struct message_struct ms;
};

struct super_cool {
    struct very_cool vc;
};

typedef int CMDCODE;

typedef struct _COMMAND_ {
    CMDCODE other;
} COMMAND;

const int MIN_MESSAGE_TYPE = 1;
const int MAX_MESSAGE_TYPE = 8;
const int MAX_MESSAGE_SIZE = 140;

// If we get a sequence of four messages with types 9 4 11 3 in that order, it will trigger a bug.

const unsigned int TYPE_1 = 8u;
const unsigned int TYPE_2 = 4u;
const unsigned int TYPE_3 = 7u;
const unsigned int TYPE_4 = 3u;
const unsigned int MAGIC_SEQUENCE = (TYPE_1 << (3u * WIDTH)) +
                                    (TYPE_2 << (2u * WIDTH)) +
                                    (TYPE_3 << (1u * WIDTH)) +
                                    (TYPE_4 << (0u * WIDTH));

const char delimiter = ':';
unsigned int current_sequence = 0u;

int process_message(const char* message_type_str, const char* message) {
    if (strlen(message) > MAX_MESSAGE_SIZE) {
        return -1;
    }

    char *endptr;
    errno = 0;

    long value = strtol(message_type_str, &endptr, 10);
    if (errno == ERANGE || *endptr != '\0' || message_type_str == endptr) {
        return -1;
    }

    if (value < MIN_MESSAGE_TYPE || value > MAX_MESSAGE_TYPE) {
        return -1;
    }

    const char *thecoolstring;
    int **foofoofoo;
    int *barbarbar;

    int message_type = (int) value;

    barbarbar = &message_type;
    foofoofoo = &barbarbar;

    **foofoofoo = message_type;

    struct message_struct ms = { 0, 0 };
    int *bleh = &ms.other;
    ms.mtype = bleh;

    *bleh = message_type;
    ms.other = message_type;
    *ms.mtype = message_type;

    thecoolstring = message_type_str;
    /*
    struct message_struct msg = { 0, 0 };
    struct very_cool vcool = { msg };
    struct super_cool scool = { vcool };
    COMMAND cd = { 0 };

    msg.mtype = message_type;
    vcool.ms.mtype = message_type;
    scool.vc.ms.mtype = message_type;

    cd.other = message_type;

    int *blah;
    *blah = message_type; */

    current_sequence = (current_sequence << WIDTH) + message_type;
    printf("magic is: %d the current sequence is: %d\n", MAGIC_SEQUENCE, current_sequence);
    if (current_sequence == MAGIC_SEQUENCE) {
        printf("You got the magic sequence!\n");
        char *buffer = malloc(5);
        strcpy(buffer, "overflow"); // heap buffer overflow when you get the magic sequence
        free(buffer);
    }

    char mt_char;
    switch (message_type) {
        case 0:
            mt_char = 'a';
            break;

        case 1:
            mt_char = 'b';
            break;

        case 2:
            mt_char = 'c';
            break;

        case 3:
            mt_char = 'd';
            break;

        case 4:
            mt_char = 'e';
            break;

        case 5:
            mt_char = 'f';
            break;

        case 6:
            mt_char = 'g';
            break;

        case 7:
            mt_char = 'h';
            break;

        case 8:
            mt_char = 'i';
            break;

        default:
            mt_char = 'j';
    }

    printf ("Message type: %d%c, Message: %s\n\n", message_type, mt_char, message);
    return 0;
}

int main(int argc, char* argv[]) {
    char *line = NULL;
    size_t bufsize;
    int exit_code = 0;

    while (exit_code == 0 && getline(&line, &bufsize, stdin)) {
        unsigned int size = strlen(line) - 1; // Ignore newline in size
        if (size == 0) {
            break;
        }

        char *ptr = strchr(line, delimiter);
        if (ptr) {
            unsigned int index = ptr - line;
            if (index == size || index == size - 1) {
                printf ("Bad message format: empty message\n\n");
                exit_code = CUSTOM_CRASH;
            } else {
                char *message_type_str = malloc(index + 1);
                memcpy(message_type_str, line, index);
                message_type_str[index] = '\0';

                char *message = malloc(size - index);
                memcpy(message, line + index + 1, (size - index) - 1); // ignore newline character at the end
                message[size - (index + 1)] = '\0';

                if (process_message(message_type_str, message) == -1) {
                    printf("Bad message size: %s\n\n", message_type_str);
                    exit_code = CUSTOM_CRASH;
                }

                free(message_type_str);
                free(message);
            }
        } else {
            printf("Bad message format: no delimiter\n\n");
            exit_code = CUSTOM_CRASH;
        }
    }

    return exit_code;
}
