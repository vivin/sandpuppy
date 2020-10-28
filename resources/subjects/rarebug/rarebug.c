#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// This program has a rare bug.

#define WIDTH    8u

const int MIN_MESSAGE_TYPE = 1;
const int MAX_MESSAGE_TYPE = 20;

// If we get a sequence of four messages with types 9 4 11 3 in that order, it will trigger a bug.
const unsigned int MAGIC_SEQUENCE = (9u << (3u * WIDTH)) + (4u << (2u * WIDTH)) + (11u << (1u * WIDTH)) + (3u << (0u * WIDTH));
const char delimiter = ':';

unsigned int current_sequence = 0u;

int process_message(const char* message_type_str, const char* message) {
    char *endptr;
    errno = 0;

    long value = strtol(message_type_str, &endptr, 10);
    if (errno == ERANGE || *endptr != '\0' || message_type_str == endptr) {
        return -1;
    }

    if (value < MIN_MESSAGE_TYPE || value > MAX_MESSAGE_TYPE) {
        return -1;
    }

    int message_type = (int) value;
    current_sequence = (current_sequence << WIDTH) + message_type;
    if (current_sequence == MAGIC_SEQUENCE) {
        printf("You got the magic sequence!\n");
        char *buffer = malloc(5);
        strcpy(buffer, "overflow"); // heap buffer overflow when you get the magic sequence
    }

    printf ("Message type: %d, Message: %s\n\n", message_type, message);
    return 0;
}

int main(int argc, char* argv[]) {
    char *line = NULL;
    size_t bufsize;

    while (getline(&line, &bufsize, stdin)) {
        unsigned int size = strlen(line) - 1; // Ignore newline in size
        if (size == 0) {
            break;
        }

        const char *ptr = strchr(line, delimiter);
        if (ptr) {
            unsigned int index = ptr - line;
            if (index == size || index == size - 1) {
                printf ("Bad message format: empty message\n\n");
            } else {
                char *message_type_str = malloc(index + 1);
                memcpy(message_type_str, line, index);
                message_type_str[index] = '\0';

                char *message = malloc(size - index);
                memcpy(message, line + index + 1, (size - index) - 1); // ignore newline character at the end
                message[size - (index + 1)] = '\0';

                if (process_message(message_type_str, message) == -1) {
                    printf("Bad message size: %s\n\n", message_type_str);
                }

                free(message_type_str);
                free(message);
            }
        } else {
            printf("Bad message format: no delimiter\n\n");
        }
    }

    return 0;
}
