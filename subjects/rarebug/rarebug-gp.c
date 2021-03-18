#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// This program has a rare bug.

#define WIDTH    8u
#define CUSTOM_CRASH 1
/*
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

struct base_struct {
    int num;
};

struct outer1_struct {
    struct base_struct base;
};

struct outer2_struct {
    struct outer1_struct outer1;
};

struct anon {
    int ab;
};

typedef int CMDCODE;

typedef struct _COMMAND_ {
    CMDCODE other;
} COMMAND;

typedef struct {
    struct {
        struct {
            int z;
        };
        int a;
    };
    int x;
} ANON_OUTER;

typedef union {
    struct {
        int o;
        int* m;
    };
    struct message_struct ms;
} UNION_STRUCT;

typedef struct {
    union {
        struct {
            int x;
            int y;
            int z;
        };
        int raw[3];
    };
} VEC3D; */

const int MIN_MESSAGE_TYPE = 1;
const int MAX_MESSAGE_TYPE = 8;
const int MAX_MESSAGE_SIZE = 140;

// If we get a sequence of four messages with types 8 4 7 3 in that order, it will trigger a bug.

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

int coolio(/*COMMAND* cmdptr, UNION_STRUCT* us, VEC3D* vec3d, */int val, /*int *ptr_val, int **ptr_ptr_val,*/ char *string, char **nextword) {
    /*cmdptr->other = val;
    us->o = val;
    *us->m = val;
    vec3d->x = val;
    vec3d->y = val;
    vec3d->z = val;*/

    val = 10;
    /*
    *ptr_val = 10;
    **ptr_ptr_val = 10;*/

    int arr[5] = {};
    int* arr_ptr = arr;

    *arr_ptr = 10;
    arr_ptr++;
    *arr_ptr = 20;
    arr_ptr++;
    *arr_ptr = 30;
    arr_ptr--;
    *arr_ptr = 40;
    *(++arr_ptr) = 50;
    *(arr_ptr++) = 60;

    //**ptr_ptr_val = 70;

    arr_ptr = arr_ptr + 5;
    *(arr_ptr) = 90;
    *(arr_ptr + 1) = val;

    //printf("%d", *ptr_val);
    return 0;
}

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

    int message_type = (int) value;

    printf ("%d:%s\n", message_type, message);
 /*
    const char *thecoolstring;
    int **foofoofoo;
    int *barbarbar;

    barbarbar = &message_type;
    foofoofoo = &barbarbar;

    **foofoofoo = message_type;

    struct message_struct ms = { 0, 0 };
    int *bleh = &ms.other;
    ms.mtype = bleh;

    *bleh = message_type;
    ms.other = message_type;
    *ms.mtype = message_type;

    COMMAND com = { 0 };

    COMMAND *cptr = &com;
    cptr->other = message_type;

    thecoolstring = message_type_str;

    struct message_struct msg = { 0, 0 };
    struct very_cool vcool = { msg };
    struct super_cool scool = { vcool };
    COMMAND cd = { 0 };

    *msg.mtype = message_type;
    *vcool.ms.mtype = message_type;
    *scool.vc.ms.mtype = message_type;

    cd.other = message_type;

    int *blah;
    *blah = message_type;

    UNION_STRUCT us = { 0, 0 };
    *us.m = message_type;

    us.ms.other = message_type;

    VEC3D vec3d;
    vec3d.x = 1;
    vec3d.y = 2;
    vec3d.z = 3;

    VEC3D *vec3dptr = &vec3d;
    vec3dptr->x = 1;
    vec3dptr->y = 2;
    vec3dptr->z = 3;

    struct outer2_struct outer2;
    outer2.outer1.base.num = 10;


    ANON_OUTER hello = {};
    hello.x = 0;
    hello.a = 0;

    struct anon an;
    an.ab = message_type;
*/
    int *mt_ptr = &message_type;
    int **mt_ptr_ptr = &mt_ptr;

    int *num;

    char *weirdo_string = NULL;
    coolio(/*cptr, &us, vec3dptr, */message_type, /*num, &num,*/ weirdo_string, &weirdo_string/*, mt_ptr, mt_ptr_ptr*/);
    weirdo_string = "hello";
    coolio(message_type, weirdo_string, &weirdo_string);

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

    unsigned int total_size = 0;
    int num_messages = 0;

    while (exit_code == 0 && getline(&line, &bufsize, stdin)) {
        unsigned int size = strlen(line) - 1; // Ignore newline in size
        total_size += size;

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
                } else {
                    num_messages++;
                }

                free(message_type_str);
                free(message);
            }
        } else {
            printf("Bad message format: no delimiter\n\n");
            exit_code = CUSTOM_CRASH;
        }
    }

    unsigned int the_full_size = total_size;

    return exit_code;
}
