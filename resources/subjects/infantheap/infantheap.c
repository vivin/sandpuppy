#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

/* this is my own babyheap and it is probably easier than babyheap so i am calling it infantheap  */

int CUSTOM_CRASH = 83;

int MAX_CHUNK_SIZE = 256;
int MAX_CHUNKS = 1000;

char *chunk_table[1000];
int max_used_table_index = -1;
int num_chunks = 0;

int free_index_stack[1000];
int num_free_indexes = 0;

bool index_allocated[1000] = { false };
bool index_filled[1000] = { false };

int alloc_chunk(int size) {
    char *chunk = malloc(size * sizeof(char));

    int chunk_index = -1;
    if (num_free_indexes > 0) {
        chunk_index = free_index_stack[-- num_free_indexes];
    } else {
        chunk_index = ++ max_used_table_index;
    }

    chunk_table[chunk_index] = chunk;
    index_allocated[chunk_index] = true;

    num_chunks ++;

    printf("\nChunk: %d (%p)\n\n", chunk_index, chunk);

    return 0;
}

int do_alloc_chunk() {
    if (num_chunks == MAX_CHUNKS) {
        printf("Maximum number of chunks (%d) allocated!", MAX_CHUNKS);
        return -1;
    }

    printf("Allocating chunk\n");
    int BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE];
    char *endptr = NULL;
    int size;

    printf("\nEnter size (max %d): ", MAX_CHUNK_SIZE);
    if (!fgets(buffer, BUFFER_SIZE, stdin)) {
        return -1;
    }

    if (strlen(buffer) == 0) {
        printf("\nBad size\n\n");
        return -1;
    }

    buffer[strlen(buffer) - 1] = 0; // remove \n

    errno = 0;
    size = strtol(buffer, &endptr, 10);
    if (errno != 0 || *endptr != 0 || size <= 0 || size > MAX_CHUNK_SIZE) {
        printf("\nBad size\n\n");
        return -1;
    }

    return alloc_chunk(size);
}

int fill_chunk(int chunk_index) {
    printf("Filling chunk\n");
    if (!index_allocated[chunk_index]) {
        printf("Chunk %d is not allocated.\n\n", chunk_index);
        return -1;
    }

    char buffer[MAX_CHUNK_SIZE];

    printf("Content: ");
    if(!fgets(buffer, MAX_CHUNK_SIZE, stdin)) {
        return -1;
    }

    if (strlen(buffer) == 0) {
        printf("\nBad content\n\n");
        return -1;
    }

    buffer[strlen(buffer) - 1] = 0; // remove \n

    //char* addr = chunk_table[chunk_index];
    //*addr = 'a';

    //printf("strcpy %s to %p\n", buffer, chunk_table[chunk_index]);
    strcpy(chunk_table[chunk_index], buffer);
    index_filled[chunk_index] = true;

    return 0;
}

int do_option(int (*option_function)(int)) {
    int BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE];
    char *endptr = NULL;
    int chunk_index;

    //printf("\n\n-- index used of chunk index %d = %s\n", chunk_index, index_allocated[chunk_index] ? "true" : "false");
    //printf("-- index allocated of chunk index %d = %s\n\n", chunk_index, index_filled[chunk_index] ? "true" : "false");

    //printf("Doing something with a chunk\n");

    printf("\nEnter chunk index: ");
    if (!fgets(buffer, BUFFER_SIZE, stdin)) {
        printf("No chunk index given\n");
        return -1;
    }

    if (strlen(buffer) == 0) {
        printf("\nInvalid chunk index\n\n");
        return -1;
    }

    buffer[strlen(buffer) - 1] = 0; // remove \n

    errno = 0;
    chunk_index = strtol(buffer, &endptr, 10);

    if (errno != 0 || *endptr != 0 || chunk_index < 0 || chunk_index >= MAX_CHUNKS) {
        printf("Invalid chunk index\n\n");
        return -1;
    }

    return (*option_function)(chunk_index);
}

int dump_chunk(int chunk_index) {
    printf("Dumping chunk\n");
    if (!index_allocated[chunk_index] || !index_filled[chunk_index]) {
        printf("Chunk %d is not allocated.\n\n", chunk_index);
        return -1;
    }

    if (!index_filled[chunk_index]) {
        printf("Chunk %d is not filled.\n\n", chunk_index);
        return -1;
    }

    printf("\nContent (%p): %s\n", chunk_table[chunk_index], chunk_table[chunk_index]);

    return 0;
}

int free_chunk(int chunk_index) {
    printf("Freeing chunk\n");
    if (!index_allocated[chunk_index]) {
        printf("Chunk %d is not allocated.\n\n", chunk_index);
        return -1;
    }

    free(chunk_table[chunk_index]);
    free_index_stack[num_free_indexes ++] = chunk_index;

    index_allocated[chunk_index] = false;
    index_filled[chunk_index] = false;

    num_chunks --;

    return 0;
}

int main(int argc, char* argv[]) {
    int BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE];

    int return_value;
    char option;
    int option_num;
    bool error = false;
    bool done = false;
    while (!done && !error) {
        printf("Options\n");
        printf("=======\n\n");

        printf("a) alloc\n");
        printf("l) fill\n");
        printf("d) dump\n");
        printf("f) free\n");
        printf("x) exit (anything else)\n\n");

        printf("Select an option: ");
        if (!fgets(buffer, BUFFER_SIZE, stdin)) {
            error = true;
            continue;
        }

        if (strlen(buffer) != 2) {
            error = true;
            break;
        }

        buffer[strlen(buffer) - 1] = 0; // remove \n
        option = buffer[0];

        switch(option) {
            case 'a':
                return_value = do_alloc_chunk();
                option_num = 1;
                break;

            case 'l':
                return_value = do_option(&fill_chunk);
                option_num = 3;
                break;

            case 'd':
                return_value = do_option(&dump_chunk);
                option_num = 5;
                break;

            case 'f':
                return_value = do_option(&free_chunk);
                option_num = 7;
                break;

            case 'x':
                option_num = 9;
                done = true;
                break;

            default:
                error = true;
                break;
        }

        error = error || (return_value != 0);
    }

    //return 0;
    //uncomment to treat any invalid input as crash
    return error ? CUSTOM_CRASH : 0;
}
