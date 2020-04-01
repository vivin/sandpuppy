#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/* this is my own babyheap and it is probably easier than babyheap so i am calling it infantheap  */

int MAX_CHUNK_SIZE = 256;
int MAX_CHUNKS = 1000;

char *chunk_table[1000];
int max_used_table_index = -1;

int free_index_stack[1000];
int num_free_indexes = 0;

bool index_allocated[1000] = { false };
bool index_filled[1000] = { false };

void alloc_chunk(int size) {
    char *chunk = malloc(size * sizeof(char));

    int chunk_index = -1;
    if (num_free_indexes > 0) {
        chunk_index = free_index_stack[-- num_free_indexes];
    } else {
        chunk_index = ++ max_used_table_index;
    }

    chunk_table[chunk_index] = chunk;
    index_allocated[chunk_index] = true;

    printf("\nChunk: %d (%p)\n\n", chunk_index, chunk);
}

void do_alloc_chunk() {
    printf("Allocating chunk\n");
    int BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE];
    int size;

    printf("\nEnter size (max %d): ", MAX_CHUNK_SIZE);
    if (!fgets(buffer, BUFFER_SIZE, stdin)) {
        return;
    }

    buffer[strlen(buffer) - 1] = 0; // remove \n
    size = atoi(buffer);

    if (size <= 0 || size > MAX_CHUNK_SIZE) {
        printf("\nBad size\n\n");
        return;
    }

    alloc_chunk(size);
}

void fill_chunk(int chunk_index) {
    printf("Filling chunk\n");
    if (!index_allocated[chunk_index]) {
        printf("Chunk %d is not allocated.\n\n", chunk_index);
        return;
    }

    char buffer[MAX_CHUNK_SIZE];

    printf("Content: ");
    if(!fgets(buffer, MAX_CHUNK_SIZE, stdin)) {
        return;
    }

    buffer[strlen(buffer) - 1] = 0; // remove \n

    char* addr = chunk_table[chunk_index];
    *addr = 'a';

    //printf("strcpy %s to %p\n", buffer, chunk_table[chunk_index]);
    strcpy(chunk_table[chunk_index], buffer);
    index_filled[chunk_index] = true;
}

void do_option(void (*option_function)(int)) {
    int BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE];
    int chunk_index;

    //printf("\n\n-- index used of chunk index %d = %s\n", chunk_index, index_allocated[chunk_index] ? "true" : "false");
    //printf("-- index allocated of chunk index %d = %s\n\n", chunk_index, index_filled[chunk_index] ? "true" : "false");

    printf("Doing something with a chunk\n");

    printf("\nEnter chunk index: ");
    if (!fgets(buffer, BUFFER_SIZE, stdin)) {
        printf("No chunk index given.\n");
        return;
    }

    buffer[strlen(buffer) - 1] = 0; // remove \n
    chunk_index = atoi(buffer);

    if (chunk_index < 0 || chunk_index >= MAX_CHUNKS) {
        printf("Invalid chunk index\n\n");
        return;
    }

    (*option_function)(chunk_index);
}

void dump_chunk(int chunk_index) {
    printf("Dumping chunk\n");
    if (!index_allocated[chunk_index] || !index_filled[chunk_index]) {
        printf("Chunk %d is not allocated.\n\n", chunk_index);
        return;
    }

    if (!index_filled[chunk_index]) {
        printf("Chunk %d is not filled.\n\n", chunk_index);
        return;
    }

    printf("\nContent (%p): %s\n", chunk_table[chunk_index], chunk_table[chunk_index]);
}

void free_chunk(int chunk_index) {
    printf("Freeing chunk\n");
    if (!index_allocated[chunk_index]) {
        printf("Chunk %d is not allocated.\n\n", chunk_index);
        return;
    }

    free(chunk_table[chunk_index]);
    free_index_stack[num_free_indexes ++] = chunk_index;

    index_allocated[chunk_index] = false;
    index_filled[chunk_index] = false;
}

int main(int argc, char* argv[]) {
    int BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE];

    char option;
    bool done = false;
    while (!done) {
        printf("Options\n");
        printf("=======\n\n");

        printf("a) alloc\n");
        printf("l) fill\n");
        printf("d) dump\n");
        printf("f) free\n");
        printf("x) exit (anything else)\n\n");

        printf("Select an option: ");
        if (!fgets(buffer, BUFFER_SIZE, stdin)) {
            continue;
        }

        if (strlen(buffer) != 2) {
            break;
        }

        buffer[strlen(buffer) - 1] = 0; // remove \n
        option = buffer[0];

        switch(option) {
            case 'a': do_alloc_chunk();
                break;

            case 'l': do_option(&fill_chunk);
                break;

            case 'd': do_option(&dump_chunk);
                break;

            case 'f': do_option(&free_chunk);
                break;

            default: done = true;
                break;

        }
    }

    printf("Exiting\n");
    return 0;
}
