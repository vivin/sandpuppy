#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

int main(int argc, char* argv[]) {
    char *chunk1 = malloc(4 * sizeof(char));

    printf("made a chunk1. now we will copy\n");
    char buffer[10];

    printf("Content: ");
    if(!fgets(buffer, 10, stdin)) {
        return 0;
    }

    buffer[strlen(buffer) - 1] = 0; // remove \n

    strcpy(chunk1, buffer);

    int a[8] = {0};
    int b[8] = {0};
    b[1] = 1;
    for (int i = 0, x = 0, y = 0; i <= 8; ++i) // uh oh
    {
        // This loop looks like it only reads / writes inside b
        b[i] += x + y;
        y = x;
        x = b[i];
    }

    int c = a[0];

    char *chunk2 = malloc(4 * sizeof(char));

    printf("made a chunk2. now we will copy\n");
    char buffer2[10];

    printf("Content: ");
    if(!fgets(buffer2, 10, stdin)) {
        return 0;
    }

    buffer2[strlen(buffer2) - 1] = 0; // remove \n

    strcpy(chunk2, buffer2);

    int d[8] = {0};
    int e[8] = {0};
    e[1] = 1;
    for (int i = 0, x = 0, y = 0; i <= 8; ++i) // uh oh
    {
        // This loop looks like it only reads / writes inside b
        e[i] += x + y;
        y = x;
        x = e[i];
    }

    int f = d[0];

    char *chunk3 = malloc(4 * sizeof(char));

    printf("made a chunk3. now we will copy\n");
    char buffer3[10];

    printf("Content: ");
    if(!fgets(buffer3, 10, stdin)) {
        return 0;
    }

    buffer3[strlen(buffer3) - 1] = 0; // remove \n

    strcpy(chunk3, buffer3);
    //free(chunk1);
    //free(chunk3);
    // a has been altered, b[8] is actually a[0]
    //return a[0];
}