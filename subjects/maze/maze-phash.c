#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

const int MAZE_ROWS = 16;
const int MAZE_COLUMNS = 32;

const char* maze[] = {
    "+-+---------+------------------+",
    "| |         |                  |",
    "| +------- -+ +-+ +------------+",
    "|             | | |            |",
    "| +-----------+ | | +----+ # # |",
    "| |           | | | +----+ | | |",
    "| +---------+ | | |        | | |",
    "|           | | | +------+ | | |",
    "| +---------+ | |       *| | | |",
    "| +---------+ | +--------+ | | |",
    "|           | |            | | |",
    "| #---------+ +----------# | # |",
    "|           | |            |   |",
    "| #---------+ +----------# +---+",
    "|                              |",
    "+------------------------------+"
};

uint64_t hash_int(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}

uint32_t hash_ints(uint32_t old, uint32_t val){
    uint64_t input = (((uint64_t)(old))<<32) | ((uint64_t)(val));
    return (uint32_t)(hash_int(input));
}

void print_maze(int player_row, int player_column) {
    for (int i = 0; i < MAZE_ROWS; i++) {
        for (int j = 0; j < MAZE_COLUMNS; j++) {
            if (i == player_row && j == player_column) {
                printf("o");
            } else {
                printf("%c", maze[i][j]);
            }
        }

        printf("\n");
    }
}

bool can_move_to(int row, int column) {
    return row >= 0 && row < MAZE_ROWS &&
           column >= 0 && column < MAZE_COLUMNS &&
           maze[row][column] == ' ' || maze[row][column] == '*';
}

bool found_target(const int* row, const int* column) {
    return maze[*row][*column] == '*';
}

int main(int argc, char* argv[]) {
    int player_row = 14;
    int player_col = 13;

    int delta_row;
    int delta_col;

    int moves = 0;

    int BUFFER_SIZE = 3;
    char buffer[BUFFER_SIZE];

    char option;
    bool error = false;
    bool done = false;
    while (!done && !error) {
        //print_maze(player_row, player_col);
        //printf("u, d, l, or r: ");
        if (fgets(buffer, BUFFER_SIZE, stdin) == NULL) {
            done = true;
            break;
        }

        if (strlen(buffer) != 2) {
            error = true;
            break;
        }

        buffer[strlen(buffer) - 1] = 0; // remove \n
        option = buffer[0];

        switch(option) {
            case 'u':
                delta_row = -1;
                delta_col = 0;
                break;

            case 'd':
                delta_row = 1;
                delta_col = 0;
                break;

            case 'l':
                delta_row = 0;
                delta_col = -1;
                break;

            case 'r':
                delta_row = 0;
                delta_col = 1;
                break;

            default:
                error = true;
                break;
        }

        if (!error) {
            moves++;
            if (can_move_to(player_row + delta_row, player_col + delta_col)) {
                player_row += delta_row;
                player_col += delta_col;

                printf("hash of %d and %d: %d\n", player_col, player_row, hash_ints(player_col, player_row));

                if (found_target(&player_row, &player_col)) {
                    printf("You found the treasure in %d moves!\n", moves);
                    done = true;
                }
            }

            printf("\n");
        }
    }

    return error ? 1 : 0;
}
