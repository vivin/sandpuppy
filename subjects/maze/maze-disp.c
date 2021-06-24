#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

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

void print_maze(char* filename, int player_row, int player_column) {
    printf("\033[2J\033[0;0H\n");
    printf("%s\n", filename);
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
    if (argc < 2) {
        printf("expected input filename");
        return 1;
    }

    char* filename = argv[1];

    int player_row = 14;
    int player_col = 13;

    int delta_row = 0;
    int delta_col = 0;

    int moves = 0;

    int BUFFER_SIZE = 3;
    char buffer[BUFFER_SIZE];

    char option;
    bool error = false;
    bool done = false;
    print_maze(filename, player_row, player_col);
    while (!done && !error) {
        //print_maze(player_row, player_col);
        printf("u, d, l, or r: ");
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

                if (found_target(&player_row, &player_col)) {
                    printf("You found the treasure in %d moves!\n", moves);
                    done = true;
                }
            } else {
                printf("You smashed into the wall!\n");
                done = true;
            }

            print_maze(filename, player_row, player_col);
            usleep(62500);
        }
    }

    return error ? 1 : 0;
}
