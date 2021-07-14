#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

const int MAZE_ROWS_1 = 16;
const int MAZE_COLUMNS_1 = 32;

const char* maze_1[] = {
    "+-+---------+------------------+",
    "| |         |                  |",
    "| +------- -+ +-+ +------------+",
    "|             | | |            |",
    "| +-----------+ | | +----+ | | |",
    "| |           | | | +----+ | | |",
    "| +---------+ | | |        | | |",
    "|           | | | +------+ | | |",
    "| +---------+ | |       *| | | |",
    "| +---------+ | +--------+ | | |",
    "|           | |            | | |",
    "| ----------+ +----------- | | |",
    "|           | |            |   |",
    "| ----------+ +----------- +---+",
    "|                              |",
    "+------------------------------+"
};

const int MAZE_ROWS_2 = 13;
const int MAZE_COLUMNS_2 = 17;

const char* maze_2[] = {
    "+-+-------------+",
    "| |             |",
    "| | +------ ----+",
    "|   |           |",
    "+---+-- --------+",
    "|               |",
    "+ +-------------+",
    "| |       |   |*|",
    "| | ----+ | | | |",
    "| |     |   |   |",
    "| +---- +-------+",
    "|               |",
    "+---------------+"
};

const int MAZE_ROWS_3 = 7;
const int MAZE_COLUMNS_3 = 11;

const char* maze_3[] = {
    "+-+---+---+",
    "| |     |*|",
    "| | --+ | |",
    "| |   | | |",
    "| +-- | | |",
    "|     |   |",
    "+-----+---+"
};

const char* target_name = NULL;
const char* pod_name = NULL;
const char* filename = NULL;

int MAZE_ROWS = 0;
int MAZE_COLUMNS = 0;
const char** maze = NULL;
const char* maze_name = NULL;

void print_maze(int player_row, int player_column) {
    printf("\033[0;0H");
    printf("Target    : %s\n", target_name);
    printf("Pod       : %s\n", pod_name);
    printf("Maze      : %s\n", maze_name);
    printf("Input file: %s\n\n", filename);

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
    if (argc < 5) {
        printf("Syntax: %s <target-name> <pod-name> <input-filename> <maze-type:1|2|3>\n", argv[0]);
        return 1;
    }

    target_name = argv[1];
    pod_name = argv[2];
    filename = argv[3];

    int player_row;
    int player_col;

    char *p;
    int maze_type = (int) strtol(argv[4], &p, 10);
    if (maze_type == 1) {
        MAZE_ROWS = MAZE_ROWS_1;
        MAZE_COLUMNS = MAZE_COLUMNS_1;
        maze = maze_1;
        maze_name = "maze";

        player_row = 14;
        player_col = 13;
    } else if (maze_type == 2) {
        MAZE_ROWS = MAZE_ROWS_2;
        MAZE_COLUMNS = MAZE_COLUMNS_2;
        maze = maze_2;
        maze_name = "maze_ijon";

        player_row = 1;
        player_col = 1;
    } else if (maze_type == 3) {
        MAZE_ROWS = MAZE_ROWS_3;
        MAZE_COLUMNS = MAZE_COLUMNS_3;
        maze = maze_3;
        maze_name = "maze_klee";

        player_row = 1;
        player_col = 1;
    } else {
        printf("Unknown maze type %d\n", maze_type);
        return 1;
    }

    printf("\033[2J\033[0;0H");

    int delta_row;
    int delta_col;

    int moves = 0;

    int BUFFER_SIZE = 3;
    char buffer[BUFFER_SIZE];

    char last_option = '0';
    char option;
    bool error = false;
    bool done = false;
    print_maze(player_row, player_col);
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
                if (last_option == 'd') {
                    printf("No backtracking allowed!\n");
                    done = true;
                    break;
                }
                delta_row = -1;
                delta_col = 0;
                break;

            case 'd':
                if (last_option == 'u') {
                    printf("No backtracking allowed!\n");
                    done = true;
                    break;
                }
                delta_row = 1;
                delta_col = 0;
                break;

            case 'l':
                if (last_option == 'r') {
                    printf("No backtracking allowed!\n");
                    done = true;
                    break;
                }
                delta_row = 0;
                delta_col = -1;
                break;

            case 'r':
                if (last_option == 'l') {
                    printf("No backtracking allowed!\n");
                    done = true;
                    break;
                }
                delta_row = 0;
                delta_col = 1;
                break;

            default:
                error = true;
                break;
        }

        if (!error && !done) {
            last_option = option;
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

            print_maze(player_row, player_col);
            usleep(31250);
        }
    }

    return error ? 1 : 0;
}
