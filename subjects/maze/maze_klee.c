#include <stdio.h>
#include <string.h>
#include <stdbool.h>

const int MAZE_ROWS = 7;
const int MAZE_COLUMNS = 11;

const char* maze[] = {
    "+-+---+---+",
    "| |     |*|",
    "| | --+ | |",
    "| |   | | |",
    "| +-- | | |",
    "|     |   |",
    "+-----+---+"
};

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
    int player_row = 1;
    int player_col = 1;

    int delta_row;
    int delta_col;

    int moves = 0;

    int BUFFER_SIZE = 3;
    char buffer[BUFFER_SIZE];

    char last_option = '0';
    char option;
    bool error = false;
    bool done = false;
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
                printf("You smashed into a wall and died!\n");
                done = true;
            }

            printf("\n");
        }
    }

    return error ? 1 : 0;
}
