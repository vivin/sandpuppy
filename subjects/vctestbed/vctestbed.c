//
// Created by vivin on 7/12/21.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BUFFER_SIZE    512
#define MIN_INPUT_SIZE 31
#define NUM_OPS        9
#define MAX_VALUES     128

#define STATIC_POS_COUNTER_VAR_NUM                    0
#define STATIC_NEG_COUNTER_VAR_NUM                    1
#define DYNAMIC_POS_COUNTER_VAR_NUM_AND_LIMIT         2
#define DYNAMIC_NEG_COUNTER_VAR_NUM_AND_LIMIT         3
#define VARYING_STATIC_POS_COUNTER_VAR_NUM            4
#define VARYING_STATIC_NEG_COUNTER_VAR_NUM            5
#define VARYING_DYNAMIC_POS_COUNTER_VAR_NUM_AND_LIMIT 6
#define VARYING_DYNAMIC_NEG_COUNTER_VAR_NUM_AND_LIMIT 7
#define ENUM_VAR_AND_VALUES                           8

#define VAR_NUM 0
#define LIMIT   1

#define ENUM_VAR_NUM      0
#define ENUM_VAR_MOD_TYPE 1
#define VALUES            2

#define ENUM_VAR_SINGLE_MOD 's'
#define ENUM_VAR_MULTI_MOD  'm'

#define vvdump_ignore __attribute__((annotate("vvdump_ignore")))

void fn_static_pos_counter_1() {
    for (int static_pos_counter_1 = 1; static_pos_counter_1 <= 10; static_pos_counter_1 ++) {
        //printf("static_pos_counter_1: %d\n", static_pos_counter_1);
    }
}

void fn_static_pos_counter_2() {
    for (int static_pos_counter_2 = 1; static_pos_counter_2 <= 20; static_pos_counter_2 ++) {
        //printf("static_pos_counter_2: %d\n", static_pos_counter_2);
    }
}

void fn_static_pos_counter_3() {
    for (int static_pos_counter_3 = 1; static_pos_counter_3 <= 30; static_pos_counter_3 ++) {
        //printf("static_pos_counter_3: %d\n", static_pos_counter_3);
    }
}

void fn_static_pos_counter_4() {
    for (int static_pos_counter_4 = 1; static_pos_counter_4 <= 40; static_pos_counter_4 ++) {
        //printf("static_pos_counter_4: %d\n", static_pos_counter_4);
    }
}

void fn_static_pos_counter_5() {
    for (int static_pos_counter_5 = 1; static_pos_counter_5 <= 50; static_pos_counter_5 ++) {
        //printf("static_pos_counter_5: %d\n", static_pos_counter_5);
    }
}

void fn_static_neg_counter_1() {
    for (int static_neg_counter_1 = 10; static_neg_counter_1 >= 1; static_neg_counter_1 --) {
        //printf("static_neg_counter_1: %d\n", static_neg_counter_1);
    }
}

void fn_static_neg_counter_2() {
    for (int static_neg_counter_2 = 20; static_neg_counter_2 >= 1; static_neg_counter_2 --) {
        //printf("static_neg_counter_2: %d\n", static_neg_counter_2);
    }
}

void fn_static_neg_counter_3() {
    for (int static_neg_counter_3 = 30; static_neg_counter_3 >= 1; static_neg_counter_3 --) {
        //printf("static_neg_counter_3: %d\n", static_neg_counter_3);
    }
}

void fn_static_neg_counter_4() {
    for (int static_neg_counter_4 = 40; static_neg_counter_4 >= 1; static_neg_counter_4 --) {
        //printf("static_neg_counter_4: %d\n", static_neg_counter_4);
    }
}

void fn_static_neg_counter_5() {
    for (int static_neg_counter_5 = 50; static_neg_counter_5 >= 1; static_neg_counter_5 --) {
        //printf("static_neg_counter_5: %d\n", static_neg_counter_5);
    }
}

void fn_dynamic_pos_counter_1(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_pos_counter_1 = 1; dynamic_pos_counter_1 <= limit; dynamic_pos_counter_1 ++) {
        //printf("dynamic_pos_counter_1: %d\n", dynamic_pos_counter_1);
    }
}

void fn_dynamic_pos_counter_2(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_pos_counter_2 = 1; dynamic_pos_counter_2 <= limit; dynamic_pos_counter_2 ++) {
        //printf("dynamic_pos_counter_2: %d\n", dynamic_pos_counter_2);
    }
}

void fn_dynamic_pos_counter_3(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_pos_counter_3 = 1; dynamic_pos_counter_3 <= limit; dynamic_pos_counter_3 ++) {
        //printf("dynamic_pos_counter_3: %d\n", dynamic_pos_counter_3);
    }
}

void fn_dynamic_pos_counter_4(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_pos_counter_4 = 1; dynamic_pos_counter_4 <= limit; dynamic_pos_counter_4 ++) {
        //printf("dynamic_pos_counter_4: %d\n", dynamic_pos_counter_4);
    }
}

void fn_dynamic_pos_counter_5(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_pos_counter_5 = 1; dynamic_pos_counter_5 <= limit; dynamic_pos_counter_5 ++) {
        //printf("dynamic_pos_counter_5: %d\n", dynamic_pos_counter_5);
    }
}

void fn_dynamic_neg_counter_1(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_neg_counter_1 = limit; dynamic_neg_counter_1 >= 1; dynamic_neg_counter_1 --) {
        //printf("dynamic_neg_counter_1: %d\n", dynamic_neg_counter_1);
    }
}

void fn_dynamic_neg_counter_2(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_neg_counter_2 = limit; dynamic_neg_counter_2 >= 1; dynamic_neg_counter_2 --) {
        //printf("dynamic_neg_counter_2: %d\n", dynamic_neg_counter_2);
    }
}

void fn_dynamic_neg_counter_3(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_neg_counter_3 = limit; dynamic_neg_counter_3 >= 1; dynamic_neg_counter_3 --) {
        //printf("dynamic_neg_counter_3: %d\n", dynamic_neg_counter_3);
    }
}

void fn_dynamic_neg_counter_4(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_neg_counter_4 = limit; dynamic_neg_counter_4 >= 1; dynamic_neg_counter_4 --) {
        //printf("dynamic_neg_counter_4: %d\n", dynamic_neg_counter_4);
    }
}

void fn_dynamic_neg_counter_5(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    for (int dynamic_neg_counter_5 = limit; dynamic_neg_counter_5 >= 1; dynamic_neg_counter_5 --) {
        //printf("dynamic_neg_counter_5: %d\n", dynamic_neg_counter_5);
    }
}

void fn_varying_static_pos_counter_1() {
    int step = 0;
    for (int varying_static_pos_counter_1 = 1; varying_static_pos_counter_1 <= 25; varying_static_pos_counter_1 += step) {
        //printf("varying_static_pos_counter_1: %d\n", varying_static_pos_counter_1);
        step++;
    }
}

void fn_varying_static_pos_counter_2() {
    int step = 0;
    for (int varying_static_pos_counter_2 = 1; varying_static_pos_counter_2 <= 50; varying_static_pos_counter_2 += step) {
        //printf("varying_static_pos_counter_2: %d\n", varying_static_pos_counter_2);
        step++;
    }
}

void fn_varying_static_pos_counter_3() {
    int step = 0;
    for (int varying_static_pos_counter_3 = 1; varying_static_pos_counter_3 <= 75; varying_static_pos_counter_3 += step) {
        //printf("varying_static_pos_counter_3: %d\n", varying_static_pos_counter_3);
        step++;
    }
}

void fn_varying_static_pos_counter_4() {
    int step = 0;
    for (int varying_static_pos_counter_4 = 1; varying_static_pos_counter_4 <= 100; varying_static_pos_counter_4 += step) {
        //printf("varying_static_pos_counter_4: %d\n", varying_static_pos_counter_4);
        step++;
    }
}

void fn_varying_static_pos_counter_5() {
    int step = 0;
    for (int varying_static_pos_counter_5 = 1; varying_static_pos_counter_5 <= 125; varying_static_pos_counter_5 += step) {
        //printf("varying_static_pos_counter_5: %d\n", varying_static_pos_counter_5);
        step++;
    }
}

void fn_varying_static_neg_counter_1() {
    int step = 0;
    for (int varying_static_neg_counter_1 = 25; varying_static_neg_counter_1 >= 1; varying_static_neg_counter_1 -= step) {
        //printf("varying_static_neg_counter_1: %d\n", varying_static_neg_counter_1);
        step++;
    }
}

void fn_varying_static_neg_counter_2() {
    int step = 0;
    for (int varying_static_neg_counter_2 = 50; varying_static_neg_counter_2 >= 1; varying_static_neg_counter_2 -= step) {
        //printf("varying_static_neg_counter_2: %d\n", varying_static_neg_counter_2);
        step++;
    }
}

void fn_varying_static_neg_counter_3() {
    int step = 0;
    for (int varying_static_neg_counter_3 = 75; varying_static_neg_counter_3 >= 1; varying_static_neg_counter_3 -= step) {
        //printf("varying_static_neg_counter_3: %d\n", varying_static_neg_counter_3);
        step++;
    }
}

void fn_varying_static_neg_counter_4() {
    int step = 0;
    for (int varying_static_neg_counter_4 = 100; varying_static_neg_counter_4 >= 1; varying_static_neg_counter_4 -= step) {
        //printf("varying_static_neg_counter_4: %d\n", varying_static_neg_counter_4);
        step++;
    }
}

void fn_varying_static_neg_counter_5() {
    int step = 0;
    for (int varying_static_neg_counter_5 = 125; varying_static_neg_counter_5 >= 1; varying_static_neg_counter_5 -= step) {
        //printf("varying_static_neg_counter_5: %d\n", varying_static_neg_counter_5);
        step++;
    }
}

void fn_varying_dynamic_pos_counter_1(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_pos_counter_1 = 1; varying_dynamic_pos_counter_1 <= limit; varying_dynamic_pos_counter_1 += step) {
        //printf("varying_dynamic_pos_counter_1: %d\n", varying_dynamic_pos_counter_1);
        step++;
    }
}

void fn_varying_dynamic_pos_counter_2(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_pos_counter_2 = 1; varying_dynamic_pos_counter_2 <= limit; varying_dynamic_pos_counter_2 += step) {
        //printf("varying_dynamic_pos_counter_2: %d\n", varying_dynamic_pos_counter_2);
        step++;
    }
}

void fn_varying_dynamic_pos_counter_3(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_pos_counter_3 = 1; varying_dynamic_pos_counter_3 <= limit; varying_dynamic_pos_counter_3 += step) {
        //printf("varying_dynamic_pos_counter_3: %d\n", varying_dynamic_pos_counter_3);
        step++;
    }
}

void fn_varying_dynamic_pos_counter_4(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_pos_counter_4 = 1; varying_dynamic_pos_counter_4 <= limit; varying_dynamic_pos_counter_4 += step) {
        //printf("varying_dynamic_pos_counter_4: %d\n", varying_dynamic_pos_counter_4);
        step++;
    }
}

void fn_varying_dynamic_pos_counter_5(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_pos_counter_5 = 1; varying_dynamic_pos_counter_5 <= limit; varying_dynamic_pos_counter_5 += step) {
        //printf("varying_dynamic_pos_counter_5: %d\n", varying_dynamic_pos_counter_5);
        step++;
    }
}

void fn_varying_dynamic_neg_counter_1(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_neg_counter_1 = limit; varying_dynamic_neg_counter_1 >= 1; varying_dynamic_neg_counter_1 -= step) {
        //printf("varying_dynamic_neg_counter_1: %d\n", varying_dynamic_neg_counter_1);
        step++;
    }
}

void fn_varying_dynamic_neg_counter_2(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_neg_counter_2 = limit; varying_dynamic_neg_counter_2 >= 1; varying_dynamic_neg_counter_2 -= step) {
        //printf("varying_dynamic_neg_counter_2: %d\n", varying_dynamic_neg_counter_2);
        step++;
    }
}

void fn_varying_dynamic_neg_counter_3(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_neg_counter_3 = limit; varying_dynamic_neg_counter_3 >= 1; varying_dynamic_neg_counter_3 -= step) {
        //printf("varying_dynamic_neg_counter_3: %d\n", varying_dynamic_neg_counter_3);
        step++;
    }
}

void fn_varying_dynamic_neg_counter_4(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_neg_counter_4 = limit; varying_dynamic_neg_counter_4 >= 1; varying_dynamic_neg_counter_4 -= step) {
        //printf("varying_dynamic_neg_counter_4: %d\n", varying_dynamic_neg_counter_4);
        step++;
    }
}

void fn_varying_dynamic_neg_counter_5(int limit) {
    if (limit < 0 || limit >= 1000) {
        exit(1);
    }

    int step = 0;
    for (int varying_dynamic_neg_counter_5 = limit; varying_dynamic_neg_counter_5 >= 1; varying_dynamic_neg_counter_5 -= step) {
        //printf("varying_dynamic_neg_counter_5: %d\n", varying_dynamic_neg_counter_5);
        step++;
    }
}

void fn_enum_var_single_mod_1(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_single_mod_1 = value;
    //printf("enum_var_single_mod_1: %d\n", enum_var_single_mod_1);
}

void fn_enum_var_single_mod_2(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_single_mod_2 = value;
    //printf("enum_var_single_mod_2: %d\n", enum_var_single_mod_2);
}

void fn_enum_var_single_mod_3(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_single_mod_3 = value;
    //printf("enum_var_single_mod_3: %d\n", enum_var_single_mod_3);
}

void fn_enum_var_single_mod_4(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_single_mod_4 = value;
    //printf("enum_var_single_mod_4: %d\n", enum_var_single_mod_4);
}

void fn_enum_var_single_mod_5(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_single_mod_5 = value;
    //printf("enum_var_single_mod_5: %d\n", enum_var_single_mod_5);
}

void fn_enum_var_multi_mod_1(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_multi_mod_1;
    if (value == 0) {
        enum_var_multi_mod_1 = value + 0;
    } else if (value == 1) {
        enum_var_multi_mod_1 = value + 1;
    } else if (value == 2) {
        enum_var_multi_mod_1 = value + 2;
    } else if (value == 3) {
        enum_var_multi_mod_1 = value + 3;
    } else if (value == 4) {
        enum_var_multi_mod_1 = value + 4;
    } else if (value == 5) {
        enum_var_multi_mod_1 = value + 5;
    } else if (value == 6) {
        enum_var_multi_mod_1 = value + 6;
    } else if (value == 7) {
        enum_var_multi_mod_1 = value + 7;
    }

    //printf("enum_var_multi_mod_1: %d\n", enum_var_multi_mod_1);
}

void fn_enum_var_multi_mod_2(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_multi_mod_2;
    if (value == 0) {
        enum_var_multi_mod_2 = value + 0;
    } else if (value == 1) {
        enum_var_multi_mod_2 = value + 1;
    } else if (value == 2) {
        enum_var_multi_mod_2 = value + 2;
    } else if (value == 3) {
        enum_var_multi_mod_2 = value + 3;
    } else if (value == 4) {
        enum_var_multi_mod_2 = value + 4;
    } else if (value == 5) {
        enum_var_multi_mod_2 = value + 5;
    } else if (value == 6) {
        enum_var_multi_mod_2 = value + 6;
    } else if (value == 7) {
        enum_var_multi_mod_2 = value + 7;
    }

    //printf("enum_var_multi_mod_2: %d\n", enum_var_multi_mod_2);
}

void fn_enum_var_multi_mod_3(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_multi_mod_3;
    if (value == 0) {
        enum_var_multi_mod_3 = value + 0;
    } else if (value == 1) {
        enum_var_multi_mod_3 = value + 1;
    } else if (value == 2) {
        enum_var_multi_mod_3 = value + 2;
    } else if (value == 3) {
        enum_var_multi_mod_3 = value + 3;
    } else if (value == 4) {
        enum_var_multi_mod_3 = value + 4;
    } else if (value == 5) {
        enum_var_multi_mod_3 = value + 5;
    } else if (value == 6) {
        enum_var_multi_mod_3 = value + 6;
    } else if (value == 7) {
        enum_var_multi_mod_3 = value + 7;
    }

    //printf("enum_var_multi_mod_3: %d\n", enum_var_multi_mod_3);
}

void fn_enum_var_multi_mod_4(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_multi_mod_4;
    if (value == 0) {
        enum_var_multi_mod_4 = value + 0;
    } else if (value == 1) {
        enum_var_multi_mod_4 = value + 1;
    } else if (value == 2) {
        enum_var_multi_mod_4 = value + 2;
    } else if (value == 3) {
        enum_var_multi_mod_4 = value + 3;
    } else if (value == 4) {
        enum_var_multi_mod_4 = value + 4;
    } else if (value == 5) {
        enum_var_multi_mod_4 = value + 5;
    } else if (value == 6) {
        enum_var_multi_mod_4 = value + 6;
    } else if (value == 7) {
        enum_var_multi_mod_4 = value + 7;
    }

    //printf("enum_var_multi_mod_4: %d\n", enum_var_multi_mod_4);
}

void fn_enum_var_multi_mod_5(int value) {
    if (value < 0 || value >= 8) {
        exit(1);
    }

    int enum_var_multi_mod_5;
    if (value == 0) {
        enum_var_multi_mod_5 = value + 0;
    } else if (value == 1) {
        enum_var_multi_mod_5 = value + 1;
    } else if (value == 2) {
        enum_var_multi_mod_5 = value + 2;
    } else if (value == 3) {
        enum_var_multi_mod_5 = value + 3;
    } else if (value == 4) {
        enum_var_multi_mod_5 = value + 4;
    } else if (value == 5) {
        enum_var_multi_mod_5 = value + 5;
    } else if (value == 6) {
        enum_var_multi_mod_5 = value + 6;
    } else if (value == 7) {
        enum_var_multi_mod_5 = value + 7;
    }

    //printf("enum_var_multi_mod_5: %d\n", enum_var_multi_mod_5);
}

vvdump_ignore
int parse_int(const char *str) {
    char *endptr = NULL;
    int var_num = strtol(str, &endptr, 10);
    if (errno == ERANGE || (*endptr != '\0' && *endptr != '\n' && *endptr != '\r') || str == endptr) {
        printf("Bad integer string to parse: %s\n", str);
        exit(1);
    }

    return var_num;
}

vvdump_ignore
void cleanup(char **tokens, int num_tokens) {
    for (int i = 0; i < num_tokens; i++) {
        free(tokens[i]);
    }
}

vvdump_ignore
int tokenize(char *buffer, char **tokens, char delim, int limit) {
    int num_tokens = 0;
    int i = 0;
    int start = 0;
    int delim_pos = 0;
    while (buffer[i] != '\0') {
        if (num_tokens == limit) {
            printf("Extra tokens after limit (%d)\n", limit);
            free(buffer);
            cleanup(tokens, num_tokens);

            exit(1);
        }

        if (buffer[i] == delim || buffer[i + 1] == '\0') {
            delim_pos = buffer[i + 1] == '\0' ? i + 1 : i;

            char *token = malloc(delim_pos - start + 1);
            for (int j = start; j < delim_pos; j++) {
                token[j - start] = buffer[j];
            }

            token[delim_pos - start] = '\0';
            tokens[num_tokens++] = token;

            start = delim_pos + 1;
        }

        i++;
    }

    return num_tokens;
}

int main(int argc, char* argv[]) {
    char *buffer;
    size_t buffer_size = BUFFER_SIZE;
    size_t num_read;

    char *ops[NUM_OPS];
    char *var_num_and_limit[2];
    char *enum_var_and_values[3];

    int num_tokens;

    int var_num;
    int limit;

    char enum_mod_type;
    char *values[MAX_VALUES];

    int num_ops = 0;

    buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));
    if (buffer == NULL) {
        perror("Unable to allocate buffer");
        exit(1);
    }

    num_read = getline(&buffer, &buffer_size, stdin);
    if (num_read < MIN_INPUT_SIZE) {
        printf("Not enough input (%zu)\n", num_read);
        free(buffer);

        exit(1);
    }

    printf("strlen(buffer) = %lu; num_read = %lu\nstr = %s\n", strlen(buffer), num_read, buffer);

    int total_ops = tokenize(buffer, ops, ':', NUM_OPS);
    if (total_ops < NUM_OPS) {
        printf("Not enough ops (%d)\n", total_ops);
        free(buffer);
        cleanup(ops, total_ops);

        exit(1);
    }

    // static_pos_counter
    var_num = parse_int(ops[STATIC_POS_COUNTER_VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad variable number (%d)\n", var_num);
        free(buffer);
        cleanup(ops, total_ops);

        exit(1);
    }

    switch (var_num) {
        case 1:
            fn_static_pos_counter_1();
            break;

        case 2:
            fn_static_pos_counter_2();
            break;

        case 3:
            fn_static_pos_counter_3();
            break;

        case 4:
            fn_static_pos_counter_4();
            break;

        case 5:
            fn_static_pos_counter_5();
            break;

        default:
            free(buffer);
            cleanup(ops, total_ops);
            exit(1);
    }

    num_ops++;

    // static_neg_counter
    var_num = parse_int(ops[STATIC_NEG_COUNTER_VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad variable number (%d)\n", var_num);
        free(buffer);
        cleanup(ops, total_ops);

        exit(1);
    }

    switch (var_num) {
        case 1:
            fn_static_neg_counter_1();
            break;

        case 2:
            fn_static_neg_counter_2();
            break;

        case 3:
            fn_static_neg_counter_3();
            break;

        case 4:
            fn_static_neg_counter_4();
            break;

        case 5:
            fn_static_neg_counter_5();
            break;

        default:
            free(buffer);
            cleanup(ops, total_ops);
            exit(1);
    }

    num_ops++;

    // dynamic_pos_counter
    num_tokens = tokenize(ops[DYNAMIC_POS_COUNTER_VAR_NUM_AND_LIMIT], var_num_and_limit, ';', 2);
    if (num_tokens < 2) {
        printf("Not enough tokens (%d)\n", num_tokens);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    var_num = parse_int(var_num_and_limit[VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad variable number (%d)\n", var_num);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    limit = parse_int(var_num_and_limit[LIMIT]);
    if (limit <= 0) {
        printf("Bad limit (%d)\n", limit);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    cleanup(var_num_and_limit, num_tokens);

    switch (var_num) {
        case 1:
            fn_dynamic_pos_counter_1(limit);
            break;

        case 2:
            fn_dynamic_pos_counter_2(limit);
            break;

        case 3:
            fn_dynamic_pos_counter_3(limit);
            break;

        case 4:
            fn_dynamic_pos_counter_4(limit);
            break;

        case 5:
            fn_dynamic_pos_counter_5(limit);
            break;

        default:
            free(buffer);
            cleanup(ops, total_ops);
            exit(1);
    }

    num_ops++;

    // dynamic_neg_counter
    num_tokens = tokenize(ops[DYNAMIC_NEG_COUNTER_VAR_NUM_AND_LIMIT], var_num_and_limit, ';', 2);
    if (num_tokens < 2) {
        printf("Not enough tokens (%d)\n", num_tokens);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    var_num = parse_int(var_num_and_limit[VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad variable number (%d)\n", var_num);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    limit = parse_int(var_num_and_limit[LIMIT]);
    if (limit <= 0) {
        printf("Bad limit (%d)\n", limit);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    cleanup(var_num_and_limit, num_tokens);

    switch (var_num) {
        case 1:
            fn_dynamic_neg_counter_1(limit);
            break;

        case 2:
            fn_dynamic_neg_counter_2(limit);
            break;

        case 3:
            fn_dynamic_neg_counter_3(limit);
            break;

        case 4:
            fn_dynamic_neg_counter_4(limit);
            break;

        case 5:
            fn_dynamic_neg_counter_5(limit);
            break;

        default:
            free(buffer);
            cleanup(ops, total_ops);
            exit(1);
    }

    num_ops++;

    // varying_static_pos_counter
    var_num = parse_int(ops[VARYING_STATIC_POS_COUNTER_VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad variable number (%d)\n", var_num);
        free(buffer);

        exit(1);
    }

    switch (var_num) {
        case 1:
            fn_varying_static_pos_counter_1();
            break;

        case 2:
            fn_varying_static_pos_counter_2();
            break;

        case 3:
            fn_varying_static_pos_counter_3();
            break;

        case 4:
            fn_varying_static_pos_counter_4();
            break;

        case 5:
            fn_varying_static_pos_counter_5();
            break;

        default:
            return 1;
    }

    num_ops++;

    // varying_static_neg_counter
    var_num = parse_int(ops[VARYING_STATIC_NEG_COUNTER_VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad variable number (%d)\n", var_num);
        free(buffer);

        exit(1);
    }

    switch (var_num) {
        case 1:
            fn_varying_static_neg_counter_1();
            break;

        case 2:
            fn_varying_static_neg_counter_2();
            break;

        case 3:
            fn_varying_static_neg_counter_3();
            break;

        case 4:
            fn_varying_static_neg_counter_4();
            break;

        case 5:
            fn_varying_static_neg_counter_5();
            break;

        default:
            return 1;
    }

    num_ops++;

    // varying_dynamic_pos_counter
    num_tokens = tokenize(ops[VARYING_DYNAMIC_POS_COUNTER_VAR_NUM_AND_LIMIT], var_num_and_limit, ';', 2);
    if (num_tokens < 2) {
        printf("Not enough tokens (%d)\n", num_tokens);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    var_num = parse_int(var_num_and_limit[VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad variable number (%d)\n", var_num);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    limit = parse_int(var_num_and_limit[LIMIT]);
    if (limit <= 0) {
        printf("Bad limit (%d)\n", limit);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    cleanup(var_num_and_limit, num_tokens);

    switch (var_num) {
        case 1:
            fn_varying_dynamic_pos_counter_1(limit);
            break;

        case 2:
            fn_varying_dynamic_pos_counter_2(limit);
            break;

        case 3:
            fn_varying_dynamic_pos_counter_3(limit);
            break;

        case 4:
            fn_varying_dynamic_pos_counter_4(limit);
            break;

        case 5:
            fn_varying_dynamic_pos_counter_5(limit);
            break;

        default:
            free(buffer);
            cleanup(ops, total_ops);
            exit(1);
    }

    num_ops++;

    // varying_dynamic_neg_counter
    num_tokens = tokenize(ops[VARYING_DYNAMIC_NEG_COUNTER_VAR_NUM_AND_LIMIT], var_num_and_limit, ';', 2);
    if (num_tokens < 2) {
        printf("Not enough tokens (%d)\n", num_tokens);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    var_num = parse_int(var_num_and_limit[VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad variable number (%d)\n", var_num);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    limit = parse_int(var_num_and_limit[LIMIT]);
    if (limit <= 0) {
        printf("Bad limit (%d)\n", limit);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(var_num_and_limit, num_tokens);

        exit(1);
    }

    cleanup(var_num_and_limit, num_tokens);

    switch (var_num) {
        case 1:
            fn_varying_dynamic_neg_counter_1(limit);
            break;

        case 2:
            fn_varying_dynamic_neg_counter_2(limit);
            break;

        case 3:
            fn_varying_dynamic_neg_counter_3(limit);
            break;

        case 4:
            fn_varying_dynamic_neg_counter_4(limit);
            break;

        case 5:
            fn_varying_dynamic_neg_counter_5(limit);
            break;

        default:
            free(buffer);
            cleanup(ops, total_ops);
            exit(1);
    }

    num_ops++;

    // enum var
    num_tokens = tokenize(ops[ENUM_VAR_AND_VALUES], enum_var_and_values, ';', 3);
    if (num_tokens < 3) {
        printf("Not enough tokens (%d)\n", num_tokens);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(enum_var_and_values, num_tokens);

        exit(1);
    }

    var_num = parse_int(enum_var_and_values[ENUM_VAR_NUM]);
    if (var_num <= 0 || var_num > 5) {
        printf("Bad enum number (%d)\n", var_num);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(enum_var_and_values, num_tokens);

        exit(1);
    }

    enum_mod_type = enum_var_and_values[ENUM_VAR_MOD_TYPE][0];
    if (enum_mod_type != ENUM_VAR_SINGLE_MOD && enum_mod_type != ENUM_VAR_MULTI_MOD) {
        printf("Bad enum mod type (%c)\n", enum_mod_type);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(enum_var_and_values, num_tokens);

        exit(1);
    }

    int num_values = tokenize(enum_var_and_values[VALUES], values, ',', MAX_VALUES);
    if (num_values == 0) {
        printf("Too few values (%d)\n", num_values);
        free(buffer);
        cleanup(ops, total_ops);
        cleanup(enum_var_and_values, num_tokens);
        cleanup(values, num_values);

        exit(1);
    }

    cleanup(enum_var_and_values, num_tokens);

    for (int i = 0; i < num_values; i ++) {
       int value = parse_int(values[i]);
       if (enum_mod_type == ENUM_VAR_SINGLE_MOD) {
           switch (var_num) {
               case 1:
                   fn_enum_var_single_mod_1(value);
                   break;

               case 2:
                   fn_enum_var_single_mod_2(value);
                   break;

               case 3:
                   fn_enum_var_single_mod_3(value);
                   break;

               case 4:
                   fn_enum_var_single_mod_4(value);
                   break;

               case 5:
                   fn_enum_var_single_mod_5(value);
                   break;

               default:
                   free(buffer);
                   cleanup(ops, total_ops);
                   cleanup(values, num_values);
                   exit(1);
           }
       } else {
           switch (var_num) {
               case 1:
                   fn_enum_var_multi_mod_1(value);
                   break;

               case 2:
                   fn_enum_var_multi_mod_2(value);
                   break;

               case 3:
                   fn_enum_var_multi_mod_3(value);
                   break;

               case 4:
                   fn_enum_var_multi_mod_4(value);
                   break;

               case 5:
                   fn_enum_var_multi_mod_5(value);
                   break;

               default:
                   free(buffer);
                   cleanup(ops, total_ops);
                   cleanup(values, num_values);
                   exit(1);
           }
       }

       num_ops++;
    }

    free(buffer);
    cleanup(ops, total_ops);
    cleanup(values, num_values);

    //printf("Ops performed: %d\n", num_ops);

    return 0;
}
