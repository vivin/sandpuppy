/*
 * Copyright (c) 2019 The Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"
#include "../types.h"
#include "reducers.h"

#ifndef VVDUMP_H
#define VVDUMP_H

#ifdef __cplusplus
extern "C" {
#endif

#define VVD_EXP_NAME_ENV_VAR        "__VVD_EXP_NAME"
#define VVD_SUBJECT_ENV_VAR         "__VVD_SUBJECT"
#define VVD_BIN_CONTEXT_ENV_VAR     "__VVD_BIN_CONTEXT"
#define VVD_EXEC_CONTEXT_ENV_VAR    "__VVD_EXEC_CONTEXT"

#define VVD_NAMED_PIPE_PATH         "/tmp/vvdump"

void __dump_variable_value(const char* filename, const char* function_name, const char* variable_name, int declared_line, int modified_line, const char* var_val_format, ...);

#ifdef __cplusplus
}
#endif

#endif // VVDUMP_H
