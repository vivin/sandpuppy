import logging
import re
import string
import sys
from ctypes import (CDLL, Array, byref, c_byte, c_char_p, c_double, c_float,
                    c_int, c_long, c_longdouble, c_longlong, c_short, c_size_t,
                    c_ubyte, c_uint, c_ulong, c_ulonglong, c_ushort, c_void_p,
                    c_wchar_p, create_string_buffer, create_unicode_buffer,
                    sizeof, util)

import angr
from angr.sim_type import SimTypeInt, SimTypeString

l = logging.getLogger(name=__name__)

LIBC = CDLL(util.find_library('c'))

C_SCANF_TYPES = {
    'i': c_int,
    'hhi': c_byte,
    'hi': c_short,
    'li': c_long,
    'lli': c_longlong,
    'ji': c_longlong,
    'zi': c_size_t,
    'ti': c_longlong,

    'd': c_int,
    'hhd': c_byte,
    'hd': c_short,
    'ld': c_long,
    'lld': c_longlong,
    'jd': c_longlong,
    'zd': c_size_t,
    'td': c_longlong,

    'u': c_uint,
    'hhu': c_ubyte,
    'hu': c_ushort,
    'lu': c_ulong,
    'llu': c_ulonglong,
    'ju': c_ulonglong,
    'zu': c_size_t,
    'tu': c_longlong,

    'o': c_uint,
    'hho': c_ubyte,
    'ho': c_ushort,
    'lo': c_ulong,
    'llo': c_ulonglong,
    'jo': c_ulonglong,
    'zo': c_size_t,
    'to': c_longlong,

    'x': c_uint,
    'hhx': c_ubyte,
    'hx': c_ushort,
    'lx': c_ulong,
    'llx': c_ulonglong,
    'jx': c_ulonglong,
    'zx': c_size_t,
    'tx': c_longlong,

    'f': c_float,
    'lf': c_double,
    'Lf': c_longdouble,
    'e': c_float,
    'le': c_double,
    'Le': c_longdouble,
    'g': c_float,
    'lg': c_double,
    'Lg': c_longdouble,
    'a': c_float,
    'la': c_double,
    'La': c_longdouble,

    'c': c_byte,  # c_char_p,
    # 'lc': lambda l: lambda: create_unicode_buffer(l),  # c_wchar_p,
    's': lambda l: lambda: create_string_buffer(l),  # c_char_p,
    # 'ls': lambda l: lambda: create_unicode_buffer(l),  # c_wchar_p,

    ']': lambda l: lambda: create_string_buffer(l),  # c_char_p,
    # 'l[]' : c_wchar_p, handled in _get_c_object

    'p': c_void_p,

    'n': c_int,
    'hhn': c_byte,
    'hn': c_short,
    'ln': c_long,
    'lln': c_longlong,
    'jn': c_longlong,
    'zn': c_size_t,
    'tn': c_longlong,
}

SPECIFIER = re.compile('%([^ \t\n\r\f\v%%*]+)')


class IllegalSpecifier(Exception):
    pass


def _get_c_object(part, length):
    ctor = None

    part = part.lstrip(string.digits)

    if part[0] == '[':
        ctor = C_SCANF_TYPES[']']
    else:
        for l in xrange(len(part), 0, -1):
            try:
                ctor = C_SCANF_TYPES[part[:l]]
                break
            except KeyError:
                continue

    if not ctor:
        raise IllegalSpecifier('cannot handle specifier "%%%s"' % part)

    # special handling of string types
    if part[:1] in ('s', '['):
        # create unicode type for l[]
        # if part[-1:] == ']' and part.find('l[') != -1:
        #     def ctor(l): return lambda: create_unicode_buffer(l)
        # string buffers with length of input string
        ctor = ctor(length)
    return ctor()


def _sscanf(fmt, s):
    """
    clib sscanf for Python.
    For unicode strings use the l-versions of the string specifiers
    (%ls instead of %s).
    Returns a list with filled specifiers in order.
    """
    length = len(s)
    args = [_get_c_object(part, length) for part in SPECIFIER.findall(fmt)]
    sscanf_func = LIBC.sscanf
    buffer_ctor = create_string_buffer
    # if isinstance(s, unicode):
    #     sscanf_func = LIBC.swscanf
    #     buffer_ctor = create_unicode_buffer
    filled = sscanf_func(buffer_ctor(s), buffer_ctor(fmt), *map(byref, args))
    return [args[i] for i in xrange(filled)]


class sscanf(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def parse(self, fmt_idx):
        fmtstr_ptr = self.arg(fmt_idx)

        if self.state.se.symbolic(fmtstr_ptr):
            raise SimProcedureError("Symbolic pointer to (format) string :(")

        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        length = self.inline_call(strlen, fmtstr_ptr).ret_expr
        if self.state.se.symbolic(length):
            all_lengths = self.state.se.eval_upto(length, 2)
            if len(all_lengths) != 1:
                raise SimProcedureError(
                    "Symbolic (format) string, game over :(")
            length = all_lengths[0]

        if self.state.se.is_true(length == 0):
            return ""

        fmt_xpr = self.state.memory.load(fmtstr_ptr, length)

        fmt = []
        for i in xrange(fmt_xpr.size(), 0, -8):
            char = fmt_xpr[i - 1: i - 8]
            try:
                conc_char = self.state.solver.eval_one(char)
            except SimSolverError:
                raise SimProcedureError(
                    "Symbolic (format) string, game over :(")
            else:
                # Concrete chars are directly appended to the list
                fmt.append(chr(conc_char))

        return ''.join(fmt)

    def run(self, data, fmt):
        # pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        s = self.parse(0)
        fmt_str = self.parse(1)

        args = _sscanf(str(fmt_str), str(s))

        arg_start_pos = 2
        for i, arg in enumerate(args):
            try:
                dest = self.arg(arg_start_pos + i)
            except SimProcedureArgumentError:
                dest = None

            if isinstance(arg, Array):
                self.state.memory.store(dest, arg.value+'\x00')
            if isinstance(arg, c_long) or isinstance(arg, c_ulong) or isinstance(arg, c_void_p):
                self.state.memory.store(
                    dest, arg.value, size=self.state.arch.bits / 8, endness=self.state.arch.memory_endness)
            else:
                self.state.memory.store(dest, arg.value, size=sizeof(
                    arg), endness=self.state.arch.memory_endness)

        return len(args)

from angr.errors import SimProcedureArgumentError, SimProcedureError, SimSolverError
