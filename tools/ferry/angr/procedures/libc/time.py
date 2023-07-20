import ctypes
import logging

import angr

l = logging.getLogger(name=__name__)


class TimeStruct(ctypes.Structure):
    _fields_ = [
        ("tm_sec", ctypes.c_int),
        ("tm_min", ctypes.c_int),
        ("tm_hour", ctypes.c_int),
        ("tm_mday", ctypes.c_int),
        ("tm_mon", ctypes.c_int),
        ("tm_year", ctypes.c_int),
        ("tm_wday", ctypes.c_int),
        ("tm_yday", ctypes.c_int),
        ("tm_isdst", ctypes.c_int),

        ("tm_gmtoff", ctypes.c_long),
        ("tm_zone", ctypes.c_long),
    ]


def store_time_t(state, resultp, time_data):
    endness = state.arch.memory_endness

    state.memory.store(resultp, time_data.contents.tm_sec, size=4, endness=endness)
    state.memory.store(resultp+4, time_data.contents.tm_min, size=4, endness=endness)
    state.memory.store(resultp+8, time_data.contents.tm_hour, size=4, endness=endness)
    state.memory.store(resultp+12, time_data.contents.tm_mday, size=4, endness=endness)
    state.memory.store(resultp+16, time_data.contents.tm_mon, size=4, endness=endness)
    state.memory.store(resultp+20, time_data.contents.tm_year, size=4, endness=endness)
    state.memory.store(resultp+24, time_data.contents.tm_wday, size=4, endness=endness)
    state.memory.store(resultp+28, time_data.contents.tm_yday, size=4, endness=endness)
    state.memory.store(resultp+32, time_data.contents.tm_isdst, size=4, endness=endness)
    state.memory.store(resultp+36, 0, size=4)
    state.memory.store(resultp+40, time_data.contents.tm_gmtoff, size=state.arch.bits // 8, endness=endness)
    state.memory.store(resultp+40+state.arch.bits // 8, time_data.contents.tm_zone,
                       size=state.arch.bits // 8, endness=endness)


class localtime(angr.SimProcedure):

    def run(self, time):
        libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
        localtime = libc.localtime

        time_ = self.state.memory.load(
            time, size=self.state.arch.bits // 8, endness=self.state.arch.memory_endness)
        c_time = ctypes.c_long(self.state.solver.eval(time_))

        localtime.restype = ctypes.POINTER(TimeStruct)
        time_data = localtime(ctypes.byref(c_time))

        if not time_data:
            return 0

        resultp = 0x10000
        l.warning("Put localtime() result in 0x%x", resultp)

        store_time_t(self.state, resultp, time_data)
        return resultp


class gmtime_r(angr.SimProcedure):

    def run(self, time, resultp):
        libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc.so.6')
        gmtime = libc.gmtime

        time_ = self.state.memory.load(
            time, size=8, endness=self.state.arch.memory_endness)
        c_time = ctypes.c_long(self.state.solver.eval(time_))

        gmtime.restype = ctypes.POINTER(TimeStruct)
        time_data = gmtime(ctypes.byref(c_time))

        if not time_data:
            return 0

        store_time_t(self.state, resultp, time_data)
        return resultp
