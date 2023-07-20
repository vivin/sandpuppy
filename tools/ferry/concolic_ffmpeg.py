import os
import sys
from collections import defaultdict
import logging
import time
import ctypes


sys.path.append('..')
import angr
from angr.sim_type import SimTypeLength, SimTypeTop
from angr.errors import SimValueError, SimSolverModeError
import claripy
import labyrinth
from labyrinth.memory_address_annotation import MemoryAddressAnnotation
from labyrinth.runtime_state_graph import RuntimeStateGraph

l = logging.getLogger('ffmpeg')

file_name = 'MargotGagnon.mov'
file_handler = logging.FileHandler(
    'ffmpeg' + '_' + file_name + '_' + str(time.strftime('%Y%m%d%H%M%S')) + '.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

class HookGMTime_r(angr.SimProcedure):
    def run(self, clock, result):
        # import IPython;IPython.embed()
        libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc-2.23.so')
        gmtime = libc.gmtime

        t_clock = self.state.memory.load(clock, size=8, endness=self.state.arch.memory_endness)
        time_clock = ctypes.c_long(self.state.solver.eval(t_clock))

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
        gmtime.restype = ctypes.POINTER(TimeStruct)
        time_data = gmtime(ctypes.byref(time_clock))

        if not time_data:
            return 0
        time_result = result
        # import IPython;IPython.embed()
        self.state.memory.store(time_result, time_data.contents.tm_sec, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+4, time_data.contents.tm_min, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+8, time_data.contents.tm_hour, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+12, time_data.contents.tm_mday, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+16, time_data.contents.tm_mon, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+20, time_data.contents.tm_year, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+24, time_data.contents.tm_wday, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+28, time_data.contents.tm_yday, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+32, time_data.contents.tm_isdst, size=4, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+36, 0, size=4)
        self.state.memory.store(time_result+40, time_data.contents.tm_gmtoff, size=self.state.arch.bits/8, endness=self.state.arch.memory_endness)
        self.state.memory.store(time_result+40+self.state.arch.bits/8, time_data.contents.tm_zone, size=self.state.arch.bits/8, endness=self.state.arch.memory_endness)

        return time_result


class HookReturnTrue(angr.SimProcedure):
    def run(self):
        return 1

count = 0
class HookAVLog(angr.SimProcedure):
    def run(self):
        # logg = self.state.solver.eval(self.state.memory.load(self.state.regs.rdx, 80), cast_to=str)
        # l.info("[av_log]:%s", logg)
        return
"""
        kw1 = ["%02d:%02d:%02d.%02d", ", SAR %d:%d DAR %d:%d", "%3.2f %s", "%1.4f %s", "%1.0f %s", "%1.0fk %s"]
        kw2 = [", bitrate: ", "(%s)", "  Duration: "]
        global count
        if self.state.solver.eval(self.state.regs.rsi) == 32:
            if count:
                import IPython;IPython.embed()
                count = 0
            else:
                for i in kw2:
                    if logg.find(i) == 0:
                        count = 1
                for i in kw1:
                    if logg.find(i) == 0:
                        import IPython;IPython.embed()

        return
"""
class HookPosix_Memalign(angr.SimProcedure):
    def run(self, memptr, alignment, sim_size):
        # malloc = angr.SIM_PROCEDURES['libc']['malloc']
        # ptr = self.inline_call(malloc, sim_size).ret_expr

        align = self.state.solver.eval(alignment)
        size = self.state.solver.eval(sim_size)
        ptr = (int(self.state.libc.heap_location/align)+1)*align
        self.state.libc.heap_location = ptr + size

        self.state.mem[memptr].int64_t = ptr
        # import IPython;IPython.embed()

        return 0

def run_simulation(project, init_state, end_branch=0, end_addr=0, end_step=0, debug=False, switch_addr=[]):
    simgr = project.factory.simgr(init_state, save_unconstrained=True)

    prev_state_count = 0
    # prev_state_addrs = []
    # state_predecessors = []
    count = 0
    while len(simgr.active) > 0:
        # for s in simgr.active:
        #     if s.history.recent_bbl_addrs:
        #         state_predecessors.append(s.history.recent_bbl_addrs[-1])
        # for addr in prev_state_addrs:
        #     if addr in state_predecessors:
        #         state_predecessors.remove(addr)
        count += 1
        l.info("[Simgr]: %s, %d more active states, %d steps!", simgr,
               len(simgr.active) - prev_state_count, count)
        # if len(state_predecessors) > 0:
        #     for addr in state_predecessors:
        #         l.info("new branch: \t0x%x", addr)
        prev_state_count = len(simgr.active)
        # prev_state_addrs = [s.addr for s in simgr.active]
        if end_branch:
            if len(simgr.active) > end_branch:
                # import IPython
                # IPython.embed()
                return simgr.active
        if end_addr:
            for s in simgr.active:
                if s.addr == end_addr:
                    return s
        if end_step:
            if count == end_step:
                if debug:
                    import IPython
                    IPython.embed()
                else:
                    return simgr.active[0]
        if switch_addr:
            for addr in switch_addr:
                if simgr.active[0].addr == addr:
                    simgr.active[0].options.add('UNICORN')
                    simgr.step(2)
                    simgr.active[0].options.remove('UNICORN')

        elif debug:
            import IPython
            IPython.embed()

        simgr.step()

    if simgr.deadended:
        # import IPython
        # IPython.embed()
        return simgr.deadended
    else:
        l.info('[Simgr]: execution terminlated with no deadended!')
        import IPython
        IPython.embed()


load_options = {}
load_options['auto_load_libs'] = True
load_options['except_missing_libs'] = True
load_options['custom_ld_path'] = [
    "lib/",
    "/usr/lib/x86_64-linux-gnu/pulseaudio/",
    "/usr/lib/x86_64-linux-gnu"
]

project = angr.Project(
    "bin/ffmpeg",
    load_options=load_options,
)

project.unhook_symbol('fread')
project.unhook_symbol('read')
hooks = {
    'term_init': HookReturnTrue(),  # term init
    'signal': HookReturnTrue(),
    'av_log': HookAVLog(),
    'parse_loglevel': HookReturnTrue(),
    'fcntl': HookReturnTrue(),
    'gmtime_r': HookGMTime_r(),
    'posix_memalign': HookPosix_Memalign(),

    'fread': angr.procedures.libc.fread.fread(symbolic_wrap=True, switch_offset=0),
    'read': angr.procedures.linux_kernel.read.read(symbolic_wrap=True, switch_offset=0),
}


def s2a(x): return project.loader.find_symbol(x).rebased_addr


for addr, hook in hooks.items():
    if not isinstance(addr, int):
        addr = s2a(addr)
    project.hook(addr, hook)


# @project.hook(0x8029800, length=0)
# def av_malloc_size(state):
#     size = state.solver.eval(state.regs.rdi)
#     l.info("[av_log]: av_malloc - size:%s", hex(size))
#     # import IPython;IPython.embed()

# @project.hook(0x802983b, length=0)
# def av_malloc_ptr(state):
#     ptr = state.solver.eval(state.regs.rax)
#     l.info("[av_log]: av_malloc - ptr:%s", hex(ptr))
#     # import IPython;IPython.embed()


argc = 3
argv = 0x2000
arg1 = 0x3000
arg2 = 0x4000
main = project.loader.find_symbol(
    'main'
)

init_state = project.factory.entry_state(
    concrete_fs=True,
    # add_options=angr.options.unicorn | { angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY },
    add_options=
    # angr.options.unicorn |
    {angr.options.SIMPLIFY_CONSTRAINTS, angr.options.SIMPLIFY_EXIT_GUARD},
    addr=main.rebased_addr
)
init_state.regs.rdi = 3
init_state.regs.rsi = argv
init_state.memory.store(arg1, "-i".ljust(0x1000, "\x00"))
init_state.memory.store(arg2, ("/home/shelven/Documents/labyrinth/tests/"+file_name).ljust(0x1000, "\x00"))
init_state.memory.store(argv+8, arg1, endness='Iend_LE')
init_state.memory.store(argv+16, arg2, endness='Iend_LE')

branch_related = list()
input_related = list()
state_related = list()
#rsg = RuntimeStateGraph()
rsg = list()


def track_branch(state):
    global branch_related, input_related, state_related, rsg

    try:
        code_loc = state.solver.eval_one(state.ip)
    except (SimValueError, SimSolverModeError):
        logger.warning("symbolic code location in branch %s", state.ip)
        return

    guard = state.inspect.exit_guard
    jumpkind = state.inspect.exit_jumpkind

    if jumpkind != 'Ijk_Boring':
        return

    def get_mem_addrs(bv):
        if type(bv) in (int, long):
            return []

        mem_addrs = [(a.mem_addr, a.size)
                     for a in bv.annotations if isinstance(a, MemoryAddressAnnotation)]

        if bv.depth == 1:
            return mem_addrs

        for arg in bv.args:
            for a in get_mem_addrs(arg):
                if a not in mem_addrs:
                    mem_addrs.append(a)

        return mem_addrs

    state_tick = False
    state_changed = False
    for mem_addr, size in get_mem_addrs(guard):
        if mem_addr in state_related:
            changed = state.runtime_state.update(
                code_loc, mem_addr, size, constraint=guard)
            if not state_changed and changed:
                state_changed = True
            state_tick = True
        else:
            if mem_addr not in branch_related:
                logger.info("branch-related memories: 0x%x", mem_addr)
                branch_related.append(mem_addr)

                if mem_addr in input_related:
                    logger.info("state-related from branch: 0x%x", mem_addr)
                    state_related.append(mem_addr)
                    changed = state.runtime_state.update(
                        code_loc, mem_addr, size, constraint=guard)
                    if not state_changed and changed:
                        state_changed = True
                    state_tick = True

    if state_tick:
        if not state_changed:
            # or (state.runtime_state.pure_state() in rsg):
            # if state.solver.is_true(guard) or state.solver.is_false(guard):
            #     logger.info("no changing to determined branch")
            # else:
            #     logger.info("cut branch because of duplicate state")
                # state.inspect.exit_guard = claripy.false
            pass
        else:
            reached = False
            for s in rsg:
                if state.runtime_state.equal(s):
                    reached = True
                    break
            if reached:
                pass
                # if state.solver.is_true(guard) or state.solver.is_false(guard):
                #     logger.info("no changing to determined branch")
                # else:
                #     logger.info("cut branch because of duplicate state")
                    # state.inspect.exit_guard = claripy.false
            else:
                rsg.append(state.runtime_state.export())


def track_mem_write(state):
    global branch_related, input_related, state_related

    try:
        code_loc = state.solver.eval_one(state.ip)
    except (SimValueError, SimSolverModeError):
        logger.warning("symbolic code location in mem_write %s", state.ip)
        return

    expr = state.inspect.mem_write_expr
    size = state.inspect.mem_write_length
    try:
        mem_addr = state.solver.eval_one(state.inspect.mem_write_address)
    except (SimValueError, SimSolverModeError):
        logger.warning("symbolic memory write address %s",
                       state.inspect.mem_write_address)
        return

    state_changed = False
    if mem_addr in state_related:
        state_changed = state.runtime_state.update(
            code_loc, mem_addr, size, assignment=expr)
    else:
        taint = False
        for v in expr.variables:
            if v.startswith('filewrap'):
                taint = True
                break

        if taint:
            if mem_addr not in input_related:
                logger.info("input-related memories: 0x%x", mem_addr)
                input_related.append(mem_addr)

                if mem_addr in branch_related:
                    logger.info("state-related from assign: 0x%x", mem_addr)
                    state_related.append(mem_addr)
                    state_changed = state.runtime_state.update(
                        code_loc, mem_addr, size, assignment=expr)

    if state_changed:
        rsg.append(state.runtime_state.export())


def taint_mem_read(state):
    try:
        addr = state.solver.eval_one(state.inspect.mem_read_address)
    except (SimValueError, SimSolverModeError):
        addr = state.inspect.mem_read_address
        logger.warning("symbolic memory read address")
        return

    for a in state.inspect.mem_read_expr.annotations:
        if isinstance(a, MemoryAddressAnnotation):
            state.inspect.mem_read_expr.annotations = tuple(
                a for a in state.inspect.mem_read_expr.annotations if not isinstance(a, MemoryAddressAnnotation))
            break

    state.inspect.mem_read_expr = state.inspect.mem_read_expr.annotate(
        MemoryAddressAnnotation(addr, state.inspect.mem_read_length))


init_state.inspect.make_breakpoint(
    event_type='mem_write',
    when=angr.BP_BEFORE,
    condition=lambda s: True,
    action=track_mem_write,
)

init_state.inspect.make_breakpoint(
    event_type='exit',
    when=angr.BP_BEFORE,
    condition=lambda s: True,
    action=track_branch,
)

init_state.inspect.make_breakpoint(
    event_type='mem_read',
    when=angr.BP_AFTER,
    condition=lambda s: True,
    action=taint_mem_read,
)

# init_state.options.remove('UNICORN')
init_state = run_simulation(project, init_state, debug=False,
                            switch_addr=[0xb041d27,0x40a88c9]
                            )
# simgr = project.factory.simgr(init_state)
# simgr.run()
# f = open(file_name +'.txt', 'w+')
# ll = list(init_state[0].history.bbl_addrs)
# import string
# for i in ll:
#     f.write(str(i)+'\n')
# f.close()

import IPython
IPython.embed()
