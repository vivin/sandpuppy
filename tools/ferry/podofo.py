import angr
import logging
import time
import ctypes

l = logging.getLogger("podofo")
file_name = 'empty.file'
file_handler = logging.FileHandler(
    's2e_state_coverage_podofo' + '_' + file_name + '_' + str(time.strftime('%Y%m%d%H%M%S')) + '.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

load_options = {}
load_options['auto_load_libs'] = True
load_options['except_missing_libs'] = True
load_options['custom_ld_path'] = [
    "lib/",
    "/lib64/",
    "/usr/lib/x86_64-linux-gnu"
]

project = angr.Project(
    "bin/podofopdfinfo",
    # default_analysis_mode='fastpath',
    # use_sim_procedures=False,
    load_options=load_options,
)

class HookDoNothing(angr.SimProcedure):
    def run(self):
        return

class HookReturnTrue(angr.SimProcedure):
    def run(self):
        return 1

class HookLocalTime(angr.SimProcedure):
    def run(self, m_time):
        libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libc-2.23.so')
        localtime = libc.localtime
        time = self.state.memory.load(m_time, size=8, endness=self.state.arch.memory_endness)
        c_time = ctypes.c_long(self.state.solver.eval(time))
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
	localtime.restype = ctypes.POINTER(TimeStruct)
	time_data = localtime(ctypes.byref(c_time))
	if not time_data:
            return 0
	time_result = 0x1000
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

hooks = {
    'localtime': HookLocalTime(),
    '_ZNSt9basic_iosIcSt11char_traitsIcEE15_M_cache_localeERKSt6locale': HookDoNothing(),
    '_ZNSt9basic_iosIwSt11char_traitsIwEE15_M_cache_localeERKSt6locale': HookDoNothing(),
}

def s2a(x): return project.loader.find_symbol(x).rebased_addr


for addr, hook in hooks.items():
    if not isinstance(addr, int):
        addr = s2a(addr)
    project.hook(addr, hook)

@project.hook(0x4dd2a6, length=0)
def PrintToken(state):
    f=state.posix.fd[3]
    l.info('token-ftell: %d c: %d', state.solver.eval(f.tell()), state.solver.eval(state.regs.eax))

argc = 3
argv = 0x2000
arg1 = 0x3000
arg2 = 0x4000
main = project.loader.find_symbol(
    'main'
)

init_state = project.factory.entry_state(
    concrete_fs=True,
    add_options=
    # angr.options.unicorn |
    { angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY },
)
# setup functions in .init_array section
"""
init_func = project.factory.callable(0x4c41d2, base_state=init_state)
init_func()
init_state = init_func.result_state

init_func = project.factory.callable(0x4df74f, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x4e2ca0, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x4d11fa, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x4dc125, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x5041a7, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x506001, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x507649, base_state=init_state)
init_func()
init_state = init_func.result_state
# init_func = project.factory.callable(0x539918, base_state=init_state)
# init_func()
# init_state = init_func.result_state

init_func = project.factory.callable(0x53c392, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x5505ea, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x5599d8, base_state=init_state)
init_func()
init_state = init_func.result_state
init_func = project.factory.callable(0x55f0fb, base_state=init_state)
init_func()
init_state = init_func.result_state

init_array = [
    0x4c41d2, 0x4df74f, 0x4e2ca0, 0x4d11fa, 0x4dc125, 0x5041a7,
    0x562074, 0x56f899, 0x5743a6, 0x582075, 0x58df78, 0x594b80, 0x59c87b, 0x59d73a, 0x4d4fc5, 0x4d7cc7, 0x4fcb4d, 0x5099d5, 0x516aae, 0x529236, 0x5505ea, 0x5599d8,
    0x507649, 0x55f0fb, 0x506001,
    # 0x53c392, 0x539918,
    ]
"""
init_array = [
    0x4c41d2, 0x4c6a29, 0x4d11fa, 0x4d4fc5, 0x4d7cc7, 0x4dc125, 0x4df74f, 0x4e2ca0, 0x4fcb4d, 0x5041a7, 0x506001, 0x507649, 0x5099d5, 0x516aae, 0x529236, 0x53c392, 0x5505ea, 0x5599d8, 0x55f0fb, 0x562074, 0x56f899, 0x5743a6, 0x582075, 0x58df78, 0x594b80, 0x59c87b, 0x59d73a,
]

# init_array = []
for addr in init_array:
    init_func = project.factory.callable(addr, base_state=init_state)
    init_func()
    init_state = init_func.result_state

init_state = project.factory.call_state(
    main.rebased_addr,
    base_state=init_state
)
init_state.regs.edi = argc
init_state.regs.rsi = argv
init_state.memory.store(arg1, "DCPON".ljust(0x1000, "\x00"))
init_state.memory.store(arg2, ("/home/shelven/Documents/labyrinth/tests/"+file_name).ljust(0x1000, "\x00"))
init_state.memory.store(argv+8, arg1, endness='Iend_LE')
init_state.memory.store(argv+16, arg2, endness='Iend_LE')

states = list()
def track_branch(state):
    global states

    src = state.ip
    dst = state.inspect.exit_target

    if src.concrete and dst.concrete:
        src = state.solver.eval(src)
        dst = state.solver.eval(dst)
        state = (src, dst)
        if state not in states:
            states.append(state)
            l.info("Number of states: [%d]", len(states))

init_state.inspect.make_breakpoint(
    event_type='exit',
    when=angr.BP_BEFORE,
    condition=lambda s: s.inspect.exit_jumpkind == 'Ijk_Boring',
    action=track_branch,
)

# simgr = project.factory.simgr(
#     init_state,
#     save_unconstrained=True
# )

# simgr.explore(find=0x4dd2a6)
# simgr.move('found','active')
# while len(simgr.active):
#     s=simgr.active[0]
#     f=s.posix.fd[3]
#     l.info('token-ftell: %d c: %d', s.solver.eval(f.tell()), s.solver.eval(s.regs.eax))
#     simgr.step()
#     simgr.explore(find=0x4dd2a6)
#     simgr.move('found','active')

# import IPython;IPython.embed()
init_state = run_simulation(
	project,
	init_state,
	#end_branch=1,
	debug=False,
)

import IPython;IPython.embed()
