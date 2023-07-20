import sys
import logging
import time

sys.path.append('..')
import angr
from angr.state_plugins.runtime_state import RuntimeStatePlugin

l = logging.getLogger('readpcap')

file_name = 'gtpv1.pcap'
file_handler = logging.FileHandler(
    'readpcap' + '_' + file_name + '_' + str(time.strftime('%Y%m%d%H%M%S')) + '.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

def run_simulation(project, init_state, end_branch=0, end_addr=0, end_step=0, debug=False, switch_addr=[]):
    simgr = project.factory.simgr(init_state, save_unconstrained=True)

    prev_state_count = 0
    # prev_state_addrs = []
    # state_predecessors = []
    count = 0
    active = None
    while len(simgr.active) > 0:
        active = simgr.active[0]
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

    if not simgr.deadended:
        l.info('[Simgr]: execution terminlated with no deadended! Returning last active')
        return active
    else:
        return simgr.deadended

load_options = {}
load_options['auto_load_libs'] = True
load_options['except_missing_libs'] = True
load_options['ld_path'] = [
    "lib/",
    "/usr/lib/x86_64-linux-gnu/pulseaudio/",
    "/usr/lib/x86_64-linux-gnu"
]

project = angr.Project(
    "binaries/readpcap-ferry",
    load_options=load_options,
)

argc = 2
argv = 0x2000
arg1 = 0x3000
main = project.loader.find_symbol(
    'main'
)

init_state = project.factory.entry_state(
    concrete_fs=True,
    add_options=angr.options.unicorn | { angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY }
)

init_state.regs.rdi = 2
init_state.regs.rsi = argv
init_state.memory.store(arg1, ("/home/vivin/Projects/phd/tools/ferry/inputs/"+file_name).ljust(0x1000, "\x00"))
init_state.memory.store(argv+8, arg1, endness='Iend_LE')

branch_related = list()
input_related = list()
state_related = list()
rsg = list()

init_state.register_plugin("runtime_state", RuntimeStatePlugin())

# init_state.options.remove('UNICORN')
final_state = run_simulation(project, init_state, debug=False,
                            switch_addr=[]
                            )
f = open(file_name +'.txt', 'w')
for bbl in final_state.history.bbl_addrs.hardcopy:
    f.write(str(bbl)+'\n')
f.close()

#import IPython
#IPython.embed()
