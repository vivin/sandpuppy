import os
import sys
import weakref
import pickle
import logging
import time
from collections import defaultdict

sys.path.append('..')
import angr
from angr.errors import SimValueError, SimSolverModeError
import claripy
import IPython
import labyrinth
from labyrinth.memory_address_annotation import MemoryAddressAnnotation
from labyrinth.runtime_state_graph import RuntimeStateGraph


file_handler = logging.FileHandler(
    'libjpeg_%s.log' % time.strftime('%Y%m%d%H%M%S'))
formatter = logging.Formatter(
    '%(levelname)s | %(asctime)s | %(name)s | %(message)s')
file_handler.setFormatter(formatter)
logger = logging.getLogger()
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

load_options = {}
load_options['auto_load_libs'] = True
load_options['except_missing_libs'] = True
load_options['custom_ld_path'] = [
    "/home/shelven/Documents/targets/libjpeg-turbo/build"
    "/usr/lib/x86_64-linux-gnu/",
]

project = angr.Project(
    "/home/shelven/Documents/targets/libjpeg-turbo/build/djpeg",
    load_options=load_options,
)


def s2a(x): return project.loader.find_symbol(x).rebased_addr


project.unhook_symbol('fread')
hooks = {
    'fread': angr.procedures.libc.fread.fread(symbolic_wrap=True, switch_offset=0),
}
for addr, hook in hooks.items():
    if not isinstance(addr, int):
        addr = s2a(addr)
    project.hook(addr, hook)

s = project.factory.entry_state(
    concrete_fs=True,
    args=[
        '/home/shelven/Documents/targets/libjpeg-turbo/build/djpeg',
        '/home/shelven/Documents/targets/resources/test0.jpg',
    ],
    add_options={angr.options.SIMPLIFY_CONSTRAINTS,
                 angr.options.SIMPLIFY_EXIT_GUARD}
)


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
            if state.solver.is_true(guard) or state.solver.is_false(guard):
                logger.info("no changing to determined branch")
            else:
                logger.info("cut branch because of duplicate state")
                state.inspect.exit_guard = claripy.false
        else:
            reached = False
            for s in rsg:
                if state.runtime_state.equal(s):
                    reached = True
                    break
            if reached:
                if state.solver.is_true(guard) or state.solver.is_false(guard):
                    logger.info("no changing to determined branch")
                else:
                    logger.info("cut branch because of duplicate state")
                    state.inspect.exit_guard = claripy.false
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


s.inspect.make_breakpoint(
    event_type='mem_write',
    when=angr.BP_BEFORE,
    condition=lambda s: True,
    action=track_mem_write,
)

s.inspect.make_breakpoint(
    event_type='exit',
    when=angr.BP_BEFORE,
    condition=lambda s: True,
    action=track_branch,
)

s.inspect.make_breakpoint(
    event_type='mem_read',
    when=angr.BP_AFTER,
    condition=lambda s: True,
    action=taint_mem_read,
)

simgr = project.factory.simgr(s)
simgr.run()
#simgr.run(until=lambda lpg: len(lpg.active) > 1)

IPython.embed()
