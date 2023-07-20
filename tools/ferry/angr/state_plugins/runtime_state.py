import logging

from .. import options, procedures
from ..errors import SimSolverModeError, SimValueError
from .inspect import BP_AFTER, BP_BEFORE
from .plugin import SimStatePlugin
from .runtime_state_utils import (RuntimeStateSummary, RuntimeStateTransition,
                                  WindowDict, annotate_memory_source)

l = logging.getLogger(name=__name__)

plugin_name = "runtime_state"


def track_branch(state):
    if state.solver.symbolic(state.ip):
        l.warning("symbolic code location in branch %s", state.ip)
        return

    rs_summary = RuntimeStateSummary(state)

    loc = state.solver.eval(state.ip)
    jumpkind = state.inspect.exit_jumpkind
    if jumpkind == 'Ijk_Boring':
        guard = state.inspect.exit_guard
        rs_transition = RuntimeStateTransition(state, RuntimeStateTransition.RST_BRANCH, loc, branch_guard=guard)
        updated = rs_transition.update_rs_summary(rs_summary)
        if updated:
            if state.project.kb.runtime_states.reached(rs_summary, state):
                l.info("reached runtime state in branch 0x%x", loc)
            pass
    elif jumpkind == 'Ijk_Ret':
        if state.solver.symbolic(state.inspect.exit_target):
            l.warning("symbolic return target at %s", state.ip)
            return

        # we mandate the state transition point of return to return target instead of the address of return instruction
        target = state.solver.eval(state.inspect.exit_target)
        rs_transition = RuntimeStateTransition(state, RuntimeStateTransition.RST_RETURN, target,
                                               return_target=target, return_stack_pointer=state.callstack.current_stack_pointer)
        updated = rs_transition.update_rs_summary(rs_summary)
        if updated:
            if state.project.kb.runtime_states.reached(rs_summary, state):
                l.info("reached runtime state after return in 0x%x to 0x%x", loc, target)
            pass


def track_assignment(state):
    if state.solver.symbolic(state.ip):
        l.warning("symbolic code location in mem_write")
        return
    if state.solver.symbolic(state.inspect.mem_write_address):
        l.warning("symbolic memory write address")
        return

    rs_summary = RuntimeStateSummary(state)

    loc = state.solver.eval(state.ip)
    dst = state.solver.eval(state.inspect.mem_write_address)
    expr = state.inspect.mem_write_expr
    size = state.inspect.mem_write_length
    rs_transition = RuntimeStateTransition(state, RuntimeStateTransition.RST_ASSIGN, loc,
                                           assign_dst=dst, assign_expr=expr, assign_size=size)
    updated = rs_transition.update_rs_summary(rs_summary)
    if updated:
        if state.project.kb.runtime_states.reached(rs_summary, state):
            l.info("reached runtime state after assignment in 0x%x", loc)
        pass


class RuntimeStatePlugin(SimStatePlugin):

    def __init__(
        self,
        rs_transition_point=0,
        input_determined_memories=dict(),
        branch_related_memories=dict(),
        rs_related_memories=None,
        rs_window=0,
        all_concrete_values=False,
        reached=False,
        last_rs_summary=None,
        rs_depth=0,
        record_debug_info=False,
        debug_info=""
    ):
        super(RuntimeStatePlugin, self).__init__()

        self.rs_transition_point = rs_transition_point

        self.input_determined_memories = input_determined_memories
        self.branch_related_memories = branch_related_memories
        self.rs_related_memories = WindowDict(
            len_limit=rs_window) if rs_related_memories is None else rs_related_memories
        self.rs_window = rs_window
        self.all_concrete_values = all_concrete_values

        self.reached = reached

        self.last_rs_summary = last_rs_summary

        self.rs_depth = rs_depth

        self.record_debug_info = record_debug_info
        self.debug_info = debug_info

    def __hash__(self):
        return hash((
            self.rs_transition_point,
            frozenset(self.rs_related_memories.items())
        ))

    def __repr__(self):
        return "depth %d with %d memories, last transition in 0x%x" % (
            self.rs_depth,
            len(self.rs_related_memories),
            self.rs_transition_point
        )

    @SimStatePlugin.memo
    def copy(self, memo):
        return RuntimeStatePlugin(
            self.rs_transition_point,
            self.input_determined_memories.copy(),
            self.branch_related_memories.copy(),
            self.rs_related_memories.copy(),
            self.rs_window,
            self.all_concrete_values,
            self.reached,
            self.last_rs_summary,
            self.rs_depth,
            self.record_debug_info,
            self.debug_info,
        )

    def increase_depth(self):
        self.rs_depth += 1

    def update_debug_info(self, rs_transition):
        if self.record_debug_info:
            self.debug_info = rs_transition.generate_debug_info()

    @staticmethod
    def prepare_runtime_state_tracking(state, symbolic_wrap=True, switch_offset=-1, rs_window=3, in_bytes=True, record_debug_info=False):
        if state.has_plugin(plugin_name):
            runtime_state_plugin = state.get_plugin(plugin_name)
        else:
            runtime_state_plugin = RuntimeStatePlugin(rs_window=rs_window, record_debug_info=record_debug_info)
        state.register_plugin(plugin_name, runtime_state_plugin)

        # relax some limitations
        state.libc.max_str_len = 1000000
        state.libc.max_buffer_size = 0x100000
        state.libc.max_memcpy_size = 0x100000

        # disable simplification to avoid removing our memory source annotations
        state.options.remove(options.SIMPLIFY_REGISTER_WRITES)

        # set solver timeout to 10s to prevent execution from being blocked by constraint solving
        state.solver._solver.timeout = 1000 * 10

        # setup data source taint
        hooks = {
            'fgetc': procedures.libc.fgetc.fgetc(symbolic_wrap=symbolic_wrap, switch_offset=switch_offset),
            'fgets': procedures.libc.fgets.fgets(symbolic_wrap=symbolic_wrap, switch_offset=switch_offset),
            'fread': procedures.libc.fread.fread(symbolic_wrap=symbolic_wrap, switch_offset=switch_offset),
            'read': procedures.posix.read.read(symbolic_wrap=symbolic_wrap, switch_offset=switch_offset),
            'recv': procedures.posix.recv.recv(symbolic_wrap=symbolic_wrap, switch_offset=switch_offset),
            'recvfrom': procedures.posix.recvfrom.recvfrom(symbolic_wrap=symbolic_wrap, switch_offset=switch_offset),
        }

        for func, hook in hooks.items():
            symbol = state.project.loader.find_symbol(func)
            if symbol is None:
                l.warning("Fail to find symbol for %s", func)
                continue
            state.project.hook(symbol.rebased_addr, hook, replace=True)

        if switch_offset < 0:
            l.info("hook POSIX APIs, just add symbolic wrapper")
        else:
            l.info("hook POSIX APIs with symbolic switch offset %d", switch_offset)

        state.inspect.make_breakpoint(
            event_type='mem_read',
            when=BP_AFTER,
            action=annotate_memory_source,
        )
        # setup state-describing memory unit recognition and state transition monitoring
        state.inspect.make_breakpoint(
            event_type='mem_write',
            when=BP_BEFORE,
            action=track_assignment,
        )
        state.inspect.make_breakpoint(
            event_type='exit',
            when=BP_BEFORE,
            action=track_branch,
        )
