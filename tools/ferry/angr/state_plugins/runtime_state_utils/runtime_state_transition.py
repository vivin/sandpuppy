import logging

from .memory_source_annotation import get_memory_sources
from .runtime_state_summary import RuntimeStateSummary
from .window_dict import WindowDict

l = logging.getLogger(name=__name__)

STACK_BOTTOM = 0x7ffffffffff0000
STACK_TOP = 0x700000000000000
HEAP_BOTTOM = 0xc0000000
HEAP_TOP = STACK_TOP

RST_BRANCH = 'RST_BRANCH'
RST_INDIRECT_JUMP = 'RST_INDIRECT_JUMP'
RST_RETURN = 'RST_RETURN'
RST_ASSIGN = 'RST_ASSIGN'
RST_FREE = 'RST_FREE'

state_transition_attributes = [
    'branch_guard',

    'indirect_jump_cond',
    'indirect_jump_target',

    'return_target',
    'return_stack_pointer',

    'assign_dst',
    'assign_expr',
    'assign_size',

    'free_ptr',
    'free_size',
]


def _ensure_satisfiable(state, extra_constraints=()):
    return state.solver.satisfiable(extra_constraints=extra_constraints)


class RuntimeStateTransition:

    RST_BRANCH = RST_BRANCH
    RST_INDIRECT_JUMP = RST_INDIRECT_JUMP
    RST_RETURN = RST_RETURN
    RST_ASSIGN = RST_ASSIGN
    RST_FREE = RST_FREE

    def __init__(self, state, transition_type, rs_transition_loc, **kwargs):
        self.state = state

        if transition_type not in (RST_BRANCH, RST_INDIRECT_JUMP, RST_RETURN, RST_ASSIGN, RST_FREE):
            raise ValueError("Invalid state transition type %s passed in" % transition_type)
        self.transition_type = transition_type

        self.rs_transition_loc = rs_transition_loc

        for k, v in kwargs.items():
            if k not in state_transition_attributes:
                raise ValueError("Invalid state transition attribute %s passed in. Should be one of: %s" %
                                 (k, state_transition_attributes))
            setattr(self, k, v)

    def _update_transition_point(self, rs_summary):
        rs_summary.rs_transition_point = self.rs_transition_loc
        self.state.runtime_state.rs_transition_point = self.rs_transition_loc

    def _incoming_constraint(self, rs_summary, new_constraint):
        if not _ensure_satisfiable(self.state, (new_constraint,)):
            return False

        metadata_update = False
        for addr, size in get_memory_sources(self.state, new_constraint, extra_constraints=(new_constraint,)):
            if addr in rs_summary.rs_related_memories:
                l.info("branch involves state-related memory 0x%x with size %s at 0x%x", addr, size, self.rs_transition_loc)

                if self.rs_transition_loc != rs_summary.rs_transition_point:
                    l.info("transition by new state transition point at 0x%x", self.rs_transition_loc)
                    self._update_transition_point(rs_summary)
                    metadata_update = True

                if size > rs_summary.rs_related_memories[addr]:
                    l.info("transition by size extention at 0x%x", self.rs_transition_loc)
                    self.state.runtime_state.rs_related_memories[addr] = size
                    self.state.runtime_state.rs_related_memories.access_count[addr] += 1
                    rs_summary.rs_related_memories[addr] = size
                    metadata_update = True

            elif addr not in self.state.runtime_state.branch_related_memories \
                    or (addr in self.state.runtime_state.branch_related_memories
                        and size > self.state.runtime_state.branch_related_memories[addr]):
                l.info("new branch-related memory 0x%x by branch at 0x%x", addr, self.rs_transition_loc)
                self.state.runtime_state.branch_related_memories[addr] = size
                if addr in self.state.runtime_state.input_determined_memories:
                    l.info("new state-related memory 0x%x by branch at 0x%x", addr, self.rs_transition_loc)
                    l.info("transition by new state-related memory at 0x%x", self.rs_transition_loc)

                    max_size = max(size, self.state.runtime_state.input_determined_memories[addr])
                    self.state.runtime_state.rs_related_memories[addr] = max_size
                    self.state.runtime_state.rs_related_memories.access_count[addr] += 1
                    rs_summary.rs_related_memories[addr] = max_size

                    self._update_transition_point(rs_summary)
                    metadata_update = True

        value_update = False
        concrete_values, symbolic_values, constraints = RuntimeStateSummary.extract_rs_related_values(
            self.state,
            concretize=rs_summary.concretize,
            with_constraints=rs_summary.with_constraints,
            extra_constraints=(new_constraint,)
        )
        if metadata_update \
                or concrete_values.keys() != rs_summary.concrete_values.keys() \
                or symbolic_values.keys() != rs_summary.symbolic_values.keys():
            value_update = True
        elif self.state.solver.will_change(new_constraint):
            # compare each value and constraints
            for m, v in concrete_values.items():
                if v != rs_summary.concrete_values[m]:
                    value_update = True
                    break

            if not value_update and rs_summary.with_constraints:
                for m, v in symbolic_values.items():
                    # we don't need to consider guard now since it's already in constraints
                    all_constraints = list(constraints[m])
                    all_constraints.extend(rs_summary.constraints[m])
                    if not self.state.solver.same_range(  # since all constraints are independent, any solver will work here
                        v, rs_summary.symbolic_values[m],
                        extra_constraints=all_constraints
                    ):
                        value_update = True
                        break

        if value_update:
            l.info("transition by value change at 0x%x", self.rs_transition_loc)
            rs_summary.concrete_values, rs_summary.symbolic_values, rs_summary.constraints = \
                concrete_values, symbolic_values, constraints
            self.state.runtime_state.all_concrete_values = len(
                rs_summary.concrete_values) == len(rs_summary.rs_related_memories)

        if metadata_update or value_update:
            l.info("runtime state transition %s at 0x%x", self.transition_type, self.rs_transition_loc)
            self.state.runtime_state.increase_depth()
            self.state.runtime_state.update_debug_info(self)

        return metadata_update or value_update

    def _update_by_branch(self, rs_summary):
        return self._incoming_constraint(rs_summary, self.branch_guard)

    def _update_by_indirect_jump(self, rs_summary):
        return self._incoming_constraint(rs_summary, self.indirect_jump_cond)

    def _update_by_single_assign(self, rs_summary, offset, size):
        metadata_update = False
        need_value_update = False
        addr = self.assign_dst + offset
        value = self.state.solver.simplify(self.state.solver.Extract(
            offset * 8 + size * 8 - 1, offset * 8, self.assign_expr))
        if addr in rs_summary.rs_related_memories:
            l.info("assignment to state-related memory 0x%x at 0x%x", addr, self.rs_transition_loc)
            if self.rs_transition_loc != rs_summary.rs_transition_point:
                l.info("transition by new state transition point at 0x%x", self.rs_transition_loc)
                self._update_transition_point(rs_summary)
                metadata_update = True

            if size > rs_summary.rs_related_memories[addr]:
                l.info("transition by size extention at 0x%x", self.rs_transition_loc)
                self.state.runtime_state.rs_related_memories[addr] = size
                self.state.runtime_state.rs_related_memories.access_count[addr] += 1
                rs_summary.rs_related_memories[addr] = size
                metadata_update = True
                need_value_update = True

        else:
            tainted = False
            if addr not in self.state.runtime_state.input_determined_memories:
                # check whether to update the state-related memories
                for v in value.variables:
                    if v.startswith('filewrap'):
                        tainted = True
                        break
            elif size > self.state.runtime_state.input_determined_memories[addr]:
                tainted = True

            if tainted:
                l.info("new input-determined memory 0x%x by assignment at 0x%x with size %d",
                       addr, self.rs_transition_loc, size)
                self.state.runtime_state.input_determined_memories[addr] = size
                if addr in self.state.runtime_state.branch_related_memories:
                    l.info("new state-related memory 0x%x by assignment at 0x%x", addr, self.rs_transition_loc)
                    l.info("transition by new state-related memory at 0x%x", self.rs_transition_loc)

                    max_size = max(size, self.state.runtime_state.input_determined_memories[addr])
                    self.state.runtime_state.rs_related_memories[addr] = max_size
                    self.state.runtime_state.rs_related_memories.access_count[addr] += 1
                    rs_summary.rs_related_memories[addr] = max_size

                    self._update_transition_point(rs_summary)
                    metadata_update = True
                    need_value_update = True

        if need_value_update:
            rs_summary.concrete_values, rs_summary.symbolic_values, rs_summary.constraints = RuntimeStateSummary.extract_rs_related_values(
                self.state,
                concretize=rs_summary.concretize,
                with_constraints=rs_summary.with_constraints,
            )
            self.state.runtime_state.all_concrete_values = len(
                rs_summary.concrete_values) == len(rs_summary.rs_related_memories)

        return metadata_update

    def _update_by_assign(self, rs_summary):
        if self.state.solver.symbolic(self.assign_size):
            l.warning("symbolic size in _update_by_assign(), use default value")
            assign_size = RuntimeStateSummary.DEFAULT_MEMORY_SIZE
        else:
            assign_size = self.state.solver.eval(self.assign_size)

        update = False
        for offset in range(0, assign_size - 1, RuntimeStateSummary.DEFAULT_MEMORY_SIZE):
            update = update or self._update_by_single_assign(rs_summary, offset, min(
                assign_size - offset, RuntimeStateSummary.DEFAULT_MEMORY_SIZE))

        if update:
            l.info("runtime state transition %s at 0x%x", self.transition_type, self.rs_transition_loc)
            self.state.runtime_state.increase_depth()
            self.state.runtime_state.update_debug_info(self)

        return update

    def _invalidate_outdated_memories(self, filtered, rs_summary):
        metadata_update = False
        rs_related_memories = WindowDict(len_limit=rs_summary.rs_window)
        for addr, size in rs_summary.rs_related_memories.items():
            if not filtered(addr):
                rs_related_memories[addr] = size
            else:
                l.info("invalidate state-related memory 0x%x by %s", addr, self.transition_type)
                rs_summary.concrete_values.pop(addr, None)
                rs_summary.symbolic_values.pop(addr, None)
                rs_summary.constraints.pop(addr, None)
                metadata_update = True
        rs_summary.rs_related_memories = rs_related_memories
        self.state.runtime_state.all_concrete_values = len(
            rs_summary.concrete_values) == len(rs_summary.rs_related_memories)

        self.state.runtime_state.input_determined_memories = {
            m: v for m, v in self.state.runtime_state.input_determined_memories.items()
            if not filtered(m)
        }
        self.state.runtime_state.branch_related_memories = {
            m: v for m, v in self.state.runtime_state.branch_related_memories.items()
            if not filtered(m)
        }
        self.state.runtime_state.rs_related_memories = rs_related_memories.copy()

        return metadata_update

    def _update_by_return(self, rs_summary):  # we assume stack can never grow over this
        assert(self.return_stack_pointer > STACK_TOP)

        def filtered(m): return m <= self.return_stack_pointer and m >= STACK_TOP

        metadata_update = self._invalidate_outdated_memories(filtered, rs_summary)

        if metadata_update:
            self._update_transition_point(rs_summary)
            l.info("runtime state transition %s at 0x%x", self.transition_type, self.rs_transition_loc)
            self.state.runtime_state.increase_depth()
            self.state.runtime_state.update_debug_info(self)

        return metadata_update

    def _update_by_free(self, rs_summary):
        def filtered(m): return m >= self.free_ptr and m < self.free_ptr + self.free_size

        metadata_update = self._invalidate_outdated_memories(filtered, rs_summary)

        if metadata_update:
            self._update_transition_point(rs_summary)
            l.info("runtime state transition %s at 0x%x", self.transition_type, self.rs_transition_loc)
            self.state.runtime_state.increase_depth()
            self.state.runtime_state.update_debug_info(self)

        return metadata_update

    def update_rs_summary(self, rs_summary):
        '''
        Update runtime state summary, and return whether it has been updated
        '''

        if self.transition_type == RST_BRANCH:
            return self._update_by_branch(rs_summary)
        elif self.transition_type == RST_INDIRECT_JUMP:
            return self._update_by_indirect_jump(rs_summary)
        elif self.transition_type == RST_RETURN:
            return self._update_by_return(rs_summary)
        elif self.transition_type == RST_ASSIGN:
            return self._update_by_assign(rs_summary)
        elif self.transition_type == RST_FREE:
            return self._update_by_free(rs_summary)
        else:
            l.warning("unknown runtime state transition type %s at 0x%x", self.transition_type, self.rs_transition_loc)
            return False

    def generate_debug_info(self):
        template = """Runtime state transition type: %s
IP: %s
Stack info:
    RBP: %s
    RSP: %s
Registers:
    RAX: %s
    RBX: %s
    RCX: %s
    RDX: %s
    RSI: %s
    RDI: %s
    R8: %s
    R9: %s
"""
        debug_info = template % (
            self.transition_type,
            self.state.ip if not self.state.solver.symbolic(
                self.state.ip) else hex(self.state.solver.eval(self.state.ip)),
            self.state.regs.rbp, self.state.regs.rsp,
            self.state.regs.rax, self.state.regs.rbx, self.state.regs.rcx, self.state.regs.rdx,
            self.state.regs.rsi, self.state.regs.rdi, self.state.regs.r8, self.state.regs.r9,
        )

        stack_base = self.state.solver.eval(self.state.regs.rbp)
        if self.transition_type == RST_ASSIGN:
            debug_info += "Assign expr: %s\n" % self.assign_expr
            debug_info += "Assign expr memory sources: %s\n" % [(hex(addr), hex(stack_base - addr))
                                                                for addr, _ in get_memory_sources(self.state, self.assign_expr)]
            debug_info += "Potential expr values: %s\n" % self.state.solver.eval_upto(self.assign_expr, 5)
            debug_info += "Assign dst: %s\n" % hex(self.assign_dst)
        elif self.transition_type == RST_BRANCH:
            debug_info += "Branch constraint: %s\n" % self.branch_guard
            debug_info += "Branch constraint op: %s\n" % self.branch_guard.op
            for i in range(len(self.branch_guard.args)):
                debug_info += "Potential value for argument [%d]: %s\n" % (
                    i, self.state.solver.eval_upto(self.branch_guard.args[i], 5))
            debug_info += "Branch constraint memory sources: %s\n" % [(hex(addr), hex(stack_base - addr)) for addr, _ in get_memory_sources(
                self.state, self.branch_guard, extra_constraints=(self.branch_guard,))]

        return debug_info
