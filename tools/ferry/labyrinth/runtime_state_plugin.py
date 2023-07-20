import copy
import angr
from angr.errors import SimValueError, SimSolverModeError

import logging
l = logging.getLogger('labyrinth.runtime_state_plugin')


class RuntimeStatePlugin(angr.SimStatePlugin):

    def __init__(self, code_loc=-1, state_related_memories=None):
        super(RuntimeStatePlugin, self).__init__()

        self.code_loc = code_loc
        self.state_related_memories = dict(
        ) if state_related_memories is None else state_related_memories

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return RuntimeStatePlugin(self.code_loc, copy.deepcopy(self.state_related_memories))

    def __hash__(self):
        return hash(tuple(self.code_loc, self.state_related_memories))

    def equal(self, other):
        code_loc = other[0]
        state_related_memories = other[1]

        if self.code_loc != code_loc:
            return False

        if set(self.state_related_memories.keys()) != set(state_related_memories.keys()):
            return False

        for addr, constraint in self.state_related_memories.items():
            other_constraint = state_related_memories[addr]
            if type(constraint) != type(other_constraint):
                return False
            if type(constraint) is int:
                if constraint != other_constraint:
                    return False
            elif isinstance(constraint, list):
                if len(constraint) != len(other_constraint):
                    return False
                constraint_ids = [c._hash for c in constraint]
                other_constraint_ids = [c._hash for c in other_constraint]
                if set(constraint_ids) != set(other_constraint_ids):
                    return False
            else:
                if self.state.solver.is_false(constraint == other_constraint):
                    return False

        return True

    def update(self, code_loc, addr, size, constraint=None, assignment=None):
        changed = False

        if code_loc != self.code_loc:
            self.code_loc = code_loc
            changed = True

        mem_value = self.state.memory.load(addr, size)

        concrete_val = None
        if constraint is not None:
            try:
                concrete_val = self.state.solver.eval_one(
                    mem_value, extra_constraints=[constraint])
            except (SimValueError, SimSolverModeError):
                pass
        else:
            try:
                concrete_val = self.state.solver.eval_one(assignment)
            except (SimValueError, SimSolverModeError):
                pass

        if addr not in self.state_related_memories:
            if concrete_val is not None:
                self.state_related_memories[addr] = concrete_val
            elif constraint is not None:
                self.state_related_memories[addr] = [constraint]
            else:
                self.state_related_memories[addr] = assignment
            changed = True
            return changed

        old_val = self.state_related_memories[addr]
        if type(old_val) is int:
            if concrete_val is not None:
                if old_val != concrete_val:
                    self.state_related_memories[addr] = concrete_val
                    changed = True
            elif assignment is not None:
                self.state_related_memories[addr] = assignment
                changed = True
        elif isinstance(old_val, list):
            if concrete_val is not None:
                self.state_related_memories[addr] = concrete_val
                changed = True
            elif constraint is not None:
                constraint_ids = [c._hash for c in old_val]
                if constraint._hash not in old_val:
                    self.state_related_memories[addr].append(constraint)
                    changed = True
            else:
                self.state_related_memories[addr] = assignment
                changed = True
        else:
            if concrete_val is not None:
                self.state_related_memories[addr] = concrete_val
                changed = True
            elif constraint is not None:
                try:
                    concrete_val = self.state.solver.eval_one(
                        old_val, extra_constraints=[constraint])
                    self.state_related_memories[addr] = concrete_val
                    changed = True
                except (SimValueError, SimSolverModeError):
                    pass
            else:
                if not self.state.solver.is_true(old_val == assignment):
                    self.state_related_memories[addr] = assignment
                    changed = True

        return changed

    def export(self):
        return (self.code_loc, copy.deepcopy(self.state_related_memories))

    def pure_state(self):
        return (self.code_loc, self.state_related_memories)

#RuntimeStatePlugin.register_default('runtime_state')
