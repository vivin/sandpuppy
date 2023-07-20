import logging
import sys
from collections import defaultdict

from ..errors import SimSolverModeError, SimValueError
from .plugin import KnowledgeBasePlugin

l = logging.getLogger(name=__name__)


def get_related_constraints(state, value):
    result = list()

    constraints = dict()
    for variables, c_list in state.solver.independent_constraints:
        for variable in variables:
            if variable in constraints:
                l.warning("duplicate variable keys")
            constraints[variable] = c_list

    for variable in value.variables:
        result.extend(constraints.get(variable, list()))

    return set(result)


class RuntimeStates(KnowledgeBasePlugin):

    def __init__(self, kb):
        # { hash(runtime_state):{ hash(concrete_values): RuntimeStateSummary } }
        self.reached_runtime_states = defaultdict(lambda: defaultdict(list))

        self.rs_roots = set()

        self.reached_state_count = 0
        self.killed_state_count = 0

        self.taint_overhead = 0

    def reached(self, new_rs_summary, state, record_runtime_tree=False):

        if len(new_rs_summary.rs_related_memories) == 0:
            l.info("evict runtime state of %s", state)
            state.runtime_state.last_rs_summary = None
            return False

        reached = True
        last_rs_summary = state.runtime_state.last_rs_summary
        memory_hash, value_hash = new_rs_summary.memory_hash, new_rs_summary.value_hash
        if memory_hash in self.reached_runtime_states:
            # l.info("known state-related memory set")
            if value_hash in self.reached_runtime_states[memory_hash]:
                state_exist = False
                if new_rs_summary.with_constraints:
                    for rs_sum in self.reached_runtime_states[memory_hash][value_hash]:
                        if self.same_memory_constraints(state.solver, new_rs_summary, rs_sum):
                            l.info("Reached RS: same symbolic constraints")
                            state.runtime_state.last_rs_summary = rs_sum
                            state_exist = True
                            break

                    if not state_exist:
                        l.info("New RS: different symbolic constraints")
                else:
                    # there should be only one rs_summary if not considering constraints
                    l.info("Reached RS: same concrete values")
                    state.runtime_state.last_rs_summary = self.reached_runtime_states[memory_hash][value_hash][0]
                    state_exist = True

                reached = state_exist
            else:
                l.info("New RS: different concrete value hash")
                reached = False
        else:
            l.info("New RS: different memory hash")
            reached = False

        if not reached:
            l.debug("Record runtime state transition")
            l.debug("From %s", last_rs_summary)
            l.debug("To %s", new_rs_summary)
            self.reached_runtime_states[memory_hash][value_hash].append(new_rs_summary)
            state.runtime_state.last_rs_summary = new_rs_summary
            self.reached_state_count += 1
        else:
            state.runtime_state.reached = True
            self.killed_state_count += 1

        # update runtime state tree
        if record_runtime_tree:
            if last_rs_summary is None:
                self.rs_roots.add(state.runtime_state.last_rs_summary)
            else:
                last_rs_summary.children.add(state.runtime_state.last_rs_summary)

        return reached

    def same_memory_constraints(self, solver, rs_sum1, rs_sum2, extra_constraints=()):
        for m, v in rs_sum1.symbolic_values.items():
            all_constraints = list(rs_sum1.constraints[m])
            all_constraints.extend(rs_sum2.constraints[m])
            if not solver.same_range(
                v, rs_sum2.symbolic_values[m],
                extra_constraints=all_constraints
            ):
                return False

        return True

    def record_taint_overhead(self, time):
        self.taint_overhead += time


KnowledgeBasePlugin.register_default('runtime_states', RuntimeStates)
