from ...errors import SimSolverModeError, SimValueError


class RuntimeStateSummary:

    DEFAULT_MEMORY_SIZE = 4  # bytes

    def __init__(self, state, concretize=True, with_constraints=False):
        self.concretize = concretize
        self.with_constraints = with_constraints

        self.rs_transition_point = state.runtime_state.rs_transition_point
        self.rs_related_memories = state.runtime_state.rs_related_memories.copy()
        self.rs_window = state.runtime_state.rs_window

        self.concrete_values, self.symbolic_values, self.constraints = RuntimeStateSummary.extract_rs_related_values(
            state,
            concretize=concretize,
            with_constraints=with_constraints
        )

        # record runtime state tree
        self.parents = set()
        self.children = set()

    def __repr__(self):
        res = "<Runtime State Transition at 0x%x>" % self.rs_transition_point

        line_template = "\n\t\t0x%x: %s"

        for m, v in self.concrete_values.items():
            res += line_template % (m, v)

        if self.with_constraints:
            for m, v in self.symbolic_values.items():
                res += line_template % (m, v)
            res += "\tConstraints:\n"
            for m, v in self.constraints.items():
                res += line_template % (m, v)

        return res

    @property
    def memory_hash(self):
        return hash((
            self.rs_transition_point,
            frozenset(self.rs_related_memories.items())
        ))

    @property
    def value_hash(self):
        return hash(frozenset(self.concrete_values.items()))

    @staticmethod
    def extract_rs_related_values(state, concretize=True, with_constraints=False, extra_constraints=()):
        concrete_values = dict()
        symbolic_values = dict()
        constraints = dict()
        for m, size in state.runtime_state.rs_related_memories.items():
            v = state.memory.load(m, size, disable_actions=True, inspect=False)
            if state.solver.symbolic(v):
                concretized = False
                if concretize:
                    try:
                        c_value = state.solver.eval_one(v, extra_constraints=extra_constraints)
                        state.add_constraints(v == c_value)
                        concrete_values[m] = c_value
                        concretized = True
                    except (SimValueError, SimSolverModeError):
                        pass

                if with_constraints and not concretized:
                    r_expr, r_constraints = state.solver.replace_all_variables(v, extra_constraints=extra_constraints)
                    symbolic_values[m] = r_expr
                    constraints[m] = set(r_constraints)
            else:
                concrete_values[m] = state.solver.eval(v)

        return concrete_values, symbolic_values, constraints
