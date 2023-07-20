import logging
from timeit import default_timer as timer

import claripy
from claripy.ast import Base

from ...errors import SimSolverModeError, SimValueError

l = logging.getLogger(__name__)


class MemorySourceAnnotation(claripy.Annotation):

    def __init__(self, addr, size):
        self.addr = addr
        self.size = size

    def __repr__(self):
        s = "from memory "
        if isinstance(self.addr, int):
            s += "0x%x" % self.addr
        else:
            s += "%s" % self.addr
        s += " with size "
        if isinstance(self.size, int):
            s += "%d" % self.size
        else:
            s += "%s" % self.size
        return s

    @property
    def eliminatable(self):  # pylint:disable=no-self-use
        return False

    @property
    def relocatable(self):  # pylint:disable=no-self-use
        return True


def try_concretize(state, expr):
    if state.solver.symbolic(expr):
        return expr
    else:
        return state.solver.eval(expr)


def annotate_memory_source(state):
    begin = timer()

    addr = try_concretize(state, state.inspect.mem_read_address)
    size = try_concretize(state, state.inspect.mem_read_length)

    if len(state.inspect.mem_read_expr.annotations) > 0:
        state.inspect.mem_read_expr.annotations = tuple(
            [a for a in state.inspect.mem_read_expr.annotations if not isinstance(a, MemorySourceAnnotation)])
    state.inspect.mem_read_expr = state.inspect.mem_read_expr.annotate(MemorySourceAnnotation(addr, size))

    end = timer()
    state.project.kb.runtime_states.record_taint_overhead(end - begin)


def get_memory_sources(state, bv, extra_constraints=(), raw_data=True, timing=True):
    if not isinstance(bv, Base):
        return set()

    begin = timer()

    mem_sources = set()
    for anno in bv.annotations:
        if not isinstance(anno, MemorySourceAnnotation):
            continue

        if state.solver.symbolic(anno.addr):
            try:
                anno.addr = state.solver.eval_one(anno.addr, extra_constraints=extra_constraints)
                anno.size = state.solver.eval_one(anno.size, extra_constraints=extra_constraints)
            except (SimValueError, SimSolverModeError):
                continue

        if raw_data:
            mem_sources.add((anno.addr, anno.size))
        else:
            mem_sources.add(anno)

    if bv.depth != 1:
        for arg in bv.args:
            mem_sources.update(get_memory_sources(state, arg, timing=False))

    end = timer()
    if timing:
        state.project.kb.runtime_states.record_taint_overhead(end - begin)

    return mem_sources
