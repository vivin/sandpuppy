import logging
import angr
from ..symbol_annotation import SymbolAnnotation

l = logging.getLogger('labyrinth.checks.common')

def print_stacktrace(state):
    l.info("Return to %s", state.stack_read(0, 4))
    l.info("Stack trace:")
    for addr in state.history.recent_bbl_addrs:
        l.info("\t0x%x", addr)

class CheckMemcpy(angr.SimProcedure):
    def run(self, dst, src, n):
        tags_dst = SymbolAnnotation.get_all_tags(dst)
        tags_src = SymbolAnnotation.get_all_tags(src)
        tags_n = SymbolAnnotation.get_all_tags(n)
        if len(tags_dst) > 0 or len(tags_src) > 0 or len(tags_n) > 0:
            l.info("[Bug]: User controlled memcpy(dst, src, n)")
            print_stacktrace(self.state)
            if len(tags_dst) > 0:
                l.info("dst with tags: %s", tags_dst)
            if len(tags_src) > 0:
                l.info("src with tags: %s", tags_src)
            if len(tags_n) > 0:
                l.info("n with tags: %s", tags_n)

            self.exit(-1)

        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state, self.state.addr, self.state.se.true, 'Ijk_NoHook')


class CheckMemset(angr.SimProcedure):
    def run(self, s, c, n):
        tags_s = SymbolAnnotation.get_all_tags(s)
        tags_c = SymbolAnnotation.get_all_tags(c)
        tags_n = SymbolAnnotation.get_all_tags(n)
        if len(tags_s) > 0 or len(tags_c) > 0 or len(tags_n) > 0:
            l.info("[Bug]: User controlled memset(s, c, n)")
            print_stacktrace(self.state)
            if len(tags_s) > 0:
                l.info("s with tags: %s", tags_s)
            if len(tags_c) > 0:
                l.info("c with tags: %s", tags_c)
            if len(tags_n) > 0:
                l.info("n with tags: %s", tags_n)

            self.exit(-1)

        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state, self.state.addr, self.state.se.true, 'Ijk_NoHook')


class CheckNew(angr.SimProcedure):
    def run(self, n):
        tags_n = SymbolAnnotation.get_all_tags(n)
        if len(tags_n) > 0:
            l.info("[Bug]: User controlled operator new(n)")
            print_stacktrace(self.state)
            l.info("n with tags: %s", tags_n)
            if self.state.solver.satisfiable(extra_constraints=[n == 0]):
                l.info("n can be 0")

            self.exit(-1)

        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state, self.state.addr, self.state.se.true, 'Ijk_NoHook')


class CheckNewArray(angr.SimProcedure):
    def run(self, n):
        tags_n = SymbolAnnotation.get_all_tags(n)
        if len(tags_n) > 0:
            l.info("[Bug]: User controlled operator new[](n)")
            print_stacktrace(self.state)
            l.info("n with tags: %s", tags_n)
            if self.state.solver.satisfiable(extra_constraints=[n == 0]):
                l.info("n can be 0")

            self.exit(-1)

        self.inhibit_autoret = True
        self.successors.add_successor(
            self.state, self.state.addr, self.state.se.true, 'Ijk_NoHook')