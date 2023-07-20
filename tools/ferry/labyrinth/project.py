import logging
import os
import time
import pickle
import angr

l = logging.getLogger('labyrinth.project')


class Project(object):
    """
    This is the main class of labyrinth module.

    :param name:            The name of the project, which will determine the cache file.
    :param target_file:     The path to the file to analyze.
    """

    def __init__(self, name, target_file, **kwargs):
        self.name = name
        self.target_file = target_file
        l.info("Loading target file...")
        cache_file = 'cache-' + name
        if os.path.exists(cache_file):
            # use pickle cache to accelerate loading progress
            with open(cache_file, 'rb') as f:
                self.project = pickle.load(f)
        else:
            self.project = angr.Project(
                self.target_file,
                **kwargs
            )
            with open(cache_file, 'wb') as f:
                pickle.dump(self.project, f)

        # l.info("Generating control flow graph...")
        # self.cfg = self.project.analyses.CFGFast(
        #     regions=[(self.project.loader.main_object.min_addr,
        #               self.project.loader.main_object.max_addr)],
        #     normalize=True,
        #     start_at_entry=False,
        #     show_progressbar=True,
        # )

        # l.info("Generating loop-related info...")
        # self.loop_info = self.project.analyses.LoopFinder(normalize=True)

    def setup_hooks(self, func_hooks, raw_hooks={}):
        for addr, hook in func_hooks.items():
            if isinstance(addr, str):
                addr = self.project.loader.find_symbol(addr).rebased_addr
            self.project.hook(addr, hook)

        for addr, hook in raw_hooks.items():
            self.project.hook(addr, hook)

    def setup_initial_state(self, initialization):
        """
        :param init_func: a function takes angr.Project as argument and do all the initialization work

        :returns: A fully initialized state.
        :rtype: angr.SimState
        """
        return initialization.setup_init_state(self.project)

    def instrument(self, init_state, inspects):
        for (event_type, when, condition, action) in inspects:
            init_state.inspect.make_breakpoint(
                event_type=event_type,
                when=when,
                condition=condition,
                action=action)

    def run_simulation(self, init_state, exploration_techniques=[]):
        simgr = self.project.factory.simgr(
            init_state,
            save_unconstrained=True
        )

        for technique in exploration_techniques:
            simgr.use_technique(technique)

        prev_state_count = 0
        prev_state_addrs = []
        while len(simgr.active) > 0:
            state_predecessors = [s.history.recent_bbl_addrs[-1]
                                  for s in simgr.active]
            for addr in prev_state_addrs:
                if addr in state_predecessors:
                    state_predecessors.remove(addr)
            l.info("[Simgr]: %s, %d more active states",
                   simgr, len(simgr.active) - prev_state_count)
            if len(state_predecessors) > 0:
                for addr in state_predecessors:
                    l.info("\t0x%x", addr)
            prev_state_count = len(simgr.active)
            prev_state_addrs = [s.addr for s in simgr.active]
            simgr.step()
