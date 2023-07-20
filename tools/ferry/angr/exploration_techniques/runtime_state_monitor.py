import logging

import psutil

from . import ExplorationTechnique

l = logging.getLogger(name=__name__)


class RuntimeStateMonitor(ExplorationTechnique):

    def __init__(self, min_memory=1024, deferred_stash='deferred', reached_stash='reached', memory_stash='lowmem'):
        super(RuntimeStateMonitor, self).__init__()

        if min_memory is not None:
            self.min_memory = 1024*1024*min_memory
        else:
            self.min_memory = int(psutil.virtual_memory().total * 0.05)

        self.deferred_stash = deferred_stash
        self.reached_stash = reached_stash
        self.memory_stash = memory_stash

    def setup(self, simgr):
        if self.memory_stash not in simgr.stashes:
            simgr.stashes[self.memory_stash] = []

        if self.reached_stash not in simgr.stashes:
            simgr.stashes[self.reached_stash] = []
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    def step(self, simgr, stash='active', **kwargs):

        # ignore reached states with all concrete values
        reached_states = [s for s in simgr.stashes[stash] if s.runtime_state.reached]
        real_reached_states = [s for s in reached_states if s.runtime_state.all_concrete_values]
        maybe_reached_states = [s for s in reached_states if not s.runtime_state.all_concrete_values]

        simgr.stashes[stash] = [s for s in simgr.stashes[stash] if not s.runtime_state.reached]

        if psutil.virtual_memory().available <= self.min_memory:
            l.warning("insufficient available memory :%d" % psutil.virtual_memory().available)
            simgr.move(from_stash='active', to_stash=self.memory_stash)
        else:
            if len(real_reached_states) > 0:
                simgr.stashes[self.reached_stash].extend(real_reached_states)
                l.info("Remove %d reached states with all concrete values", len(real_reached_states))
            if len(maybe_reached_states) > 0:
                for s in maybe_reached_states:
                    s.runtime_state.reached = False
                    simgr.stashes[self.deferred_stash].append(s)
                simgr.stashes[self.deferred_stash].sort(key=lambda s: s.runtime_state.rs_depth, reverse=True)
                l.info("Defer %d reached states", len(maybe_reached_states))
                l.info("Total %d states deferred", len(simgr.stashes[self.deferred_stash]))

            simgr = simgr.step(stash=stash, **kwargs)

            if len(simgr.stashes[stash]) == 0 and len(simgr.stashes[self.deferred_stash]) > 0:
                least_depth = simgr.stashes[self.deferred_stash][-1].runtime_state.rs_depth
                while len(simgr.stashes[self.deferred_stash]) > 0 \
                        and simgr.stashes[self.deferred_stash][-1].runtime_state.rs_depth == least_depth:
                    s = simgr.stashes[self.deferred_stash].pop()
                    simgr.stashes[stash].append(s)
                l.info("Run out of active state, pop reached rs state with depth %d", s.runtime_state.rs_depth)
                l.info("Total %d states deferred", len(simgr.stashes[self.deferred_stash]))

        return simgr
