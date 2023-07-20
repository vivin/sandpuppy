import logging

import angr
from angr.sim_type import SimTypeTop
from angr.state_plugins.runtime_state_utils import (RuntimeStateSummary,
                                                    RuntimeStateTransition)

l = logging.getLogger(name=__name__)

######################################
# free
######################################


class free(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, ptr):
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}

        # update runtime state if necessary
        if self.state.has_plugin("runtime_state"):
            if self.state.solver.symbolic(ptr):
                l.warning("try to free a symbolic ptr %s", ptr)
            else:
                c_ptr = self.state.solver.eval(ptr)

                if c_ptr != 0:
                    assert(c_ptr in self.state.heap.allocated_objects)
                    rs_summary = RuntimeStateSummary(self.state)
                    rs_transition = RuntimeStateTransition(
                        self.state, RuntimeStateTransition.RST_FREE, self.addr,
                        free_ptr = c_ptr,
                        free_size = self.state.heap.allocated_objects[c_ptr],
                    )
                    updated = rs_transition.update_rs_summary(rs_summary)
                    if updated:
                        if self.state.project.kb.runtime_states.reached(rs_summary, self.state):
                            l.info("reached runtime state when free 0x%x", c_ptr)

        return self.state.heap._free(ptr)
