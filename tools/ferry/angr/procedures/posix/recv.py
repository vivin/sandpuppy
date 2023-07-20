import angr
from angr.sim_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# recv
######################################

class recv(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length, flags, symbolic_wrap=False, switch_offset=-1):  # pylint:disable=unused-argument
        self.argument_types = {0: SimTypeFd(),
                               1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = SimTypeLength(self.state.arch)

        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        return simfd.read(dst, length, symbolic_wrap=symbolic_wrap, switch_offset=switch_offset)
