import angr

######################################
# read
######################################

class read(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length, symbolic_wrap=False, switch_offset=-1):
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        return simfd.read(dst, length, symbolic_wrap=symbolic_wrap, switch_offset=switch_offset)
