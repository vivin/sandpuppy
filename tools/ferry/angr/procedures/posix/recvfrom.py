import angr

######################################
# recvfrom
######################################

class recvfrom(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, fd, dst, length, flags, src_addr, addrlen, symbolic_wrap=False, switch_offset=-1):
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        return simfd.read(dst, length, symbolic_wrap=symbolic_wrap, switch_offset=switch_offset)
