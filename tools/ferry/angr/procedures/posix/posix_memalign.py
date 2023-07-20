import angr


class posix_memalign(angr.SimProcedure):

    def run(self, memptr, alignment, size):

        alignment_ = self.state.solver.eval(alignment)
        size_ = self.state.solver.eval(size)

        current_heap = self.state.heap.heap_location
        if current_heap % alignment_ != 0:
            self.state.heap.heap_location = (current_heap // alignment_ + 1) * alignment_

        ptr = self.state.heap.heap_location
        self.state.heap.allocate(size_)

        if self.state.arch.bits == 64:
            self.state.mem[memptr].uint64_t = ptr
        else:
            self.state.mem[memptr].uint32_t = ptr

        return 0
