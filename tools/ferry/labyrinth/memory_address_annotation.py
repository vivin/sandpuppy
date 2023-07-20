import claripy

class MemoryAddressAnnotation(claripy.Annotation):

    def __init__(self, mem_addr, size):
        self.mem_addr = mem_addr
        self.size = size

    def __hash__(self):
        return hash(repr(self))

    def __repr__(self):
        s = "mem_addr_0x%x_size_%s" % (self.mem_addr, hash(self.size))
        return s

    def __eq__(self, other):
        if not isinstance(other, MemoryAddressAnnotation):
            return False
        return self.mem_addr == other.mem_addr and self.size == other.size

    @property
    def eliminatable(self): #pylint:disable=no-self-use
        return False

    @property
    def relocatable(self): #pylint:disable=no-self-use
        return True
