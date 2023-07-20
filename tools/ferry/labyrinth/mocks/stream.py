import logging
import copy
from collections import defaultdict
import angr
import claripy
from ..symbol_annotation import SymbolAnnotation

l = logging.getLogger('labyrinth.mocks.stream')

global_storage_key_object_source = 'stream_object_source'
global_storage_key_stream_usage = 'stream_data_usage'


def register_stream_global_storage(init_state):
    # obj_mem_addr -> (stream_offset, size)
    init_state.globals[global_storage_key_object_source] = {}
    # stream_offset -> (obj_mem_addr, size)
    init_state.globals[global_storage_key_stream_usage] = defaultdict(list)


class MockStreamReadAt(angr.SimProcedure):
    def run(self, this, offset_h, offset_l, p_dst, size):
        # TODO(shelven): Eliminate duplicate code
        offset = self.state.stack_read(8, 8)

        dst_concrete = self.state.solver.eval(p_dst)
        offset_concrete = self.state.solver.eval(offset)
        # TODO(shelven): [Security Policy]What if size can be controlled
        size_concrete = self.state.solver.eval(size) * 8
        # if size is extremely large, limit it to 32 in case of the z3solver exception
        if size_concrete > 10000:
            size_concrete = 32

        self.state.globals[global_storage_key_object_source] = copy.deepcopy(
            self.state.globals[global_storage_key_object_source])
        self.state.globals[global_storage_key_stream_usage] = copy.deepcopy(
            self.state.globals[global_storage_key_stream_usage])
        self.state.globals[global_storage_key_object_source][dst_concrete] = (
            offset_concrete, size_concrete)
        self.state.globals[global_storage_key_stream_usage][offset_concrete].append(
            (dst_concrete, size_concrete))

        # TODO(shelven): Use claripy.Annotation to store the info
        l.info("MockStream::readAt(offset=%d, size=%d bits, dst=0x%x)",
               offset_concrete, size_concrete, dst_concrete)
        symbol_name = SymbolAnnotation.encode_stream_input_annotation(
            'MockStream::readAt', offset_concrete, size_concrete, dst_concrete)
        self.state.memory.store(p_dst, claripy.BVS(symbol_name, size_concrete))
        # TODO(shelven): [Security Policy]Data stream maybe not long enough
        return size


class MockStreamGetUInt16(angr.SimProcedure):
    def run(self, this, offset_h, offset_l, p_dst):
        offset = self.state.stack_read(8, 8)

        dst_concrete = self.state.solver.eval(p_dst)
        offset_concrete = self.state.solver.eval(offset)
        size_concrete = 16

        self.state.globals[global_storage_key_object_source] = copy.deepcopy(
            self.state.globals[global_storage_key_object_source])
        self.state.globals[global_storage_key_stream_usage] = copy.deepcopy(
            self.state.globals[global_storage_key_stream_usage])
        self.state.globals[global_storage_key_object_source][dst_concrete] = (
            offset_concrete, size_concrete)
        self.state.globals[global_storage_key_stream_usage][offset_concrete].append(
            (dst_concrete, size_concrete))

        l.info("MockStream::getUInt16(offset=%d, size=%d bits, dst=0x%x)",
               offset_concrete, size_concrete, dst_concrete)
        symbol_name = SymbolAnnotation.encode_stream_input_annotation(
            'MockStream::getUInt16', offset_concrete, size_concrete, dst_concrete)
        self.state.memory.store(p_dst, claripy.BVS(symbol_name, size_concrete))
        return 1


class MockStreamGetUInt24(angr.SimProcedure):
    def run(self, this, offset_h, offset_l, p_dst):
        offset = self.state.stack_read(8, 8)

        dst_concrete = self.state.solver.eval(p_dst)
        offset_concrete = self.state.solver.eval(offset)
        size_concrete = 32

        self.state.globals[global_storage_key_object_source] = copy.deepcopy(
            self.state.globals[global_storage_key_object_source])
        self.state.globals[global_storage_key_stream_usage] = copy.deepcopy(
            self.state.globals[global_storage_key_stream_usage])
        self.state.globals[global_storage_key_object_source][dst_concrete] = (
            offset_concrete, size_concrete)
        self.state.globals[global_storage_key_stream_usage][offset_concrete].append(
            (dst_concrete, size_concrete))

        l.info("MockStream::getUInt24(offset=%d, size=%d bits, dst=0x%x)",
               offset_concrete, size_concrete, dst_concrete)
        symbol_name = SymbolAnnotation.encode_stream_input_annotation(
            'MockStream::getUInt24', offset_concrete, size_concrete, dst_concrete)
        self.state.memory.store(p_dst, claripy.BVS(symbol_name, size_concrete))
        return 1


class MockStreamGetUInt32(angr.SimProcedure):
    def run(self, this, offset_h, offset_l, p_dst):
        offset = self.state.stack_read(8, 8)

        dst_concrete = self.state.solver.eval(p_dst)
        offset_concrete = self.state.solver.eval(offset)
        size_concrete = 32

        self.state.globals[global_storage_key_object_source] = copy.deepcopy(
            self.state.globals[global_storage_key_object_source])
        self.state.globals[global_storage_key_stream_usage] = copy.deepcopy(
            self.state.globals[global_storage_key_stream_usage])
        self.state.globals[global_storage_key_object_source][dst_concrete] = (
            offset_concrete, size_concrete)
        self.state.globals[global_storage_key_stream_usage][offset_concrete].append(
            (dst_concrete, size_concrete))

        l.info("MockStream::getUInt32(offset=%d, size=%d bits, dst=0x%x)",
               offset_concrete, size_concrete, dst_concrete)
        symbol_name = SymbolAnnotation.encode_stream_input_annotation(
            'MockStream::getUInt32', offset_concrete, size_concrete, dst_concrete)
        self.state.memory.store(p_dst, claripy.BVS(symbol_name, size_concrete))
        return 1


class MockStreamGetUInt64(angr.SimProcedure):
    def run(self, this, offset_h, offset_l, p_dst):
        offset = self.state.stack_read(8, 8)

        dst_concrete = self.state.solver.eval(p_dst)
        offset_concrete = self.state.solver.eval(offset)
        size_concrete = 64

        self.state.globals[global_storage_key_object_source] = copy.deepcopy(
            self.state.globals[global_storage_key_object_source])
        self.state.globals[global_storage_key_stream_usage] = copy.deepcopy(
            self.state.globals[global_storage_key_stream_usage])
        self.state.globals[global_storage_key_object_source][dst_concrete] = (
            offset_concrete, size_concrete)
        self.state.globals[global_storage_key_stream_usage][offset_concrete].append(
            (dst_concrete, size_concrete))

        l.info("MockStream::getUInt64(offset=%d, size=%d bits, dst=0x%x)",
               offset_concrete, size_concrete, dst_concrete)
        symbol_name = SymbolAnnotation.encode_stream_input_annotation(
            'MockStream::getUInt64', offset_concrete, size_concrete, dst_concrete)
        self.state.memory.store(p_dst, claripy.BVS(symbol_name, size_concrete))
        return 1
