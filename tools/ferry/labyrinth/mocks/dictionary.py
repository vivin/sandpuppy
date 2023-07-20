import logging
import copy
from collections import defaultdict
import angr
import claripy
from ..symbol_annotation import SymbolAnnotation

l = logging.getLogger('labyrinth.mocks.dictionary')

global_storage_key_set_key = 'dictionary_set_key'
global_storage_key_find_key = 'dictionary_find_key'


def register_dictionary_global_storage(init_state):
    # key -> (type, data)
    init_state.globals[global_storage_key_set_key] = defaultdict(list)
    # key
    init_state.globals[global_storage_key_find_key] = []


class MockDictionarySetData(angr.SimProcedure):
    def run(self, this, key, type_, p_data, size):
        key_str = self.state.solver.eval(key, cast_to=str)
        type_str = self.state.solver.eval(type_, cast_to=str)
        l.info("MockDictionary::setData(key=%s, type=%s)", key_str, type_str)
        self.state.globals[global_storage_key_set_key] = copy.deepcopy(
            self.state.globals[global_storage_key_set_key])
        self.state.globals[global_storage_key_set_key][key_str].append(
            (type_, p_data, size))


class MockDictionarySetInt32(angr.SimProcedure):
    def run(self, this, key, value):
        key_str = self.state.solver.eval(key, cast_to=str)
        l.info("MockDictionary::setInt32(key=%s)", key_str)
        self.state.globals[global_storage_key_set_key] = copy.deepcopy(
            self.state.globals[global_storage_key_set_key])
        self.state.globals[global_storage_key_set_key][key_str].append(
            ('int32', value))


class MockDictionarySetInt64(angr.SimProcedure):
    def run(self, this, key, value_h, value_l):
        key_str = self.state.solver.eval(key, cast_to=str)
        l.info("MockDictionary::setInt64(key=%s)", key_str)
        self.state.globals[global_storage_key_set_key] = copy.deepcopy(
            self.state.globals[global_storage_key_set_key])
        self.state.globals[global_storage_key_set_key][key_str].append(
            ('int64', claripy.Concat(value_l, value_h)))


class MockDictionarySetCString(angr.SimProcedure):
    def run(self, this, key, p_value):
        key_str = self.state.solver.eval(key, cast_to=str)
        l.info("MockDictionary::setCString(key=%s)", key_str)
        self.state.globals[global_storage_key_set_key] = copy.deepcopy(
            self.state.globals[global_storage_key_set_key])
        self.state.globals[global_storage_key_set_key][key_str].append(
            ('cstring', p_value))


class MockDictionaryFindData(angr.SimProcedure):
    def run(self, this, key, p_type, p_p_data, p_size):
        key_str = self.state.solver.eval(key, cast_to=str)
        l.info("MockDictionary::findData(key=%s)", key_str)
        self.state.globals[global_storage_key_find_key] = copy.deepcopy(
            self.state.globals[global_storage_key_find_key])
        self.state.globals[global_storage_key_find_key].append(key_str)

        # WARN this is not a general solution
        self.state.memory.store(p_type, claripy.BVS(SymbolAnnotation.encode_parser_metadata_annotation(
            'MockDictionary::findData', 'type', self.state.solver.eval(p_type), 32), 32))
        self.state.memory.store(p_p_data, claripy.BVS(SymbolAnnotation.encode_parser_metadata_annotation(
            'MockDictionary::findData', 'data', self.state.solver.eval(p_p_data), 32), 32))
        self.state.memory.store(p_size, claripy.BVS(SymbolAnnotation.encode_parser_metadata_annotation(
            'MockDictionary::findData', 'size', self.state.solver.eval(p_size), 32), 32))

        return 1


class MockDictionaryFindInt32(angr.SimProcedure):
    def run(self, this, key, p_value):
        key_str = self.state.solver.eval(key, cast_to=str)
        l.info("MockDictionary::findInt32(key=%s)", key_str)
        self.state.globals[global_storage_key_find_key] = copy.deepcopy(
            self.state.globals[global_storage_key_find_key])
        self.state.globals[global_storage_key_find_key].append(key_str)

        self.state.memory.store(p_value, claripy.BVS(SymbolAnnotation.encode_parser_metadata_annotation(
            'MockDictionary::findInt32', 'data', self.state.solver.eval(p_value), 32), 32))
        return 1


class MockDictionaryFindInt64(angr.SimProcedure):
    def run(self, this, key, p_value):
        key_str = self.state.solver.eval(key, cast_to=str)
        l.info("MockDictionary::findInt64(key=%s)", key_str)
        self.state.globals[global_storage_key_find_key] = copy.deepcopy(
            self.state.globals[global_storage_key_find_key])
        self.state.globals[global_storage_key_find_key].append(key_str)

        self.state.memory.store(p_value, claripy.BVS(SymbolAnnotation.encode_parser_metadata_annotation(
            'MockDictionary::findInt64', 'data', self.state.solver.eval(p_value), 64), 64))
        return 1


class MockDictionaryFindCString(angr.SimProcedure):
    def run(self, this, key, p_p_value):
        key_str = self.state.solver.eval(key, cast_to=str)
        l.info("MockDictionary::findCString(key=%s)", key_str)
        self.state.globals[global_storage_key_find_key] = copy.deepcopy(
            self.state.globals[global_storage_key_find_key])
        self.state.globals[global_storage_key_find_key].append(key_str)

        self.state.memory.store(p_p_value, claripy.BVS(SymbolAnnotation.encode_parser_metadata_annotation(
            'MockDictionary::findCString', 'data', self.state.solver.eval(p_p_value), 32), 32))
        return 1
