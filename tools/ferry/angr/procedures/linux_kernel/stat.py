import angr

class stat(angr.SimProcedure):

    def run(self, file_path, stat_buf):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        if self.state.fs.concrete_fs:
            f_strlen = self.inline_call(strlen, file_path)
            f_expr = self.state.memory.load(file_path, f_strlen.max_null_index, endness='Iend_BE')
            stat = self.state.fs.stat(self.state.solver.eval(f_expr, cast_to=bytes))
            self._store_real_amd64(stat_buf, stat)
        else:
            # this is a dummy for now
            stat = self.state.posix.fstat(0)
            # TODO: make arch-neutral
            self._store_amd64(stat_buf, stat)
        return 0

    def _store_amd64(self, stat_buf, stat):
        store = lambda offset, val: self.state.memory.store(stat_buf + offset, val, endness='Iend_LE')

        store(0x00, stat.st_dev)
        store(0x08, stat.st_ino)
        store(0x10, stat.st_nlink)
        store(0x18, stat.st_mode)
        store(0x1c, stat.st_uid)
        store(0x20, stat.st_gid)
        store(0x24, self.state.solver.BVV(0, 32))
        store(0x28, stat.st_rdev)
        store(0x30, stat.st_size)
        store(0x38, stat.st_blksize)
        store(0x40, stat.st_blocks)
        store(0x48, stat.st_atime)
        store(0x50, stat.st_atimensec)
        store(0x58, stat.st_mtime)
        store(0x60, stat.st_mtimensec)
        store(0x68, stat.st_ctime)
        store(0x70, stat.st_ctimensec)
        store(0x78, self.state.solver.BVV(0, 64))
        store(0x80, self.state.solver.BVV(0, 64))
        store(0x88, self.state.solver.BVV(0, 64))

    def _store_real_amd64(self, stat_buf, stat):
        store = lambda offset, val: self.state.memory.store(stat_buf + offset, val, endness='Iend_LE')

        store(0x00, stat.st_dev)
        store(0x08, stat.st_ino)
        store(0x10, stat.st_nlink)
        store(0x18, stat.st_mode)
        store(0x1c, stat.st_uid)
        store(0x20, stat.st_gid)
        store(0x24, self.state.solver.BVV(0, 32))
        store(0x28, stat.st_rdev)
        store(0x30, stat.st_size)
        store(0x38, stat.st_blksize)
        store(0x40, stat.st_blocks)
        store(0x48, int(stat.st_atime))
        store(0x50, stat.st_atime_ns)
        store(0x58, int(stat.st_mtime))
        store(0x60, stat.st_mtime_ns)
        store(0x68, int(stat.st_ctime))
        store(0x70, stat.st_ctime_ns)
        store(0x78, self.state.solver.BVV(0, 64))
        store(0x80, self.state.solver.BVV(0, 64))
        store(0x88, self.state.solver.BVV(0, 64))
