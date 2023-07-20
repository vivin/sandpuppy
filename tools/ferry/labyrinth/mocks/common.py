import logging
import angr

l = logging.getLogger('labyrinth.mocks.common')


class MockDoNothing(angr.SimProcedure):
    def run(self, extra_logs=[]):
        l.info("MockCommon::doNothing()")
        if extra_logs:
            for log in extra_logs:
                l.info(log)
        return


class MockReturnTrue(angr.SimProcedure):
    def run(self, extra_logs=[]):
        l.info("MockCommon::returnTrue()")
        if extra_logs:
            for log in extra_logs:
                l.info(log)
        return 1


class MockReturnZero(angr.SimProcedure):
    def run(self, extra_logs=[]):
        l.info("MockCommon::returnZero()")
        if extra_logs:
            for log in extra_logs:
                l.info(log)
        return 0
