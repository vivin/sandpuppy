package net.vivin.vvdump.repository;

import net.vivin.vvdump.model.VariableValueEndTrace;
import net.vivin.vvdump.model.VariableValueTrace;

/**
 * Created on 12/2/20 at 10:18 PM
 *
 * @author vivin
 */
public interface VariableValueTraceRepository {
    void insertVariableValueTrace(VariableValueTrace variableValueTrace);
    void insertFuzzedProcessInfo(VariableValueEndTrace variableValueEndTrace);
    void deleteVariableValueTraces(VariableValueEndTrace variableValueEndTrace);
}
