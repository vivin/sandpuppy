package net.vivin.vvdump.repository;

import net.vivin.vvdump.model.EndTraceMessage;
import net.vivin.vvdump.model.TraceItem;

/**
 * Created on 12/2/20 at 10:18 PM
 *
 * @author vivin
 */
public interface VariableValueTraceRepository {
    void insertVariableValueTrace(TraceItem variableValueTrace);
    void insertFuzzedProcessInfo(EndTraceMessage variableValueEndTrace);
    void deleteVariableValueTraces(EndTraceMessage variableValueEndTrace);
}
