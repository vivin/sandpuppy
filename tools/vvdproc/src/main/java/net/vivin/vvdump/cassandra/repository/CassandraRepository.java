package net.vivin.vvdump.cassandra.repository;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.model.VariableValueEndTrace;
import net.vivin.vvdump.model.VariableValueTrace;
import net.vivin.vvdump.repository.VariableValueTraceRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.cassandra.core.CassandraOperations;
import org.springframework.stereotype.Repository;

/**
 * Created on 12/2/20 at 8:36 PM
 *
 * @author vivin
 */

@Slf4j
@Repository("cassandra")
public class CassandraRepository implements VariableValueTraceRepository {

    private final CassandraOperations cassandraOperations;

    @Autowired
    public CassandraRepository(CassandraOperations cassandraOperations) {
        this.cassandraOperations = cassandraOperations;
    }

    private static final String PID_SUFFIX = RandomStringUtils.randomAlphabetic(6);

    @Value("${vvdump.sql.cassandra.insert-variable-value-trace-query}")
    private String insertVariableValueTraceQuery;

    @Value("${vvdump.sql.cassandra.insert-fuzzed-process-info-query}")
    private String insertFuzzedProcessInfoQuery;

    @Value("${vvdump.sql.cassandra.delete-variable-value-traces-query}")
    private String deleteVariableValueTracesQuery;

    @Override
    public void insertVariableValueTrace(VariableValueTrace variableValueTrace) {
        cassandraOperations.getCqlOperations().execute(
            insertVariableValueTraceQuery,
            variableValueTrace.getExperimentName(),
            variableValueTrace.getSubject(),
            variableValueTrace.getBinaryContext(),
            variableValueTrace.getExecContext(),
            String.format("%d-%s", variableValueTrace.getPid(), PID_SUFFIX),
            variableValueTrace.getFilename(),
            variableValueTrace.getFunctionName(),
            variableValueTrace.getVariableType(),
            variableValueTrace.getVariableName(),
            variableValueTrace.getDeclaredLine(),
            variableValueTrace.getTimestamp().longValueExact(),
            variableValueTrace.getModifiedLine(),
            variableValueTrace.getVariableValue()
        );
        log.info("Inserted trace");
    }

    @Override
    public void insertFuzzedProcessInfo(VariableValueEndTrace variableValueEndTrace) {
        cassandraOperations.getCqlOperations().execute(
            insertFuzzedProcessInfoQuery,
            variableValueEndTrace.getExperimentName(),
            variableValueEndTrace.getSubject(),
            variableValueEndTrace.getBinaryContext(),
            variableValueEndTrace.getExecContext(),
            String.format("%d-%s", variableValueEndTrace.getPid(), PID_SUFFIX),
            variableValueEndTrace.getExitStatus(),
            variableValueEndTrace.getInputSize().longValueExact()
        );
        log.info("Inserted info for pid {}", variableValueEndTrace.getPid());
    }

    @Override
    public void deleteVariableValueTraces(VariableValueEndTrace variableValueEndTrace) {
        log.info("Deleting traces for killed process {}", variableValueEndTrace.getPid());
        cassandraOperations.getCqlOperations().execute(
            deleteVariableValueTracesQuery,
            variableValueEndTrace.getExperimentName(),
            variableValueEndTrace.getSubject(),
            variableValueEndTrace.getBinaryContext(),
            variableValueEndTrace.getExecContext(),
            String.format("%d-%s", variableValueEndTrace.getPid(), PID_SUFFIX)
        );
    }
}
