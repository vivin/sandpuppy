package net.vivin.vvdump.postgres.repository;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.model.VariableValueEndTrace;
import net.vivin.vvdump.model.VariableValueTrace;
import net.vivin.vvdump.repository.VariableValueTraceRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.transaction.Transactional;

/**
 * Created on 11/10/20 at 11:40 AM
 *
 * @author vivin
 */

@Slf4j
@Repository("postgres")
public class PostgresRepository implements VariableValueTraceRepository {

    private static final String PID_SUFFIX = RandomStringUtils.randomAlphabetic(6);

    @Value("${vvdump.sql.postgres.insert-variable-value-trace-query}")
    private String insertVariableValueTraceQuery;

    @Value("${vvdump.sql.postgres.insert-fuzzed-process-info-query}")
    private String insertFuzzedProcessInfoQuery;

    @Value("${vvdump.sql.postgres.delete-variable-value-traces-query}")
    private String deleteVariableValueTracesQuery;

    @PersistenceContext
    private EntityManager entityManager;

    @Transactional
    @Override
    public void insertVariableValueTrace(VariableValueTrace variableValueTrace) {
        entityManager.createNativeQuery(insertVariableValueTraceQuery)
            .setParameter(1, variableValueTrace.getExperimentName())
            .setParameter(2, variableValueTrace.getSubject())
            .setParameter(3, variableValueTrace.getBinaryContext())
            .setParameter(4, variableValueTrace.getExecContext())
            .setParameter(5, String.format("%d-%s", variableValueTrace.getPid(), PID_SUFFIX))
            .setParameter(6, variableValueTrace.getFilename())
            .setParameter(7, variableValueTrace.getFunctionName())
            .setParameter(8, variableValueTrace.getVariableName())
            .setParameter(9, variableValueTrace.getDeclaredLine())
            .setParameter(10, variableValueTrace.getModifiedLine())
            .setParameter(11, variableValueTrace.getTimestamp())
            .setParameter(12, variableValueTrace.getVariableType())
            .setParameter(13, variableValueTrace.getVariableValue())
            .executeUpdate();

        //log.info("Inserted trace");
    }

    @Transactional
    @Override
    public void insertFuzzedProcessInfo(VariableValueEndTrace variableValueEndTrace) {
        entityManager.createNativeQuery(insertFuzzedProcessInfoQuery)
            .setParameter(1, variableValueEndTrace.getExperimentName())
            .setParameter(2, variableValueEndTrace.getSubject())
            .setParameter(3, variableValueEndTrace.getBinaryContext())
            .setParameter(4, variableValueEndTrace.getExecContext())
            .setParameter(5, String.format("%d-%s", variableValueEndTrace.getPid(), PID_SUFFIX))
            .setParameter(6, variableValueEndTrace.getExitStatus())
            .setParameter(7, variableValueEndTrace.getInputSize())
            .executeUpdate();

        //log.info("Inserted info for pid {}", variableValueEndTrace.getPid());
    }

    @Transactional
    @Override
    public void deleteVariableValueTraces(VariableValueEndTrace variableValueEndTrace) {
        log.info("Deleting traces for killed process {}", variableValueEndTrace.getPid());
        entityManager.createNativeQuery(deleteVariableValueTracesQuery)
            .setParameter(1, String.format("%d-%s", variableValueEndTrace.getPid(), PID_SUFFIX))
            .executeUpdate();
    }
}
