package net.vivin.vvdump.cassandra.repository;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.cassandra.config.CassandraConfiguration;
import net.vivin.vvdump.model.VariableValueEndTrace;
import net.vivin.vvdump.model.VariableValueTrace;
import net.vivin.vvdump.repository.VariableValueTraceRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.cassandra.core.CassandraOperations;
import org.springframework.stereotype.Repository;

import java.math.BigInteger;

/**
 * Created on 12/2/20 at 8:36 PM
 *
 * @author vivin
 */

@Slf4j
@Repository("cassandra")
public class CassandraRepository implements VariableValueTraceRepository {

    @Value("${vvdump.sql.cassandra.delete-processes-query}")
    private String deleteProcessesQuery;

    @Value("${vvdump.sql.cassandra.delete-process-variable-value-traces-query}")
    private String deleteProcessVariableValueTracesQuery;

    private final CassandraOperations cassandraOperations;
    private final CassandraConfiguration cassandraConfiguration;

    @Autowired
    public CassandraRepository(CassandraOperations cassandraOperations, CassandraConfiguration cassandraConfiguration) {
        this.cassandraOperations = cassandraOperations;
        this.cassandraConfiguration = cassandraConfiguration;
    }

    private static final String PID_SUFFIX = RandomStringUtils.randomAlphabetic(6);

    @Override
    public void insertVariableValueTrace(VariableValueTrace variableValueTrace) {
        cassandraConfiguration.getTraceTableFields().forEach((table, fields) -> {
            final String query = String.format(
                "INSERT INTO %s (%s) VALUES (%s%s)",
                table,
                String.join(", ", fields),
                fields.contains("id") ? "uuid(), " : "",
                "?, ".repeat(fields.contains("id") ? fields.size() - 1 : fields.size()).replaceFirst(", $", "")
            );

            final Object[] values = fields.stream().filter(field -> !field.equals("id")).map(field -> {
                Object value = variableValueTrace.get(field);

                if (field.equals("pid")) {
                    value = String.format("%s-%s", value, PID_SUFFIX);
                } else if (value instanceof BigInteger) {
                    value = ((BigInteger) value).longValue();
                }

                return value;
            }).toArray();

            cassandraOperations.getCqlOperations().execute(query, values);
        });
    }

    @Override
    public void insertFuzzedProcessInfo(VariableValueEndTrace variableValueEndTrace) {
        cassandraConfiguration.getProcessTableFields().forEach((table, fields) -> {
            final String query = String.format(
                "INSERT INTO %s (%s) VALUES (%s%s)",
                table,
                String.join(", ", fields),
                fields.contains("id") ? "uuid(), " : "",
                "?, ".repeat(fields.contains("id") ? fields.size() - 1 : fields.size()).replaceFirst(", $", "")
            );

            final Object[] values = fields.stream().filter(field -> !field.equals("id")).map(field -> {
                Object value = variableValueEndTrace.get(field);

                if (field.equals("pid")) {
                    value = String.format("%s-%s", value, PID_SUFFIX);
                } else if (value instanceof BigInteger) {
                    value = ((BigInteger) value).longValue();
                }

                return value;
            }).toArray();

            cassandraOperations.getCqlOperations().execute(query, values);
        });

        log.info("Inserted info for pid {}", variableValueEndTrace.getPid());
    }

    @Override
    public void deleteVariableValueTraces(VariableValueEndTrace variableValueEndTrace) {
        log.info("Deleting traces for killed process {}", variableValueEndTrace.getPid());
        cassandraOperations.getCqlOperations().execute(
            deleteProcessesQuery,
            variableValueEndTrace.getExperimentName(),
            variableValueEndTrace.getSubject(),
            variableValueEndTrace.getBinaryContext(),
            variableValueEndTrace.getExecContext(),
            String.format("%d-%s", variableValueEndTrace.getPid(), PID_SUFFIX)
        );
        cassandraOperations.getCqlOperations().execute(
            deleteProcessVariableValueTracesQuery,
            String.format("%d-%s", variableValueEndTrace.getPid(), PID_SUFFIX)
        );
    }
}
