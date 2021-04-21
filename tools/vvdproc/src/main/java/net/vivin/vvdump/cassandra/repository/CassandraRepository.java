package net.vivin.vvdump.cassandra.repository;

import com.datastax.dse.driver.api.core.cql.reactive.ReactiveResultSet;
import com.datastax.oss.driver.api.core.CqlSession;
import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.cassandra.config.CassandraConfiguration;
import net.vivin.vvdump.model.Entity;
import net.vivin.vvdump.model.FullTraceItem;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.cassandra.core.CassandraOperations;
import org.springframework.data.cassandra.core.CassandraTemplate;
import org.springframework.stereotype.Repository;

import javax.annotation.PreDestroy;
import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Created on 12/2/20 at 8:36 PM
 *
 * @author vivin
 */

@Slf4j
@Repository
public class CassandraRepository {

    private final CqlSession cqlSession;
    private final CassandraOperations cassandraOperations;
    private final CassandraConfiguration cassandraConfiguration;

    private final AtomicLong inserts = new AtomicLong(0);
    private final AtomicLong numTraces = new AtomicLong(0);
    private final ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();

    @Autowired
    public CassandraRepository(CqlSession cqlSession, CassandraConfiguration cassandraConfiguration) {
        this.cqlSession = cqlSession;
        this.cassandraOperations = new CassandraTemplate(cqlSession);
        this.cassandraConfiguration = cassandraConfiguration;
    }

    private static final String PID_SUFFIX = RandomStringUtils.randomAlphabetic(6);

    public void insertFullTraceItem(FullTraceItem fullTraceItem) {
        cassandraConfiguration.getTraceTableFields().forEach((table, fields) ->
            insertEntity(fullTraceItem, table, fields)
        );
    }

    private ReactiveResultSet reactiveInsertEntity(Entity entity, String table, List<String> fields) {
        final String query = getInsertQuery(table, fields);
        final Object[] values = getEntityValues(entity, fields);

        if (inserts.incrementAndGet() % cassandraConfiguration.getTraceTableFields().size() == 0) {
            numTraces.decrementAndGet();
        }

        return cqlSession.executeReactive(query, values);
    }

    private void insertEntity(Entity entity, String table, List<String> fields) {
        final String query = getInsertQuery(table, fields);
        final Object[] values = getEntityValues(entity, fields);

        cassandraOperations.getCqlOperations().execute(query, values);
    }

    private String getInsertQuery(String table, List<String> fields) {
        return String.format(
            "INSERT INTO %s (%s) VALUES (%s%s)",
            table,
            String.join(", ", fields),
            fields.contains("id") ? "uuid(), " : "",
            "?, ".repeat(fields.contains("id") ? fields.size() - 1 : fields.size()).replaceFirst(", $", "")
        );
    }

    private Object[] getEntityValues(Entity entity, List<String> fields) {
        return fields.stream().filter(field -> !field.equals("id")).map(field -> {
            Object value = entity.get(field);

            if (field.equals("pid")) {
                value = String.format("%s-%s", value, PID_SUFFIX);
            } else if (value instanceof BigInteger) {
                value = ((BigInteger) value).longValue();
            }

            return value;
        }).toArray();
    }

    @PreDestroy
    public void destroy() {
        executorService.shutdownNow();
    }
}
