package net.vivin.vvdump.cassandra.repository;

import com.datastax.dse.driver.api.core.cql.reactive.ReactiveResultSet;
import com.datastax.oss.driver.api.core.CqlSession;
import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.cassandra.config.CassandraConfiguration;
import net.vivin.vvdump.model.EndTraceMessage;
import net.vivin.vvdump.model.Entity;
import net.vivin.vvdump.model.FullTraceItem;
import net.vivin.vvdump.model.TraceItem;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.cassandra.core.CassandraOperations;
import org.springframework.data.cassandra.core.CassandraTemplate;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Created on 12/2/20 at 8:36 PM
 *
 * @author vivin
 */

@Slf4j
@Repository("cassandra")
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

    @PostConstruct
    public void init() {
        /*executorService.scheduleAtFixedRate(
            () -> log.info("{} traces remaining to be reconciled", numTraces.get()),
            0,
            5,
            TimeUnit.SECONDS
        );*/
    }

    private static final String PID_SUFFIX = RandomStringUtils.randomAlphabetic(6);

    public void insertRawTraceItem(int pid, String traceItem) {
        final String query = "INSERT INTO raw_traces (id, pid, trace_item) VALUES (uuid(), ?, ?)";
        cassandraOperations.getCqlOperations().execute(query, String.format("%s-%s", pid, PID_SUFFIX), traceItem);
        numTraces.incrementAndGet();
    }

    public void reconcileTracesUsing(EndTraceMessage endTraceMessage) {
        final String traceItemsQuery = "SELECT trace_item from raw_traces WHERE pid = ?";

        Flux.from(cqlSession.executeReactive(traceItemsQuery, String.format("%s-%s", endTraceMessage.getPid(), PID_SUFFIX)))
            .map(row -> TraceItem.fromString(row.getString("trace_item")))
            .map(traceItem -> new FullTraceItem(traceItem, endTraceMessage))
            .flatMap(fullTraceItem ->
                Flux.fromIterable(cassandraConfiguration.getTraceTableFields().entrySet())
                    .map(entry -> new ImmutableTriple<>(fullTraceItem, entry.getKey(), entry.getValue())), 64
            ).flatMap(triple ->
            this.reactiveInsertEntity(triple.left, triple.middle, triple.right), 64
        ).blockLast();
    }

    public void reconcileProcessesAndTraces() {
        final ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();
        executorService.scheduleAtFixedRate(
            () -> log.info("{} traces remaining to be reconciled", numTraces.get()),
            0,
            5,
            TimeUnit.SECONDS
        );

        final String processesQuery = "SELECT * from processes";
        final String traceItemsQuery = "SELECT trace_item from raw_traces WHERE pid = ?";

        Flux.from(cqlSession.executeReactive(processesQuery))
            .map(row ->
                EndTraceMessage.builder()
                    .experimentName(row.getString("experiment"))
                    .subject(row.getString("subject"))
                    .binaryContext(row.getString("binary"))
                    .execContext(row.getString("execution"))
                    .pid(Integer.parseInt(
                        row.getString("pid").replace(String.format("-%s", PID_SUFFIX), ""))
                    )
                    .exitStatus(row.getString("exit_status"))
                    .inputSize(BigInteger.valueOf(row.getLong("input_size")))
                    .build()
            ).flatMap(endTraceMessage ->
            Flux.from(cqlSession.executeReactive(traceItemsQuery, String.format("%s-%s", endTraceMessage.getPid(), PID_SUFFIX)))
                .map(row -> TraceItem.fromString(row.getString("trace_item")))
                .map(traceItem -> new FullTraceItem(traceItem, endTraceMessage)), 32
        ).flatMap(fullTraceItem ->
            Flux.fromIterable(cassandraConfiguration.getTraceTableFields().entrySet())
                .map(entry -> new ImmutableTriple<>(fullTraceItem, entry.getKey(), entry.getValue())), 32
        ).flatMap(triple ->
            this.reactiveInsertEntity(triple.left, triple.middle, triple.right), 32
        ).blockLast();

        /*StreamSupport.stream(cqlSession.execute(processesStatement).spliterator(), true)
            .map(row -> EndTraceMessage.builder()
                .experimentName(row.getString("experiment"))
                .subject(row.getString("subject"))
                .binaryContext(row.getString("binary"))
                .execContext(row.getString("execution"))
                .pid(Integer.parseInt(
                    row.getString("pid").replace(String.format("-%s", PID_SUFFIX), ""))
                )
                .exitStatus(row.getString("exit_status"))
                .inputSize(BigInteger.valueOf(row.getLong("input_size")))
                .build()
            ).forEach(endTraceMessage -> {
                final BoundStatement tracesStatement = cqlSession
                    .prepare("SELECT trace_item from raw_traces WHERE pid = ?")
                    .bind(String.format("%s-%s", endTraceMessage.getPid(), PID_SUFFIX))
                    .setPageSize(2000);

                StreamSupport.stream(cqlSession.execute(tracesStatement).spliterator(), true)
                    .map(row -> TraceItem.fromString(row.getString("trace_item")))
                    .map(traceItem -> new FullTraceItem(traceItem, endTraceMessage))
                    .forEach(fullTraceItem -> {
                        insertFullTraceItem(fullTraceItem);
                        numTraces.decrementAndGet();
                    });
            });*/

        executorService.shutdownNow();
    }

    public void insertProcessInformation(EndTraceMessage endTraceMessage) {
        final String table = "processes";
        final List<String> fields = cassandraConfiguration.getTraceTableFields().get(table);

        insertEntity(endTraceMessage, table, fields);
    }

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
