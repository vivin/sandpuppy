package net.vivin.vvdump.cassandra.repository;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.cassandra.config.CassandraConfiguration;
import net.vivin.vvdump.model.FullTraceItem;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
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
public class CassandraRepository {

    private final CassandraOperations cassandraOperations;
    private final CassandraConfiguration cassandraConfiguration;

    @Autowired
    public CassandraRepository(CassandraOperations cassandraOperations, CassandraConfiguration cassandraConfiguration) {
        this.cassandraOperations = cassandraOperations;
        this.cassandraConfiguration = cassandraConfiguration;
    }

    private static final String PID_SUFFIX = RandomStringUtils.randomAlphabetic(6);

    public void insertFullTraceItem(FullTraceItem fullTraceItem) {
        cassandraConfiguration.getTraceTableFields().forEach((table, fields) -> {
            final String query = String.format(
                "INSERT INTO %s (%s) VALUES (%s%s)",
                table,
                String.join(", ", fields),
                fields.contains("id") ? "uuid(), " : "",
                "?, ".repeat(fields.contains("id") ? fields.size() - 1 : fields.size()).replaceFirst(", $", "")
            );

            final Object[] values = fields.stream().filter(field -> !field.equals("id")).map(field -> {
                Object value = fullTraceItem.get(field);

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
}
