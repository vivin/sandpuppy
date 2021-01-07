package net.vivin.vvdump.cassandra.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Created on 1/5/21 at 8:06 PM
 *
 * @author vivin
 */

@Component
@ConfigurationProperties("vvdump.sql.cassandra")
@Data
public class CassandraConfiguration {
    private Map<String, List<String>> traceTableFields;
    private Map<String, List<String>> processTableFields;
}
