package net.vivin.vvdump.model;

import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Created on 11/10/20 at 12:15 PM
 *
 * @author vivin
 */

@Getter
@ToString
@Builder
public class EndTraceMessage implements Entity {

    private final String experimentName;
    private final String subject;
    private final String binaryContext;
    private final String execContext;
    private final int pid;
    private final String exitStatus;
    private final BigInteger inputSize;

    private final Map<String, Supplier<Object>> tableFieldToGetter = new HashMap<>();

    public EndTraceMessage(String experimentName, String subject, String binaryContext, String execContext, int pid, String exitStatus, BigInteger inputSize) {
        this.experimentName = experimentName;
        this.subject = subject;
        this.binaryContext = binaryContext;
        this.execContext = execContext;
        this.pid = pid;
        this.exitStatus = exitStatus;
        this.inputSize = inputSize;

        tableFieldToGetter.put("experiment", this::getExperimentName);
        tableFieldToGetter.put("subject", this::getSubject);
        tableFieldToGetter.put("binary", this::getBinaryContext);
        tableFieldToGetter.put("execution", this::getExecContext);
        tableFieldToGetter.put("pid", this::getPid);
        tableFieldToGetter.put("exit_status", this::getExitStatus);
        tableFieldToGetter.put("input_size", this::getInputSize);
    }

    public enum Components {
        EXPERIMENT_NAME,
        SUBJECT,
        BINARY_CONTEXT,
        EXEC_CONTEXT,
        PID,
        EXIT_STATUS,
        INPUT_SIZE;

        private static class IndexHolder {
            private static int index = 0;
        }

        public final int index;

        Components() {
            this.index = Components.IndexHolder.index++;
        }
    }

    public static EndTraceMessage from(String trace) {
        String[] components = trace.split(":");

        return new EndTraceMessage(
            components[Components.EXPERIMENT_NAME.index],
            components[Components.SUBJECT.index],
            components[Components.BINARY_CONTEXT.index],
            components[Components.EXEC_CONTEXT.index],
            Integer.parseInt(components[Components.PID.index]),
            components[Components.EXIT_STATUS.index],
            new BigInteger(components[Components.INPUT_SIZE.index])
        );
    }

    public Object get(final String tableFieldName) {
        if (!tableFieldToGetter.containsKey(tableFieldName)) {
            throw new IllegalArgumentException("Invalid field name: " + tableFieldName);
        }

        return tableFieldToGetter.get(tableFieldName).get();
    }
}
