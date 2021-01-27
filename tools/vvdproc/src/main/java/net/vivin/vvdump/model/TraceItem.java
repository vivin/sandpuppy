package net.vivin.vvdump.model;

import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Created on 11/10/20 at 11:48 AM
 *
 * @author vivin
 */

@Slf4j
@Getter
@ToString
public class TraceItem implements Entity {

    private final String experimentName;
    private final String subject;
    private final String binaryContext;
    private final String execContext;
    private final int pid;
    private final String filename;
    private final String functionName;
    private final String variableName;
    private final int declaredLine;
    private final int modifiedLine;
    private final BigInteger timestamp;
    private final String variableType;
    private final String variableValue;

    private final Map<String, Supplier<Object>> tableFieldToGetter = new HashMap<>();

    public TraceItem(String experimentName, String subject, String binaryContext, String execContext, int pid, String filename, String functionName, String variableName, int declaredLine, int modifiedLine, BigInteger timestamp, String variableType, String variableValue) {
        this.experimentName = experimentName;
        this.subject = subject;
        this.binaryContext = binaryContext;
        this.execContext = execContext;
        this.pid = pid;
        this.filename = filename;
        this.functionName = functionName;
        this.variableName = variableName;
        this.declaredLine = declaredLine;
        this.modifiedLine = modifiedLine;
        this.timestamp = timestamp;
        this.variableType = variableType;
        this.variableValue = variableValue;

        tableFieldToGetter.put("experiment", this::getExperimentName);
        tableFieldToGetter.put("subject", this::getSubject);
        tableFieldToGetter.put("binary", this::getBinaryContext);
        tableFieldToGetter.put("execution", this::getExecContext);
        tableFieldToGetter.put("pid", this::getPid);
        tableFieldToGetter.put("filename", this::getFilename);
        tableFieldToGetter.put("function_name", this::getFunctionName);
        tableFieldToGetter.put("variable_name", this::getVariableName);
        tableFieldToGetter.put("declared_line", this::getDeclaredLine);
        tableFieldToGetter.put("modified_line", this::getModifiedLine);
        tableFieldToGetter.put("timestamp", this::getTimestamp);
        tableFieldToGetter.put("variable_type", this::getVariableType);
        tableFieldToGetter.put("variable_value", this::getVariableValue);
    }

    public enum Components {
        EXPERIMENT_NAME,
        SUBJECT,
        BINARY_CONTEXT,
        EXEC_CONTEXT,
        PID,
        FILENAME,
        FUNCTION_NAME,
        VARIABLE_NAME,
        DECLARED_LINE,
        MODIFIED_LINE,
        TIMESTAMP,
        VARIABLE_TYPE,
        VARIABLE_VALUE;

        private static class IndexHolder {
            private static int index = 0;
        }

        public final int index;

        Components() {
            this.index = IndexHolder.index++;
        }
    }

    public static TraceItem fromString(String trace) {
        String[] components = trace.split(":");

        return new TraceItem(
            components[Components.EXPERIMENT_NAME.index],
            components[Components.SUBJECT.index],
            components[Components.BINARY_CONTEXT.index],
            components[Components.EXEC_CONTEXT.index],
            Integer.parseInt(components[Components.PID.index]),
            components[Components.FILENAME.index],
            components[Components.FUNCTION_NAME.index],
            components[Components.VARIABLE_NAME.index],
            Integer.parseInt(components[Components.DECLARED_LINE.index]),
            Integer.parseInt(components[Components.MODIFIED_LINE.index]),
            new BigInteger(components[Components.TIMESTAMP.index]),
            components[Components.VARIABLE_TYPE.index],
            components[Components.VARIABLE_VALUE.index]
        );
    }

    public Object get(final String tableFieldName) {
        if (!tableFieldToGetter.containsKey(tableFieldName)) {
            throw new IllegalArgumentException("Invalid field name: " + tableFieldName);
        }

        return tableFieldToGetter.get(tableFieldName).get();
    }
}
