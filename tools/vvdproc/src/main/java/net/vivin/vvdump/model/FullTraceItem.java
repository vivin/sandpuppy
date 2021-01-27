package net.vivin.vvdump.model;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Created on 1/7/21 at 9:00 PM
 *
 * @author vivin
 */
public class FullTraceItem implements Entity {

    private final TraceItem traceItem;
    private final EndTraceMessage endTraceMessage;
    private final Map<String, Supplier<Object>> tableFieldToGetter = new HashMap<>();

    public FullTraceItem(TraceItem traceItem, EndTraceMessage endTraceMessage) {
        this.traceItem = traceItem;
        this.endTraceMessage = endTraceMessage;

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
        tableFieldToGetter.put("exit_status", this::getExitStatus);
        tableFieldToGetter.put("input_size", this::getInputSize);
    }

    public String getExperimentName() {
        return traceItem.getExperimentName();
    }

    public String getSubject() {
        return traceItem.getSubject();
    }

    public String getBinaryContext() {
        return traceItem.getBinaryContext();
    }

    public String getExecContext() {
        return traceItem.getExecContext();
    }

    public int getPid() {
        return traceItem.getPid();
    }

    public String getFilename() {
        return traceItem.getFilename();
    }

    public String getFunctionName() {
        return traceItem.getFunctionName();
    }

    public String getVariableName() {
        return traceItem.getVariableName();
    }

    public int getDeclaredLine() {
        return traceItem.getDeclaredLine();
    }

    public int getModifiedLine() {
        return traceItem.getModifiedLine();
    }

    public BigInteger getTimestamp() {
        return traceItem.getTimestamp();
    }

    public String getVariableType() {
        return traceItem.getVariableType();
    }

    public String getVariableValue() {
        return traceItem.getVariableValue();
    }

    public String getExitStatus() {
        return endTraceMessage.getExitStatus();
    }

    public BigInteger getInputSize() {
        return endTraceMessage.getInputSize();
    }

    public Object get(final String tableFieldName) {
        if (!tableFieldToGetter.containsKey(tableFieldName)) {
            throw new IllegalArgumentException("Invalid field name: " + tableFieldName);
        }

        return tableFieldToGetter.get(tableFieldName).get();
    }

    public static FullTraceItem from(String traceItem, String endTraceMessage) {
        return new FullTraceItem(
            TraceItem.fromString(traceItem),
            EndTraceMessage.from(endTraceMessage)
        );
    }
}
