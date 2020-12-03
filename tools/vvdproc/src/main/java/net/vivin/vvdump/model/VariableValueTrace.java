package net.vivin.vvdump.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

import java.math.BigInteger;

/**
 * Created on 11/10/20 at 11:48 AM
 *
 * @author vivin
 */

@Getter
@AllArgsConstructor
@ToString
public class VariableValueTrace {

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

    private enum Components {
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

        private final int index;

        Components() {
            this.index = IndexHolder.index++;
        }
    }

    public static VariableValueTrace fromStringTrace(String trace) {
        String[] components = trace.split(":");

        return new VariableValueTrace(
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
}
