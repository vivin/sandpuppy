package net.vivin.vvdump.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

import java.math.BigInteger;

/**
 * Created on 11/10/20 at 12:15 PM
 *
 * @author vivin
 */

@Getter
@AllArgsConstructor
@ToString
public class VariableValueEndTrace {
    private final String experimentName;
    private final String subject;
    private final String binaryContext;
    private final String execContext;
    private final int pid;
    private final String exitStatus;
    private final BigInteger inputSize;

    private enum Components {
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

        private final int index;

        Components() {
            this.index = Components.IndexHolder.index++;
        }
    }

    public static VariableValueEndTrace fromStringTrace(String trace) {
        String[] components = trace.split(":");

        return new VariableValueEndTrace(
            components[Components.EXPERIMENT_NAME.index],
            components[Components.SUBJECT.index],
            components[Components.BINARY_CONTEXT.index],
            components[Components.EXEC_CONTEXT.index],
            Integer.parseInt(components[Components.PID.index]),
            components[Components.EXIT_STATUS.index],
            new BigInteger(components[Components.INPUT_SIZE.index])
        );
    }
}
