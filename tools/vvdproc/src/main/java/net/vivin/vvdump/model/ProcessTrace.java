package net.vivin.vvdump.model;

import lombok.Getter;
import lombok.NonNull;

import java.io.Serializable;
import java.util.Queue;

@Getter
public class ProcessTrace implements Serializable {
    @NonNull
    private final Queue<String> traceItems;

    @NonNull
    private final String endTraceItem;

    public ProcessTrace(Queue<String> traceItems, String endTraceItem) {
        this.traceItems = traceItems;
        this.endTraceItem = endTraceItem;
    }

    public int size() {
        return traceItems.size();
    }
}
