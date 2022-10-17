package net.vivin.vvdump.repository;

import net.vivin.vvdump.model.FullTraceItem;

public interface TraceRepository {
    void insertFullTraceItem(FullTraceItem fullTraceItem);
}
