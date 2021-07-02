package net.vivin.vvdump.model;

import static org.awaitility.Awaitility.await;
import static net.vivin.vvdump.service.TraceProcessingService.Metrics;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.cassandra.repository.CassandraRepository;
import org.apache.commons.lang3.RandomStringUtils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

@Slf4j
public class ProcessTraceTask implements Runnable {
    private ProcessTrace processTrace = null;

    private final int traceSize;

    @NonNull
    private final Path savedProcessTracePath;

    @NonNull
    private final ExecutorService executor;

    @NonNull
    private final CassandraRepository cassandra;

    @NonNull
    private final Metrics metrics;

    public ProcessTraceTask(ProcessTrace processTrace, @NonNull Path dataDirectory, @NonNull ExecutorService executor, @NonNull CassandraRepository cassandra, @NonNull Metrics metrics) {

        this.traceSize = processTrace.size();
        savedProcessTracePath = dataDirectory.resolve(
            String.format(
                "process-trace-%s-%d.sgz",
                RandomStringUtils.randomAlphabetic(13),
                processTrace.size()
            )
        );

        try {
            final var processTraceFile = savedProcessTracePath.toFile();
            if (!processTraceFile.createNewFile()) {
                throw new IOException("Could not create file: " + savedProcessTracePath.toString() + " because it already exists");
            }

            final var fileOutputStream = new FileOutputStream(processTraceFile);
            final var gzipOutputStream = new GZIPOutputStream(fileOutputStream);
            final var objectOutputStream = new ObjectOutputStream(gzipOutputStream);

            objectOutputStream.writeObject(processTrace);
            objectOutputStream.close();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        this.executor = executor;
        this.cassandra = cassandra;
        this.metrics = metrics;

        this.metrics.addToTotalTraceItems(processTrace.size());
        this.metrics.incrementTotalProcessTraces();
    }

    private ProcessTrace getProcessTrace() {
        if (processTrace != null) {
            return processTrace;
        }

        final var processTraceFile = savedProcessTracePath.toFile();

        try {
            final var fileInputStream = new FileInputStream(processTraceFile);
            final var gzipInputStream = new GZIPInputStream(fileInputStream);
            final var objectInputStream = new ObjectInputStream(gzipInputStream);

            this.processTrace = (ProcessTrace) objectInputStream.readObject();
            if(!processTraceFile.delete()) {
                log.warn("Could not delete process trace file {}", processTraceFile.getAbsolutePath());
            }

            return processTrace;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void run() {
        final ProcessTrace trace = getProcessTrace();
        metrics.addToProcessingTraceItems(trace.size());

        final var endTraceItem = trace.getEndTraceItem();
        final List<Callable<Object>> callables = trace.getTraceItems().stream().map(traceItem ->
            Executors.callable(() -> {
                cassandra.insertFullTraceItem(FullTraceItem.from(traceItem, endTraceItem));

                metrics.decrementProcessingTraceItems();
                metrics.incrementProcessedTraceItems();
            })
        ).collect(Collectors.toList());

        try {
            processTrace = null;
            executor.invokeAll(callables);
            metrics.incrementProcessedProcessTraces();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}
