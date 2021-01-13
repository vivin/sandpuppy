package net.vivin.vvdump.service;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.cassandra.repository.CassandraRepository;
import net.vivin.vvdump.model.EndTraceMessage;
import net.vivin.vvdump.model.FullTraceItem;
import net.vivin.vvdump.model.TraceItem;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Service
public class TraceProcessingService {

    private static final int NUM_END_TRACE_COMPONENTS = 8;
    private static final String END_TRACE_MARKER = "__$VVDUMP_END$__";

    @Value("${vvdump.named-pipe-path}")
    private String namedPipePath;

    private final ApplicationContext applicationContext;
    private final CassandraRepository cassandraRepository;
    private final ExecutorService pipeReaderExecutor;
    private final ExecutorService dbQueryExecutor;
    private final ExecutorService traceConsumerExecutor;

    private final Set<Integer> pids = new HashSet<>();
    private final Map<Integer, Queue<String>> processTraces = new HashMap<>();

    @Autowired
    public TraceProcessingService(ApplicationContext applicationContext, CassandraRepository cassandraRepository) {
        this.applicationContext = applicationContext;
        this.cassandraRepository = cassandraRepository;
        this.pipeReaderExecutor = Executors.newSingleThreadExecutor();
        this.dbQueryExecutor = Executors.newFixedThreadPool(32);
        this.traceConsumerExecutor = Executors.newFixedThreadPool(16);
    }

    @PostConstruct
    public void init() {
        CompletableFuture.runAsync(this::readPipe, pipeReaderExecutor)
            .whenCompleteAsync((v, e) -> {
                if (e != null) {
                    log.error("Processor shut down unexpectedly", e);
                }
                ((ConfigurableApplicationContext) applicationContext).close();
            });
    }
    // TODO: look at this: https://stackoverflow.com/questions/8183205/what-could-be-the-cause-of-rejectedexecutionexception/8183463
    // TODO: rejected execution might be happening due to queue saturation.
    private void readPipe() {
        final AtomicInteger traceCount = new AtomicInteger(0);

        try {
            var pipe = new RandomAccessFile(namedPipePath, "rw");
            log.info("Listening...");

            String line;
            while ((line = pipe.readLine()) != null && !END_TRACE_MARKER.equals(line)) {
                var components = line.split(":");
                if (components.length != NUM_END_TRACE_COMPONENTS) {
                    var pid = Integer.parseInt(components[TraceItem.Components.PID.index]);

                    if (!pids.contains(pid)) {
                        log.info("Recording traces for new process {}", pid);
                        processTraces.put(pid, new ArrayDeque<>());
                        pids.add(pid);
                    }

                    traceCount.incrementAndGet();
                    processTraces.get(pid).add(line);
                } else {
                    // Only insert the traces if the process wasn't killed and if we have seen at least one trace from
                    // this process (that's the only way it would be inside the pids set).

                    var exitStatus = components[EndTraceMessage.Components.EXIT_STATUS.index];
                    var pid = Integer.parseInt(components[EndTraceMessage.Components.PID.index]);
                    if (!"killed".equals(exitStatus) && pids.contains(pid)) {
                        pids.remove(pid);
                        var traceItems = processTraces.remove(pid);
                        var endTrace = line;

                        traceConsumerExecutor.submit(() -> {
                            String traceItem;
                            while ((traceItem = traceItems.poll()) != null) {
                                var fullTraceItem = FullTraceItem.from(traceItem, endTrace);
                                dbQueryExecutor.submit(() -> {
                                    cassandraRepository.insertFullTraceItem(fullTraceItem);
                                    traceCount.decrementAndGet();
                                });
                            }
                        });
                    }
                }
            }
        } catch (FileNotFoundException e) {
            throw new UncheckedIOException("Could not find named pipe", e);
        } catch (IOException e) {
            log.error("Error while reading from pipe", e);
            throw new UncheckedIOException(e);
        }

        log.info("Fuzzer has shut down. No more incoming traces.");
        traceConsumerExecutor.shutdown();
        while (!traceConsumerExecutor.isTerminated()) {
            try {
                log.info("{} trace items remain to be saved...", traceCount.get());
                traceConsumerExecutor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        dbQueryExecutor.shutdown();
        try {
            if (!dbQueryExecutor.awaitTermination(30, TimeUnit.SECONDS)) {
                dbQueryExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @PreDestroy
    public void destroy() throws InterruptedException {
        log.info("Shutting down pipe reader executor...");
        pipeReaderExecutor.shutdown();

        var attempts = 5;
        while (!pipeReaderExecutor.isTerminated() && attempts > 0) {
            pipeReaderExecutor.awaitTermination(3, TimeUnit.SECONDS);
            attempts--;
            log.info("Waiting on pipe reader executor to terminate...");
        }

        pipeReaderExecutor.shutdownNow();
    }
}
