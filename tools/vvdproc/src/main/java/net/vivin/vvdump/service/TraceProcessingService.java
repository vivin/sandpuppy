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
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.awaitility.Awaitility.await;

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
    private final ExecutorService traceInsertionExecutor;

    private final Set<Integer> pids = new HashSet<>();
    private final Map<Integer, Queue<String>> processTraces = new HashMap<>();

    @Autowired
    public TraceProcessingService(ApplicationContext applicationContext, CassandraRepository cassandraRepository) {
        this.applicationContext = applicationContext;
        this.cassandraRepository = cassandraRepository;
        this.pipeReaderExecutor = Executors.newSingleThreadExecutor();
        this.traceInsertionExecutor = Executors.newFixedThreadPool(32);
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

    private void readPipe() {
        final var traceCount = new AtomicInteger();

        try {
            var pipe = new RandomAccessFile(namedPipePath, "rw");
            log.info("Listening...");

            long lastLoggedTime = System.currentTimeMillis();

            String line;
            while ((line = pipe.readLine()) != null && !END_TRACE_MARKER.equals(line)) {
                var components = line.split(":");
                if (components.length != NUM_END_TRACE_COMPONENTS) {
                    var pid = Integer.parseInt(components[TraceItem.Components.PID.index]);

                    if (!pids.contains(pid)) {
                        processTraces.put(pid, new ArrayDeque<>());
                        pids.add(pid);
                    }

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

                        traceCount.addAndGet(traceItems.size());
                        traceInsertionExecutor.submit(() -> {
                            var size = traceItems.size();
                            String traceItem;
                            while ((traceItem = traceItems.poll()) != null) {
                                var fullTraceItem = FullTraceItem.from(traceItem, endTrace);
                                cassandraRepository.insertFullTraceItem(fullTraceItem);
                            }

                            traceCount.addAndGet(-size);
                        });

                        if (System.currentTimeMillis() - lastLoggedTime > 5000) {
                            log.info("{} trace items from {} processes remain to be saved...", traceCount.get(), getRemainingProcesses());
                            lastLoggedTime = System.currentTimeMillis();
                        }
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
        traceInsertionExecutor.shutdown();
        await()
            .atMost(Duration.ofMinutes(10))
            .with().pollInterval(Duration.ofSeconds(5))
            .until(() -> {
                log.info("{} trace items from {} processes remain to be saved...", traceCount.get(), getRemainingProcesses());
                return traceInsertionExecutor.isTerminated();
            });
    }

    private long getRemainingProcesses() {
        long taskCount = ((ThreadPoolExecutor) traceInsertionExecutor).getTaskCount();
        long completedTaskCount = ((ThreadPoolExecutor) traceInsertionExecutor).getCompletedTaskCount();
        return (taskCount - completedTaskCount);
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
