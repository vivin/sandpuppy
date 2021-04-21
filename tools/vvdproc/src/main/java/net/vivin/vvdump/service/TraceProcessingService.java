package net.vivin.vvdump.service;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.cassandra.repository.CassandraRepository;
import net.vivin.vvdump.model.EndTraceMessage;
import net.vivin.vvdump.model.FullTraceItem;
import net.vivin.vvdump.model.TraceItem;
import org.apache.commons.math3.stat.descriptive.SynchronizedDescriptiveStatistics;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.text.DecimalFormat;
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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

import static org.awaitility.Awaitility.await;

@Slf4j
@Service
public class TraceProcessingService {

    private static final int NUM_THREADS = 128;
    private static final int NUM_TRACE_COMPONENTS = 13;
    private static final int NUM_END_TRACE_COMPONENTS = 8;
    private static final String END_TRACE_MARKER = "__$VVDUMP_END$__";
    private static final DecimalFormat df = new DecimalFormat("0.00");

    @Value("${vvdump.named-pipe-path}")
    private String namedPipePath;

    private final ApplicationContext applicationContext;
    private final CassandraRepository cassandraRepository;
    private final ExecutorService pipeReaderExecutor;
    private final ExecutorService traceInsertionExecutor;

    private final Set<Integer> pids = new HashSet<>();
    private final Map<Integer, Queue<String>> processTraces = new HashMap<>();

    private final LongAdder processCount = new LongAdder();
    private final LongAdder totalTraceCount = new LongAdder();
    private final LongAdder processedTraceCount = new LongAdder();

    private final SynchronizedDescriptiveStatistics traceInsertionTimes = new SynchronizedDescriptiveStatistics();

    @Autowired
    public TraceProcessingService(ApplicationContext applicationContext, CassandraRepository cassandraRepository) {
        this.applicationContext = applicationContext;
        this.cassandraRepository = cassandraRepository;
        this.pipeReaderExecutor = Executors.newSingleThreadExecutor();
        this.traceInsertionExecutor = Executors.newFixedThreadPool(NUM_THREADS);
    }

    @PostConstruct
    public void init() {
        log.info("Starting trace processor with {} processing threads...", NUM_THREADS);
        traceInsertionTimes.setWindowSize(100000);
        CompletableFuture.runAsync(this::readPipe, pipeReaderExecutor)
            .whenCompleteAsync((v, e) -> {
                if (e != null) {
                    log.error("Processor shut down unexpectedly", e);
                }
                ((ConfigurableApplicationContext) applicationContext).close();
            });
    }

    private void readPipe() {
        try {
            // Need to open in read-write mode because the fuzzer is continually starting up processes and shutting
            // them down, meaning that there are windows of time where there are no writers. If opened in read mode
            // we will get an EOF when the writer goes away.
            //var pipe = new RandomAccessFile(namedPipePath, "rw");
            var pipe = new BufferedReader(new FileReader(namedPipePath), 512);
            long lastLoggedTime = System.currentTimeMillis();
            String line;
            while ((line = pipe.readLine()) != null && !END_TRACE_MARKER.equals(line)) {
                var components = line.split(":");
                if (components.length == NUM_TRACE_COMPONENTS) {
                    var pid = Integer.parseInt(components[TraceItem.Components.PID.index]);

                    if (!pids.contains(pid)) {
                        processTraces.put(pid, new ArrayDeque<>());
                        pids.add(pid);
                        processCount.increment();
                    }

                    processTraces.get(pid).add(line);
                    totalTraceCount.increment();
                } else if (components.length == NUM_END_TRACE_COMPONENTS) {
                    // Only insert the traces if the process wasn't killed and if we have seen at least one trace from
                    // this process (that's the only way it would be inside the pids set).

                    var exitStatus = components[EndTraceMessage.Components.EXIT_STATUS.index];
                    var pid = Integer.parseInt(components[EndTraceMessage.Components.PID.index]);
                    if (!"killed".equals(exitStatus) && pids.contains(pid)) {
                        pids.remove(pid);
                        var traceItems = processTraces.remove(pid);
                        var endTrace = line;

                        traceInsertionExecutor.submit(() -> {
                            try {
                                String traceItem;
                                while ((traceItem = traceItems.poll()) != null) {
                                    long start = System.currentTimeMillis();
                                    cassandraRepository.insertFullTraceItem(FullTraceItem.from(traceItem, endTrace));
                                    traceInsertionTimes.addValue(System.currentTimeMillis() - start);

                                    processedTraceCount.increment();
                                }
                                processCount.decrement();
                            } catch (Exception e) {
                                log.error("Error while inserting: {}", e.getMessage(), e);
                            }
                        });
                    }
                } else {
                    log.warn("Malformed line: {}", line);
                }

                long elapsed = System.currentTimeMillis() - lastLoggedTime;
                if (elapsed > 5000) {
                    logProgress();
                    lastLoggedTime = System.currentTimeMillis();
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
            .atMost(Duration.ofHours(3))
            .with().pollInterval(Duration.ofSeconds(5))
            .until(() -> {
                logProgress();
                return traceInsertionExecutor.isTerminated();
            });
    }

    private void logProgress() {
        long total = totalTraceCount.longValue();
        long processed = processedTraceCount.longValue();
        double averageInsertionTimePerTrace = traceInsertionTimes.getMean();

        double averageTraceInsertionRate = (1d / averageInsertionTimePerTrace) * 1000d * NUM_THREADS;
        long remaining = total - processed;
        long remainingTimeInSeconds = Math.round(remaining / averageTraceInsertionRate);

        log.info(
            "trace items: {}; processes: {}; insertion time: {} ms/trace; insertion rate: {} traces/s; percent done: {}%; time remaining: {}",
            remaining,
            processCount.longValue(),
            df.format(averageInsertionTimePerTrace),
            df.format(averageTraceInsertionRate),
            df.format(((double) processed / (double) total) * 100),
            getDescriptiveTimeDelta(Math.round(remainingTimeInSeconds))
        );
    }

    private String getDescriptiveTimeDelta(long delta) {
        long hours = delta / 3600;
        long minutes = (delta / 60) % 60;
        long seconds = delta % 60;

        return String.format(
            "%s:%s:%s",
            hours < 10 ? "0" + hours : hours,
            minutes < 10 ? "0" + minutes : minutes,
            seconds < 10 ? "0" + seconds : seconds
        );
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
