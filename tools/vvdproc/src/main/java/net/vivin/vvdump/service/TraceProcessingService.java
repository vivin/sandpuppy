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
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.RandomAccessFile;
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
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.awaitility.Awaitility.await;

@Slf4j
@Service
public class TraceProcessingService {

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

    @Autowired
    public TraceProcessingService(ApplicationContext applicationContext, CassandraRepository cassandraRepository) {
        this.applicationContext = applicationContext;
        this.cassandraRepository = cassandraRepository;
        this.pipeReaderExecutor = Executors.newSingleThreadExecutor();
        this.traceInsertionExecutor = Executors.newFixedThreadPool(96);
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
        final var totalTraceCount = new AtomicLong();
        final var lastProcessedTraceCount = new AtomicLong();
        final var processedTraceCount = new AtomicLong();

        try {
            // Need to open in read-write mode because the fuzzer is continually starting up processes and shutting
            // them down, meaning that there are windows of time where there are no writers. If opened in read mode
            // we will get an EOF when the writer goes away.
            //var pipe = new RandomAccessFile(namedPipePath, "rw");
            var pipe = new BufferedReader(new FileReader(namedPipePath), 8192 * 8);
            log.info("Listening...");

            long lastLoggedTime = System.currentTimeMillis();

            String line;
            while ((line = pipe.readLine()) != null && !END_TRACE_MARKER.equals(line)) {
                var components = line.split(":");
                if (components.length == NUM_TRACE_COMPONENTS) {
                    var pid = Integer.parseInt(components[TraceItem.Components.PID.index]);

                    if (!pids.contains(pid)) {
                        processTraces.put(pid, new ArrayDeque<>());
                        pids.add(pid);
                    }

                    processTraces.get(pid).add(line);
                } else if (components.length == NUM_END_TRACE_COMPONENTS) {
                    // Only insert the traces if the process wasn't killed and if we have seen at least one trace from
                    // this process (that's the only way it would be inside the pids set).

                    var exitStatus = components[EndTraceMessage.Components.EXIT_STATUS.index];
                    var pid = Integer.parseInt(components[EndTraceMessage.Components.PID.index]);
                    if (!"killed".equals(exitStatus) && pids.contains(pid)) {
                        pids.remove(pid);
                        var traceItems = processTraces.remove(pid);
                        var endTrace = line;
                        var numTraceItems = traceItems.size();

                        totalTraceCount.addAndGet(numTraceItems);
                        traceInsertionExecutor.submit(() -> {
                            String traceItem;
                            while ((traceItem = traceItems.poll()) != null) {
                                cassandraRepository.insertFullTraceItem(FullTraceItem.from(traceItem, endTrace));
                                processedTraceCount.incrementAndGet();
                            }
                        });

                        long elapsed = System.currentTimeMillis() - lastLoggedTime;
                        if (elapsed > 5000) {
                            logProgress(totalTraceCount, lastProcessedTraceCount, processedTraceCount, elapsed);
                            lastLoggedTime = System.currentTimeMillis();
                        }
                    }
                } else {
                    log.warn("Malformed line: {}", line);
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
                logProgress(totalTraceCount, lastProcessedTraceCount, processedTraceCount, 5000d);
                return traceInsertionExecutor.isTerminated();
            });
    }

    private void logProgress(AtomicLong totalTraceCount, AtomicLong lastProcessedTraceCount, AtomicLong processedTraceCount, double elapsed) {
        long total = totalTraceCount.longValue();
        long processed = processedTraceCount.longValue();
        long lastProcessed = lastProcessedTraceCount.longValue();

        long remaining = total - processed;
        long processedCount = processed - lastProcessed;
        double processingRate = processedCount / (elapsed / 1000d);
        double processingTimePerTrace = elapsed / processedCount;
        long remainingTimeInSeconds = Math.round(remaining / processingRate);
        lastProcessedTraceCount.set(processed);

        log.info(
            "{} trace items from {} processes remaining ({} trace/s; {} ms/trace; {}% done; time remaining: {})",
            remaining,
            getRemainingProcesses(),
            df.format(processingRate),
            df.format(processingTimePerTrace),
            df.format(((double) processed / (double) total) * 100),
            getDescriptiveTimeDelta(remainingTimeInSeconds)
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
