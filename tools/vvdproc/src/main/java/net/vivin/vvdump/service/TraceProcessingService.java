package net.vivin.vvdump.service;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.cassandra.repository.CassandraRepository;
import net.vivin.vvdump.model.EndTraceMessage;
import net.vivin.vvdump.model.ProcessTrace;
import net.vivin.vvdump.model.ProcessTraceTask;
import net.vivin.vvdump.model.TraceItem;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.LongAdder;

import static org.awaitility.Awaitility.await;

@Slf4j
@Service
public class TraceProcessingService {

    private static final int PROCESS_TRACE_EXECUTOR_NUM_THREADS = 12;
    private static final int TRACE_ITEM_EXECUTOR_NUM_THREADS = 256;
    private static final int NUM_TRACE_COMPONENTS = 13;
    private static final int NUM_END_TRACE_COMPONENTS = 8;
    private static final String END_TRACE_MARKER = "__$VVDUMP_END$__";
    private static final DecimalFormat df = new DecimalFormat("0.00");

    @Value("${vvdump.named-pipe-path}")
    private String namedPipePath;

    private final ApplicationContext applicationContext;
    private final CassandraRepository cassandra;
    private final ExecutorService pipeReaderExecutor;
    private final ScheduledExecutorService loggerExecutor;
    private final ExecutorService processTraceExecutor;
    private final ExecutorService traceItemInsertionExecutor;

    private final Path dataDirectory;

    private final Set<Integer> pids = new HashSet<>();
    private final Map<Integer, Queue<String>> processTraces = new HashMap<>();

    private final Metrics metrics = new Metrics();

    private long lastProcessedTraceItems;
    private long lastLoggedTime;
    private boolean showProgress = false;

    @Autowired
    public TraceProcessingService(ApplicationContext applicationContext, CassandraRepository cassandra) throws IOException {
        this.applicationContext = applicationContext;
        this.cassandra = cassandra;
        this.pipeReaderExecutor = Executors.newSingleThreadExecutor();
        this.loggerExecutor = Executors.newSingleThreadScheduledExecutor();
        this.processTraceExecutor = Executors.newFixedThreadPool(PROCESS_TRACE_EXECUTOR_NUM_THREADS);
        this.traceItemInsertionExecutor = Executors.newFixedThreadPool(TRACE_ITEM_EXECUTOR_NUM_THREADS);
        this.dataDirectory = Files.createTempDirectory("vvdump-data");
        this.lastProcessedTraceItems = 0L;
    }

    @PostConstruct
    public void init() {
        log.info("Starting trace processor with {} processing threads...", TRACE_ITEM_EXECUTOR_NUM_THREADS);
        CompletableFuture.runAsync(this::readPipe, pipeReaderExecutor)
            .whenCompleteAsync((v, e) -> {
                if (e != null) {
                    log.error("Processor shut down unexpectedly", e);
                }

                log.info("Shutting down pipe reader executor...");
                pipeReaderExecutor.shutdown();

                var attempts = 5;
                while (!pipeReaderExecutor.isTerminated() && attempts > 0) {
                    try {
                        pipeReaderExecutor.awaitTermination(3, TimeUnit.SECONDS);
                    } catch (InterruptedException interruptedException) {
                        Thread.currentThread().interrupt();
                    }
                    attempts--;
                    log.info("Waiting on pipe reader executor to terminate...");
                }

                pipeReaderExecutor.shutdownNow();
                ((ConfigurableApplicationContext) applicationContext).close();
            });
    }

    private void readPipe() {
        long start = -1;

        this.lastLoggedTime = System.currentTimeMillis();
        loggerExecutor.scheduleAtFixedRate(this::logStatistics, 0, 1, TimeUnit.SECONDS);

        try {
            // Need to open in read-write mode because the fuzzer is continually starting up processes and shutting
            // them down, meaning that there are windows of time where there are no writers. If opened in read mode
            // we will get an EOF when the writer goes away.
            //var pipe = new RandomAccessFile(namedPipePath, "rw");
            var pipe = new BufferedReader(new FileReader(namedPipePath), 8192 * 8);

            String line;
            while ((line = pipe.readLine()) != null && !END_TRACE_MARKER.equals(line)) {
                if (start == -1) {
                    start = System.currentTimeMillis();
                }

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

                    // Uncomment and then get rid of the else block (or leave it in; doesn't matter) if you want to
                    // insert ALL traces, even crashes and hangs etc.
                    // if (!"killed".equals(exitStatus) && pids.contains(pid)) {
                    if ("success".equals(exitStatus) && pids.contains(pid)) {
                        pids.remove(pid);
                        processTraceExecutor.submit(new ProcessTraceTask(
                            new ProcessTrace(processTraces.remove(pid), line),
                            dataDirectory,
                            traceItemInsertionExecutor,
                            cassandra,
                            metrics
                        ));
                    } else {
                        pids.remove(pid);
                        processTraces.remove(pid);
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
        this.showProgress = true;

        log.info("Shutting down process-trace executor and waiting for termination...");
        shutdownExecutorAndMonitor(processTraceExecutor);
        log.info("Process-trace executor has shutdown.");

        log.info("Shutting down trace-item insertion executor and waiting for termination...");
        shutdownExecutorAndMonitor(traceItemInsertionExecutor);
        log.info("Trace-item insertion execution has shutdown.");

        shutdownExecutorAndMonitor(loggerExecutor);

        long totalTime = System.currentTimeMillis() - start;
        long actualTotalProcessingTime = metrics.getActualTotalProcessingTime();
        double totalTraceItems = Long.valueOf(metrics.getTotalTraceItems()).doubleValue();
        log.info(
            "Processed {} traces in {} seconds overall ({} traces/s; {} ms/trace)",
            metrics.getTotalTraceItems(),
            getDescriptiveTimeDelta(totalTime / 1000),
            df.format(totalTraceItems / (totalTime / 1000d)),
            df.format(totalTime / totalTraceItems)
        );
        log.info(
            "Processed {} traces in {} seconds actual ({} traces/s; {} ms/trace)",
            metrics.getTotalTraceItems(),
            getDescriptiveTimeDelta(actualTotalProcessingTime / (1000 * TRACE_ITEM_EXECUTOR_NUM_THREADS)),
            df.format(totalTraceItems / (actualTotalProcessingTime / (1000d * TRACE_ITEM_EXECUTOR_NUM_THREADS))),
            df.format((actualTotalProcessingTime / (1d * TRACE_ITEM_EXECUTOR_NUM_THREADS)) / totalTraceItems)
        );
    }

    private void shutdownExecutorAndMonitor(ExecutorService executor) {
        executor.shutdown();
        await()
            .atMost(Duration.ofHours(3))
            .with().pollInterval(Duration.ofSeconds(1))
            .until(executor::isTerminated);
    }

    private void logStatistics() {
        long totalTraceItems = metrics.getTotalTraceItems();
        long processingTraceItems = metrics.getProcessingTraceItems();

        long lastProcessedTraceItems = this.lastProcessedTraceItems;
        long processedTraceItems = metrics.getProcessedTraceItems();
        long elapsed = System.currentTimeMillis() - this.lastLoggedTime;
        long remainingTraceItems = totalTraceItems - processedTraceItems;

        this.lastProcessedTraceItems = processedTraceItems;
        this.lastLoggedTime = System.currentTimeMillis();

        long totalProcessTraces = metrics.getTotalProcessTraces();
        long processedProcessTraces = metrics.getProcessedProcessTraces();
        long remainingProcessTraces = totalProcessTraces - processedProcessTraces;

        double newlyProcessedTraceItems = Long.valueOf(processedTraceItems - lastProcessedTraceItems).doubleValue();
        if (newlyProcessedTraceItems > 0) {
            metrics.recordTraceProcessingTime(
                Long.valueOf(elapsed).doubleValue() / newlyProcessedTraceItems
            );
        }

        double averageProcessingTimePerTrace = metrics.getTraceProcessingTimes().getMean();
        if (Double.isNaN(averageProcessingTimePerTrace)) {
            averageProcessingTimePerTrace = 0;
        }

        long estimatedTimeRemaining = Math.round((averageProcessingTimePerTrace * Long.valueOf(remainingTraceItems).doubleValue()) / 1000);

        if (showProgress) {
            log.info(
                "trace items: (total: {}, processed: {}, {} remaining, {} processing); process traces: (total: {}, processed: {}, remaining: {}); processing time: {} ms/trace; percent done: {}%; estimated time remaining: {}",
                totalTraceItems,
                processedTraceItems,
                remainingTraceItems,
                processingTraceItems,
                totalProcessTraces,
                processedProcessTraces,
                remainingProcessTraces,
                df.format(averageProcessingTimePerTrace),
                df.format(((double) processedTraceItems / (double) totalTraceItems) * 100),
                getDescriptiveTimeDelta(estimatedTimeRemaining)
            );
        } else {
            log.info(
                "trace items: (total: {}, processed: {}, {} remaining, {} processing); process traces: (total: {}, processed: {}, remaining: {}); processing time: {} ms/trace",
                totalTraceItems,
                processedTraceItems,
                remainingTraceItems,
                processingTraceItems,
                totalProcessTraces,
                processedProcessTraces,
                remainingProcessTraces,
                df.format(averageProcessingTimePerTrace)
            );
        }
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

    public static class Metrics {
        private final LongAdder totalTraceItems = new LongAdder();
        private final LongAdder processingTraceItems = new LongAdder();
        private final LongAdder processedTraceItems = new LongAdder();

        private final LongAdder totalProcessTraces = new LongAdder();
        private final LongAdder processedProcessTraces = new LongAdder();
        private final LongAdder cumulativeProcessingTime = new LongAdder();

        private final DescriptiveStatistics traceProcessingTimes = new DescriptiveStatistics();

        public Metrics() {
            traceProcessingTimes.setWindowSize(60);
        }

        public long getTotalTraceItems() {
            return totalTraceItems.longValue();
        }

        public long getProcessingTraceItems() {
            return processingTraceItems.longValue();
        }

        public long getProcessedTraceItems() {
            return processedTraceItems.longValue();
        }

        public long getTotalProcessTraces() {
            return totalProcessTraces.longValue();
        }

        public long getProcessedProcessTraces() {
            return processedProcessTraces.longValue();
        }

        public DescriptiveStatistics getTraceProcessingTimes() {
            return traceProcessingTimes;
        }

        public long getActualTotalProcessingTime() {
            return cumulativeProcessingTime.longValue();
        }

        public void addToTotalTraceItems(long value) {
            totalTraceItems.add(value);
        }

        public void addToProcessingTraceItems(long value) {
            processingTraceItems.add(value);
        }

        public void decrementProcessingTraceItems() {
            processingTraceItems.decrement();
        }

        public void incrementTotalProcessTraces() {
            totalProcessTraces.increment();
        }

        public void incrementProcessedTraceItems() {
            processedTraceItems.increment();
        }

        public void incrementProcessedProcessTraces() {
            processedProcessTraces.increment();
        }

        public void recordTraceProcessingTime(double time) {
            traceProcessingTimes.addValue(time);
        }

        public void accumulateProcessingTime(long millis) {
            cumulativeProcessingTime.add(millis);
        }
    }
}
