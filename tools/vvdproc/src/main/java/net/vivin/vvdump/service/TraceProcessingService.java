package net.vivin.vvdump.service;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.model.VariableValueEndTrace;
import net.vivin.vvdump.model.VariableValueTrace;
import net.vivin.vvdump.repository.VariableValueTraceRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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
import java.util.HashSet;
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
    private final VariableValueTraceRepository variableValueRepository;
    private final ExecutorService pipeReaderExecutor;
    private final ExecutorService dbQueryExecutor;

    private final Set<Integer> pids = new HashSet<>();

    @Autowired
    public TraceProcessingService(ApplicationContext applicationContext, @Qualifier("cassandra") VariableValueTraceRepository variableValueRepository) {
        this.applicationContext = applicationContext;
        this.variableValueRepository = variableValueRepository;
        this.pipeReaderExecutor = Executors.newSingleThreadExecutor();
        this.dbQueryExecutor = Executors.newWorkStealingPool(32);
    }

    @PostConstruct
    public void init() {
        CompletableFuture.runAsync(this::readPipe, pipeReaderExecutor)
            .whenCompleteAsync((v, e) -> ((ConfigurableApplicationContext) applicationContext).close());
    }

    private void readPipe() {
        final AtomicInteger processCount = new AtomicInteger(0);
        final AtomicInteger traceCount = new AtomicInteger(0);

        VariableValueEndTrace killedVariableValueEndTrace = null;
        try {
            var pipe = new RandomAccessFile(namedPipePath, "rw");
            log.info("Listening...");

            String line;
            while ((line = pipe.readLine()) != null && !END_TRACE_MARKER.equals(line)) {
                var components = line.split(":");
                if (components.length != NUM_END_TRACE_COMPONENTS) {
                    var variableValueTrace = VariableValueTrace.fromStringTrace(line);

                    if (!pids.contains(variableValueTrace.getPid())) {
                        log.info("Recording trace for new process {}", variableValueTrace.getPid());
                        //log.info(variableValueTrace.toString());
                        pids.add(variableValueTrace.getPid());
                        processCount.incrementAndGet();
                    }

                    traceCount.incrementAndGet();
                    dbQueryExecutor.submit(() -> {
                        variableValueRepository.insertVariableValueTrace(variableValueTrace);
                        traceCount.decrementAndGet();
                    });
                } else {
                    var variableValueEndTrace = VariableValueEndTrace.fromStringTrace(line);
                    //log.info(variableValueEndTrace.toString());
                    if (!"killed".equals(variableValueEndTrace.getExitStatus())) {
                        traceCount.incrementAndGet();
                        dbQueryExecutor.submit(() -> {
                            variableValueRepository.insertFuzzedProcessInfo(variableValueEndTrace);
                            traceCount.decrementAndGet();
                            processCount.decrementAndGet();
                        });
                    } else {
                        killedVariableValueEndTrace = variableValueEndTrace;
                        processCount.decrementAndGet();
                    }
                }
            }

            /*for (int i = 0; i < 10; i++) {
                log.info("Fuzzer has shut down. No more incoming traces. null: {}, end trace: {}", line == null, line);
            }*/
        } catch (FileNotFoundException e) {
            throw new UncheckedIOException("Could not find named pipe", e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        log.info("Fuzzer has shut down. No more incoming traces.");
        log.info("Shutting down db query executor. {} traces from {} processes remaining.", traceCount.get(), processCount.get());
        dbQueryExecutor.shutdown();
        while (!dbQueryExecutor.isTerminated()) {
            try {
                dbQueryExecutor.awaitTermination(3, TimeUnit.SECONDS);
                log.info("Waiting on db query executor to terminate ({} traces from {} processes remaining)...", traceCount.get(), processCount.get());
            } catch (InterruptedException e) {
                if (killedVariableValueEndTrace != null) {
                    variableValueRepository.deleteVariableValueTraces(killedVariableValueEndTrace);
                }

                throw new RuntimeException(e);
            }
        }

        if (killedVariableValueEndTrace != null) {
            variableValueRepository.deleteVariableValueTraces(killedVariableValueEndTrace);
        }
    }

    @PreDestroy
    public void destroy() throws InterruptedException {
        log.info("Shutting down pipe reader executor...");
        pipeReaderExecutor.shutdown();

        var attempts = 3;
        while (!pipeReaderExecutor.isTerminated() && attempts > 0) {
            pipeReaderExecutor.awaitTermination(3, TimeUnit.SECONDS);
            attempts--;
            log.info("Waiting on pipe reader executor to terminate...");
        }

        pipeReaderExecutor.shutdownNow();
    }
}
// Fixed Thread Pool:
// 32 started at 17:35:04.991
// 32 ended at 18:09:52.625 (35 min)
// 32 had 40.4k execs; 134.667 execs/s
// 32 had 2,073,850 traces remaining to process; 987.547 traces/s
//
// 16 started at 18:16:07.905
// 16 ended at 19:00:34.595 (44 min)
// 16 had 39.4k execs; 131.333 execs/s
// 16 had 2,286,812 traces remaining to process; 866.216 traces/s
//
// Work Stealing Pool:
// 64 started at 20:37:19.271
// 64 ended at 21:29:02.760 (52 min)
// 64 had 43.9k execs; 146.333 execs/s
// 64 had 2,519,268 traces remaining to process; 807.457 traces/s
//
// 32 started at 00:01:59.255  << probably the best? (do one more and compare with another 32 fixed thread pool)
// 32 ended at 00:42:46.181 (40 min)
// 32 had 44.8k execs; 149.333 execs/s
// 32 had 2,431,689 traces remaining to process; 1013.203 traces/s
//
// 32 started at 21:51:07.961
// 32 ended at 22:30:38.091 (39 min)
// 32 had 41.6 execs; 138.666 execs/s
// 32 had 2,196,769 traces remaining to process;  938.790 traces/s
//
// 16 started at 19:16:39.638
// 16 ended at 20:05:34.806 (49 min)
// 16 had 43.4k execs; 144.667 execs/s
// 16 had 2,485,337 traces remaining to process; 845.342 traces/s
//
// Try inserting in cassandra.
//
// partition key: (experiment_name, subject, binary_context, exec_context, pid)
// clustering keys: (filename, function_name, variable_type, variable_name, declared_line)
// rest: modified_line, variable_value, timestamp

