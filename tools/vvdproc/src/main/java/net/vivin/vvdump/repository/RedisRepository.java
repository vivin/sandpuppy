package net.vivin.vvdump.repository;

import lombok.extern.slf4j.Slf4j;
import net.vivin.vvdump.model.FullTraceItem;
import org.apache.commons.lang3.tuple.Pair;
import org.redisson.api.RedissonClient;
import org.redisson.client.codec.StringCodec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import javax.annotation.PostConstruct;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

@Slf4j
@Repository("redis")
public class RedisRepository implements TraceRepository {

    private static final String SUBJECT_FILES_KEY_FORMAT = "%s.files";
    private static final String SUBJECT_FILE_FUNCTIONS_KEY_FORMAT = "%s:%s.functions";

    private static final String SUBJECT_FILE_FUNCTION_VARIABLES_KEY_FORMAT = "%s:%s:%s.variables";
    private static final String SUBJECT_FILE_FUNCTION_VARIABLE_VALUE_FORMAT = "%d,%s,%s";

    private static final String VARIABLE_EXIT_STATUS_PIDS_KEY_FORMAT = "%s:%s:%s:%s:%s:%s:%d:%s:%s:%s";
    private static final String VARIABLE_EXIT_STATUS_PIDS_VALUE_FORMAT = "%d,%d";

    private static final String VARIABLE_VALUE_TRACE_KEY_FORMAT = "%s:%s:%s:%s:%s:%s:%d:%s:%s:%d";
    private static final String VARIABLE_VALUE_TRACE_VALUE_FORMAT = "%s,%d,%s";

    private static final String FIXED_CLASS_VARIABLES_SET_KEY_FORMAT = "%s:%s:%s:%s.fixed_class_variables";
    private static final String FIXED_CLASS_VARIABLES_SET_VALUE_FORMAT = "%s::%s::%s:%s:%d";

    private Set<String> fixedClassVariablesSet = null;

    private final Set<Function<FullTraceItem, Pair<String, String>>> itemToEntryFunctions = Set.of(
        this::getSubjectFileEntry,
        this::getSubjectFileFunctionEntry,
        this::getSubjectFileFunctionVariableEntry,
        this::getVariableExitStatusPidEntry,
        this::getVariableValueTraceEntry
    );

    private final RedissonClient redissonClient;

    @Autowired
    public RedisRepository(RedissonClient redissonClient) {
        this.redissonClient = redissonClient;
    }

    @Override
    public void insertFullTraceItem(FullTraceItem fullTraceItem) {
        if (!shouldInsertItem(fullTraceItem)) {
            return;
        }

        this.itemToEntryFunctions.forEach(function -> {
            final var entry = function.apply(fullTraceItem);
            redissonClient.getSet(entry.getLeft(), StringCodec.INSTANCE).add(entry.getRight());
        });
    }

    private boolean shouldInsertItem(FullTraceItem fullTraceItem) {
        initializeFixedClassVariablesSetIfNecessary(fullTraceItem);

        return !this.fixedClassVariablesSet.contains(String.format(
            FIXED_CLASS_VARIABLES_SET_VALUE_FORMAT,
            fullTraceItem.getFilename(),
            fullTraceItem.getFunctionName(),
            fullTraceItem.getVariableType(),
            fullTraceItem.getVariableName(),
            fullTraceItem.getDeclaredLine()
        ));
    }

    private void initializeFixedClassVariablesSetIfNecessary(FullTraceItem fullTraceItem) {
        if (this.fixedClassVariablesSet != null) {
            return;
        }

        var setName = String.format(
            FIXED_CLASS_VARIABLES_SET_KEY_FORMAT,
            fullTraceItem.getExperimentName(),
            fullTraceItem.getSubject(),
            fullTraceItem.getBinaryContext(),
            fullTraceItem.getExecContext()
        );
        if (this.redissonClient.getKeys().countExists(setName) == 0) {
            this.fixedClassVariablesSet = Collections.emptySet();
            return;
        }

        this.fixedClassVariablesSet = this.redissonClient.getSet(setName, StringCodec.INSTANCE);
    }

    private Pair<String, String> getSubjectFileEntry(FullTraceItem fullTraceItem) {
        return Pair.of(
            String.format(
                SUBJECT_FILES_KEY_FORMAT,
                fullTraceItem.getSubject()
            ),
            fullTraceItem.getFilename()
        );
    }

    private Pair<String, String> getSubjectFileFunctionEntry(FullTraceItem fullTraceItem) {
        return Pair.of(
            String.format(
                SUBJECT_FILE_FUNCTIONS_KEY_FORMAT,
                fullTraceItem.getSubject(),
                fullTraceItem.getFilename()
            ),
            fullTraceItem.getFunctionName()
        );
    }

    private Pair<String, String> getSubjectFileFunctionVariableEntry(FullTraceItem fullTraceItem) {
        return Pair.of(
            String.format(
                SUBJECT_FILE_FUNCTION_VARIABLES_KEY_FORMAT,
                fullTraceItem.getSubject(),
                fullTraceItem.getFilename(),
                fullTraceItem.getFunctionName()
            ),
            String.format(
                SUBJECT_FILE_FUNCTION_VARIABLE_VALUE_FORMAT,
                fullTraceItem.getDeclaredLine(),
                fullTraceItem.getVariableType(),
                fullTraceItem.getVariableName()
            )
        );
    }

    private Pair<String, String> getVariableExitStatusPidEntry(FullTraceItem fullTraceItem) {
        return Pair.of(
            String.format(
                VARIABLE_EXIT_STATUS_PIDS_KEY_FORMAT,
                fullTraceItem.getExperimentName(),
                fullTraceItem.getSubject(),
                fullTraceItem.getBinaryContext(),
                fullTraceItem.getExecContext(),
                fullTraceItem.getFilename(),
                fullTraceItem.getFunctionName(),
                fullTraceItem.getDeclaredLine(),
                fullTraceItem.getVariableType(),
                fullTraceItem.getVariableName(),
                fullTraceItem.getExitStatus()
            ),
            String.format(
                VARIABLE_EXIT_STATUS_PIDS_VALUE_FORMAT,
                fullTraceItem.getPid(),
                fullTraceItem.getInputSize()
            )
        );
    }
    private Pair<String, String> getVariableValueTraceEntry(FullTraceItem fullTraceItem) {
        return Pair.of(
            String.format(
                VARIABLE_VALUE_TRACE_KEY_FORMAT,
                fullTraceItem.getExperimentName(),
                fullTraceItem.getSubject(),
                fullTraceItem.getBinaryContext(),
                fullTraceItem.getExecContext(),
                fullTraceItem.getFilename(),
                fullTraceItem.getFunctionName(),
                fullTraceItem.getDeclaredLine(),
                fullTraceItem.getVariableType(),
                fullTraceItem.getVariableName(),
                fullTraceItem.getPid()
            ),
            String.format(
                VARIABLE_VALUE_TRACE_VALUE_FORMAT,
                fullTraceItem.getTimestamp().toString(),
                fullTraceItem.getModifiedLine(),
                fullTraceItem.getVariableValue()
            )
        );
    }
}
