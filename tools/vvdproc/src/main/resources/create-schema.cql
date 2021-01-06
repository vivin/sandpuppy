CREATE TABLE IF NOT EXISTS experiments (
  id UUID PRIMARY KEY,
  experiment text
);

CREATE TABLE IF NOT EXISTS experiment_subjects (
  id UUID,
  experiment text,
  subject text,
  PRIMARY KEY (experiment, id)
);

CREATE TABLE IF NOT EXISTS experiment_subject_binaries (
  id UUID,
  experiment text,
  subject text,
  binary text,
  PRIMARY KEY (experiment, subject, id)
);

CREATE TABLE IF NOT EXISTS experiment_subject_binary_executions (
  id UUID,
  experiment text,
  subject text,
  binary text,
  execution text,
  PRIMARY KEY (experiment, subject, binary, id)
);

CREATE TABLE IF NOT EXISTS subject_files (
  id UUID,
  subject text,
  filename text,
  PRIMARY KEY (subject, id)
);

CREATE TABLE IF NOT EXISTS subject_file_functions (
  id UUID,
  subject text,
  filename text,
  function_name text,
  PRIMARY KEY (subject, filename, id)
);

CREATE TABLE IF NOT EXISTS subject_file_function_variables (
  id UUID,
  subject text,
  filename text,
  function_name text,
  declared_line int,
  variable_type text,
  variable_name text,
  PRIMARY KEY (subject, filename, function_name, declared_line, variable_type, id)
) WITH CLUSTERING ORDER BY (filename ASC, function_name ASC, declared_line ASC);

CREATE TABLE IF NOT EXISTS processes (
  id UUID,
  experiment text,
  subject text,
  binary text,
  execution text,
  pid text,
  PRIMARY KEY (experiment, subject, binary, execution, id)
);

CREATE TABLE IF NOT EXISTS process_variable_value_trace (
  id UUID,
  pid text,
  filename text,
  function_name text,
  declared_line int,
  variable_type text,
  variable_name text,
  timestamp bigint,
  modified_line int,
  variable_value text,
  PRIMARY KEY (pid, filename, function_name, declared_line, variable_type, variable_name, timestamp, id)
) WITH CLUSTERING ORDER BY (filename ASC, function_name ASC, declared_line ASC, variable_type ASC, variable_name ASC, timestamp ASC);

CREATE TABLE IF NOT EXISTS process_info (
  id UUID,
  pid text,
  exit_status text,
  input_size bigint,
  PRIMARY KEY (pid, id)
);