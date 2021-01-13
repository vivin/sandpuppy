CREATE TABLE IF NOT EXISTS experiments (
  experiment text PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS experiment_subjects (
  experiment text,
  subject text,
  PRIMARY KEY (experiment, subject)
);

CREATE TABLE IF NOT EXISTS experiment_subject_binaries (
  experiment text,
  subject text,
  binary text,
  PRIMARY KEY (experiment, subject, binary)
);

CREATE TABLE IF NOT EXISTS experiment_subject_binary_executions (
  experiment text,
  subject text,
  binary text,
  execution text,
  PRIMARY KEY (experiment, subject, binary, execution)
);

CREATE TABLE IF NOT EXISTS subject_files (
  subject text,
  filename text,
  PRIMARY KEY (subject, filename)
);

CREATE TABLE IF NOT EXISTS subject_file_functions (
  subject text,
  filename text,
  function_name text,
  PRIMARY KEY (subject, filename, function_name)
);

CREATE TABLE IF NOT EXISTS subject_file_function_variables (
  subject text,
  filename text,
  function_name text,
  variable_type text,
  variable_name text,
  declared_line int,
  PRIMARY KEY (subject, filename, function_name, variable_type, variable_name, declared_line)
);

CREATE TABLE IF NOT EXISTS subject_file_function_variables_by_declaration_order (
  subject text,
  filename text,
  function_name text,
  declared_line int,
  variable_type text,
  variable_name text,
  PRIMARY KEY (subject, filename, function_name, declared_line, variable_type, variable_name)
);

CREATE TABLE IF NOT EXISTS processes (
  experiment text,
  subject text,
  binary text,
  execution text,
  pid text,
  exit_status text,
  input_size bigint,
  PRIMARY KEY (experiment, subject, binary, execution, pid)
);
CREATE INDEX IF NOT EXISTS exit_status_index ON processes (exit_status);

CREATE TABLE IF NOT EXISTS process_variable_value_traces (
  id UUID,
  experiment text,
  subject text,
  binary text,
  execution text,
  pid text,
  exit_status text,
  input_size bigint,
  filename text,
  function_name text,
  declared_line int,
  variable_type text,
  variable_name text,
  timestamp bigint,
  modified_line int,
  variable_value text,
  PRIMARY KEY (experiment, subject, binary, execution, exit_status, filename, function_name, declared_line, variable_type, variable_name, pid, timestamp, id)
);
