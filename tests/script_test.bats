#!/usr/bin/env bats

setup() {
  export MOCK_DIR="$BATS_TEST_DIRNAME/mocks"
  export FAKE_DB_DIR="$BATS_TEST_DIRNAME/fake_db"
  mkdir -p "$MOCK_DIR" "$FAKE_DB_DIR"
  export PATH="$MOCK_DIR:$PATH"

  export DB_PATH="$FAKE_DB_DIR/crowdsec.db"
  export CONTAINER_NAME="crowdsec"

  # Dynamically find the scripts regardless of where BATS is executed from
  if [ -f "$BATS_TEST_DIRNAME/../crowdsec-db-cleanup.sh" ]; then
     export SCRIPT1="$BATS_TEST_DIRNAME/../crowdsec-db-cleanup.sh"
     export SCRIPT2="$BATS_TEST_DIRNAME/../cs-db-cleanup.sh"
  else
     echo "ERROR: Could not find scripts to test. Check your repository paths!" >&3
     exit 1
  fi

  # Ensure scripts are executable
  chmod +x "$SCRIPT1" "$SCRIPT2"
}

teardown() {
  rm -rf "$MOCK_DIR" "$FAKE_DB_DIR"
}

create_mock() {
  local cmd_name="$1"
  local mock_behavior="$2"
  echo "#!/bin/sh" > "$MOCK_DIR/$cmd_name"
  echo "$mock_behavior" >> "$MOCK_DIR/$cmd_name"
  chmod +x "$MOCK_DIR/$cmd_name"
}

@test "Exits gracefully when DB size is under threshold" {
  # Create a 5MB fake file cleanly
  truncate -s 5M "$DB_PATH" 2>/dev/null || dd if=/dev/zero of="$DB_PATH" bs=1M count=5 2>/dev/null

  create_mock "docker" '
    if [ "$1" = "ps" ]; then exit 0; fi
    if [ "$1" = "exec" ] && echo "$*" | grep -q "wc -c"; then
      # strip spaces just in case GNU wc formatting breaks math
      wc -c < "$DB_PATH" | tr -d " "
      exit 0
    fi
  '

  run "$SCRIPT1" 10 48h

  # Print to logs if test fails (BATS swallows this if test passes)
  echo "Status: $status"
  echo "Output: $output"

  [ "$status" -eq 0 ]
  [[ "$output" == *"is under the threshold"* ]]
}

@test "Performs cleanup when DB size exceeds threshold" {
  truncate -s 15M "$DB_PATH" 2>/dev/null || dd if=/dev/zero of="$DB_PATH" bs=1M count=15 2>/dev/null

  export CALL_LOG="$BATS_TEST_DIRNAME/calls.log"
  touch "$CALL_LOG"

  create_mock "docker" '
    if [ "$1" = "ps" ]; then exit 0; fi
    if [ "$1" = "exec" ] && echo "$*" | grep -q "wc -c"; then
      if grep -q "run.*alpine.*sqlite3.*VACUUM" "'$CALL_LOG'" 2>/dev/null; then
         echo "5242880"
      else
         echo "15728640"
      fi
      exit 0
    fi
    echo "docker $*" >> "'$CALL_LOG'"
  '
  create_mock "sleep" 'exit 0'

  run "$SCRIPT1" 10 48h

  echo "Status: $status"
  echo "Output: $output"

  [ "$status" -eq 0 ]
  [[ "$output" == *"Threshold exceeded! Starting cleanup process..."* ]]

  run cat "$CALL_LOG"
  [[ "${lines[0]}" == *"exec crowdsec cscli alerts flush"* ]]
  [[ "${lines[1]}" == *"stop crowdsec"* ]]

  rm -f "$CALL_LOG"
}

@test "Fails if container is not running" {
  create_mock "docker" '
    if [ "$1" = "ps" ]; then exit 1; fi
  '

  run "$SCRIPT1" 10 48h

  echo "Status: $status"
  echo "Output: $output"

  [ "$status" -eq 1 ]
  [[ "$output" == *"Error: Container 'crowdsec' is not running."* ]]
}

@test "cs-db-cleanup detects native mode correctly" {
  create_mock "cscli" 'exit 0'
  create_mock "systemctl" 'echo "systemctl $*" >> "'$BATS_TEST_DIRNAME/calls.log'"'
  create_mock "sqlite3" 'echo "sqlite3 $*" >> "'$BATS_TEST_DIRNAME/calls.log'"'
  create_mock "sleep" 'exit 0'

  export CROWDSEC_ETC="$BATS_TEST_DIRNAME/etc_crowdsec"
  mkdir -p "$CROWDSEC_ETC"

  sed "s|/etc/crowdsec|$CROWDSEC_ETC|g" "$SCRIPT2" > "$BATS_TEST_DIRNAME/cs-test.sh"
  chmod +x "$BATS_TEST_DIRNAME/cs-test.sh"

  truncate -s 15M "$DB_PATH" 2>/dev/null || dd if=/dev/zero of="$DB_PATH" bs=1M count=15 2>/dev/null

  run "$BATS_TEST_DIRNAME/cs-test.sh" 10 48h

  [ "$status" -eq 0 ]

  # Use grep for foolproof multi-line string matching
  echo "$output" | grep -q "Mode: Native (Host)"

  # Verify it actually called the native linux commands!
  run cat "$BATS_TEST_DIRNAME/calls.log"
  [[ "${lines[0]}" == *"systemctl stop crowdsec"* ]]
  [[ "${lines[1]}" == *"sqlite3 $DB_PATH"* ]]
  [[ "${lines[2]}" == *"systemctl start crowdsec"* ]]

  rm -rf "$CROWDSEC_ETC" "$BATS_TEST_DIRNAME/cs-test.sh" "$BATS_TEST_DIRNAME/calls.log"
}
