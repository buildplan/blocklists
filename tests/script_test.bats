#!/usr/bin/env bats

setup() {
  # Create a temporary directory for our mocks and fake database
  export MOCK_DIR="$BATS_TEST_DIRNAME/mocks"
  export FAKE_DB_DIR="$BATS_TEST_DIRNAME/fake_db"
  mkdir -p "$MOCK_DIR" "$FAKE_DB_DIR"

  # Ensure our mocks take precedence in the PATH
  export PATH="$MOCK_DIR:$PATH"

  # Set environment variables expected by the scripts
  export DB_PATH="$FAKE_DB_DIR/crowdsec.db"
  export CONTAINER_NAME="crowdsec"

  # Create a fake database file
  echo "dummy data" > "$DB_PATH"
}

teardown() {
  # Clean up after each test
  rm -rf "$MOCK_DIR" "$FAKE_DB_DIR"
}

# Helper function to create a mock command
create_mock() {
  local cmd_name="$1"
  local mock_behavior="$2"
  echo "#!/bin/sh" > "$MOCK_DIR/$cmd_name"
  echo "$mock_behavior" >> "$MOCK_DIR/$cmd_name"
  chmod +x "$MOCK_DIR/$cmd_name"
}

@test "Exits gracefully when DB size is under threshold" {
  # Setup: Create a 5MB fake file
  dd if=/dev/zero of="$DB_PATH" bs=1M count=5 2>/dev/null

  # Mock docker to simulate running container
  create_mock "docker" '
    if [ "$1" = "ps" ]; then exit 0; fi
    # Fallback to real wc for size calculation in script
    if [ "$1" = "exec" ] && echo "$*" | grep -q "wc -c"; then wc -c < "$DB_PATH"; exit 0; fi
  '

  # Run script with 10MB threshold
  run ./scripts/crowdsec-db-cleanup.sh 10 48h

  # Assertions
  [ "$status" -eq 0 ]
  [[ "$output" == *"is under the threshold"* ]]
  [[ "$output" == *"No maintenance required. Exiting."* ]]
}

@test "Performs cleanup when DB size exceeds threshold" {
  # Setup: Create a 15MB fake file (above 10MB threshold)
  dd if=/dev/zero of="$DB_PATH" bs=1M count=15 2>/dev/null

  # We need to track the commands called to verify the cleanup sequence
  export CALL_LOG="$BATS_TEST_DIRNAME/calls.log"
  touch "$CALL_LOG"

  # Mock docker to log actions and simulate size changes
  create_mock "docker" '
    if [ "$1" = "ps" ]; then exit 0; fi

    # Size check before and after
    if [ "$1" = "exec" ] && echo "$*" | grep -q "wc -c"; then
      # If we already vacuumed, return smaller size
      if grep -q "run.*alpine.*sqlite3.*VACUUM" "'$CALL_LOG'" 2>/dev/null; then
         echo "5242880" # 5MB
      else
         echo "15728640" # 15MB
      fi
      exit 0
    fi

    # Log other commands to verify execution order
    echo "docker $*" >> "'$CALL_LOG'"
  '

  # Mock sleep so tests run instantly
  create_mock "sleep" 'exit 0'

  # Run script with 10MB threshold
  run ./scripts/crowdsec-db-cleanup.sh 10 48h

  # Check script exit status
  [ "$status" -eq 0 ]

  # Verify log output contains expected phases
  [[ "$output" == *"Threshold exceeded! Starting cleanup process..."* ]]
  [[ "$output" == *"[1/4] Flushing alerts"* ]]
  [[ "$output" == *"[4/4] Starting '*"* ]]
  [[ "$output" == *"Database size is now under the threshold. Cleanup successful!"* ]]

  # Verify the actual sequence of commands executed
  run cat "$CALL_LOG"
  [[ "${lines[0]}" == *"exec crowdsec cscli alerts flush"* ]]
  [[ "${lines[1]}" == *"stop crowdsec"* ]]
  [[ "${lines[2]}" == *"run --rm"* ]]
  [[ "${lines[2]}" == *"VACUUM; PRAGMA optimize;"* ]]
  [[ "${lines[3]}" == *"start crowdsec"* ]]

  rm -f "$CALL_LOG"
}

@test "Fails if container is not running" {
  # Mock docker ps to return failure (simulating stopped container)
  create_mock "docker" '
    if [ "$1" = "ps" ]; then exit 1; fi
  '

  run ./scripts/crowdsec-db-cleanup.sh 10 48h

  [ "$status" -eq 1 ]
  [[ "$output" == *"Error: Container 'crowdsec' is not running."* ]]
}

@test "cs-db-cleanup detects native mode correctly" {
  # Mock cscli and systemctl to simulate native host
  create_mock "cscli" 'exit 0'
  create_mock "systemctl" 'echo "systemctl $*" >> "'$BATS_TEST_DIRNAME/calls.log'"'
  create_mock "sqlite3" 'echo "sqlite3 $*" >> "'$BATS_TEST_DIRNAME/calls.log'"'
  create_mock "sleep" 'exit 0'

  # Create a dummy config dir to trigger native detection
  export CROWDSEC_ETC="$BATS_TEST_DIRNAME/etc_crowdsec"
  mkdir -p "$CROWDSEC_ETC"

  # Inject the test directory into the script using sed for the test run only
  # (Since the script hardcodes /etc/crowdsec)
  sed "s|/etc/crowdsec|$CROWDSEC_ETC|g" ./scripts/cs-db-cleanup.sh > "$BATS_TEST_DIRNAME/cs-test.sh"
  chmod +x "$BATS_TEST_DIRNAME/cs-test.sh"

  dd if=/dev/zero of="$DB_PATH" bs=1M count=15 2>/dev/null

  run "$BATS_TEST_DIRNAME/cs-test.sh" 10 48h

  [ "$status" -eq 0 ]
  [[ "$output" == *"Mode: Native (Host)"* ]]

  rm -rf "$CROWDSEC_ETC" "$BATS_TEST_DIRNAME/cs-test.sh" "$BATS_TEST_DIRNAME/calls.log"
}
