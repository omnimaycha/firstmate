#!/usr/bin/env bash
# Behavioral coverage for the private Captain-message archive: capture with
# multiline fidelity, serialized replay and redaction, private filesystem
# enforcement, role refusal, bounded retrieval, Captain-directed deletion,
# credential safety, and exclusion from the injected startup-memory budget.
set -u

# shellcheck source=tests/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

TMP_ROOT=$(fm_test_tmproot fm-captain-log)
CL="$ROOT/bin/fm-captain-log.sh"
BUDGET="$ROOT/bin/fm-startup-memory-budget.sh"

# A fresh, isolated data dir per case.
fresh_data() {
  local d="$TMP_ROOT/$1/data"
  mkdir -p "$d"
  printf '%s\n' "$d"
}

file_mode() {
  if [ "$(uname)" = Darwin ]; then
    /usr/bin/stat -f %Lp "$1"
  else
    stat -c %a "$1"
  fi
}

# --- retention policy is exposed through the executable help contract -------
help=$("$CL" --help)
assert_contains "$help" "bridge authenticated as the Captain" "help limits capture to bridge-authenticated Captain messages"
assert_contains "$help" "Never archive another group member's messages" "help excludes other group members"
assert_contains "$help" "Message content remains until Captain-directed" "help states the retention duration"
assert_contains "$help" "may contain secrets" "help does not claim secret-free storage"
assert_contains "$help" "sole privacy control is 0700" "help names file modes as the sole privacy control"
pass "help exposes the approved capture, retention, and privacy policy"

# --- capture with multiline fidelity ---------------------------------------
DATA=$(fresh_data capture)
out=$(printf 'line one\nline two 123\n' | FM_DATA_OVERRIDE="$DATA" "$CL" \
  append --role captain --chat 555 --msg-id 1001)
assert_contains "$out" "appended telegram:555:-:1001" "append reports the composed event id"
assert_present "$DATA/captain-log" "archive directory is created"
got=$(FM_DATA_OVERRIDE="$DATA" "$CL" search 'line two 123')
assert_contains "$got" "line one" "search returns the first line"
assert_contains "$got" "line two 123" "search returns the second line verbatim"
assert_contains "$got" "[captain]" "search shows the role"
assert_contains "$got" "id=telegram:555:-:1001" "search shows the event id as provenance"
pass "capture stores a multiline Captain message and search returns it verbatim"

# --- idempotent replay ------------------------------------------------------
out2=$(printf 'line one\nline two 123\n' | FM_DATA_OVERRIDE="$DATA" "$CL" \
  append --role captain --chat 555 --msg-id 1001)
assert_contains "$out2" "replay telegram:555:-:1001" "a repeated event id is a replay, not a second write"
count=$(grep -c . "$DATA/captain-log/"*.log)
assert_equals "1" "$count" "the replayed event is stored exactly once"
pass "append is idempotent on the event id"

# --- private permissions ----------------------------------------------------
dir_mode=$(file_mode "$DATA/captain-log")
file_mode_value=$(file_mode "$DATA/captain-log/"*.log)
assert_equals "700" "$dir_mode" "archive directory is 0700"
assert_equals "600" "$file_mode_value" "archive file is 0600"
pass "the archive is private by file mode"

# --- permissive pre-existing state is repaired on every access path ----------
DATA_P=$(fresh_data permissions)
mkdir -p "$DATA_P/captain-log"
month=$(date -u +%Y-%m)
: > "$DATA_P/captain-log/$month.log"
chmod 0755 "$DATA_P/captain-log"
chmod 0644 "$DATA_P/captain-log/$month.log"
printf 'repair on append' | FM_DATA_OVERRIDE="$DATA_P" "$CL" \
  append --role captain --chat 10 --msg-id 1 >/dev/null
assert_equals "700" "$(file_mode "$DATA_P/captain-log")" "append repairs the archive directory mode"
assert_equals "600" "$(file_mode "$DATA_P/captain-log/$month.log")" "append repairs the archive file mode"
chmod 0755 "$DATA_P/captain-log"
chmod 0644 "$DATA_P/captain-log/$month.log"
FM_DATA_OVERRIDE="$DATA_P" "$CL" search --all >/dev/null
assert_equals "700" "$(file_mode "$DATA_P/captain-log")" "search repairs the archive directory mode"
assert_equals "600" "$(file_mode "$DATA_P/captain-log/$month.log")" "search repairs the archive file mode"
chmod 0755 "$DATA_P/captain-log"
chmod 0644 "$DATA_P/captain-log/$month.log"
FM_DATA_OVERRIDE="$DATA_P" "$CL" redact --event-id telegram:10:-:1 --reason cleanup >/dev/null
assert_equals "700" "$(file_mode "$DATA_P/captain-log")" "redact repairs the archive directory mode"
assert_equals "600" "$(file_mode "$DATA_P/captain-log/$month.log")" "redact repairs the archive file mode"
pass "append, search, and redact repair private modes before access"

# --- symlinked archive state is refused on every access path -----------------
DATA_S=$(fresh_data symlinks)
OUTSIDE_S="$TMP_ROOT/symlink-outside"
mkdir -p "$OUTSIDE_S"
ln -s "$OUTSIDE_S" "$DATA_S/captain-log"
set +e
printf 'must not escape' | FM_DATA_OVERRIDE="$DATA_S" "$CL" \
  append --role captain --chat 11 --msg-id 1 >/dev/null 2>&1
rc_symlink_dir_append=$?
FM_DATA_OVERRIDE="$DATA_S" "$CL" search --all >/dev/null 2>&1
rc_symlink_dir_search=$?
FM_DATA_OVERRIDE="$DATA_S" "$CL" redact --event-id telegram:11:-:1 --reason x >/dev/null 2>&1
rc_symlink_dir_redact=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_symlink_dir_append" "append refuses a symlinked archive directory"
expect_code 2 "$rc_symlink_dir_search" "search refuses a symlinked archive directory"
expect_code 2 "$rc_symlink_dir_redact" "redact refuses a symlinked archive directory"
assert_absent "$OUTSIDE_S/$month.log" "a symlinked archive directory receives no content"

DATA_F=$(fresh_data file-symlinks)
mkdir -p "$DATA_F/captain-log"
OUTSIDE_FILE="$TMP_ROOT/outside-month.log"
printf 'outside bytes\n' > "$OUTSIDE_FILE"
ln -s "$OUTSIDE_FILE" "$DATA_F/captain-log/2000-01.log"
set +e
printf 'must not follow' | FM_DATA_OVERRIDE="$DATA_F" "$CL" \
  append --role captain --chat 12 --msg-id 1 >/dev/null 2>&1
rc_symlink_file_append=$?
FM_DATA_OVERRIDE="$DATA_F" "$CL" search --all >/dev/null 2>&1
rc_symlink_file_search=$?
FM_DATA_OVERRIDE="$DATA_F" "$CL" redact --event-id telegram:12:-:1 --reason x >/dev/null 2>&1
rc_symlink_file_redact=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_symlink_file_append" "append refuses a symlinked archive file"
expect_code 2 "$rc_symlink_file_search" "search refuses a symlinked archive file"
expect_code 2 "$rc_symlink_file_redact" "redact refuses a symlinked archive file"
assert_equals "outside bytes" "$(cat "$OUTSIDE_FILE")" "refused accesses leave the symlink target unchanged"
pass "all archive access paths fail closed on symlinks"

# --- role refusal: only captain roles are captured --------------------------
DATA_R=$(fresh_data refuse)
set +e
printf 'hi' | FM_DATA_OVERRIDE="$DATA_R" "$CL" append --role group --chat 9 --msg-id 1 >/dev/null 2>&1
rc_group=$?
printf 'hi' | FM_DATA_OVERRIDE="$DATA_R" "$CL" append --role somebody --chat 9 --msg-id 1 >/dev/null 2>&1
rc_unknown=$?
printf 'hi' | FM_DATA_OVERRIDE="$DATA_R" "$CL" append --role captain --msg-id 1 >/dev/null 2>&1
rc_nochat=$?
printf 'hi' | FM_DATA_OVERRIDE="$DATA_R" "$CL" append --role captain --chat 9 >/dev/null 2>&1
rc_nomsg=$?
printf 'hi' | FM_DATA_OVERRIDE="$DATA_R" "$CL" append --role captain --channel 'tele:gram' --chat 9 --msg-id 1 >/dev/null 2>&1
rc_channel_colon=$?
printf 'hi' | FM_DATA_OVERRIDE="$DATA_R" "$CL" append --role captain --chat '9:10' --msg-id 1 >/dev/null 2>&1
rc_chat_colon=$?
printf 'hi' | FM_DATA_OVERRIDE="$DATA_R" "$CL" append --role captain --chat 9 --topic '1:2' --msg-id 1 >/dev/null 2>&1
rc_topic_colon=$?
printf 'hi' | FM_DATA_OVERRIDE="$DATA_R" "$CL" append --role captain --chat 9 --msg-id '1:2' >/dev/null 2>&1
rc_msg_colon=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_group" "group role is refused"
expect_code 2 "$rc_unknown" "unknown role is refused"
expect_code 2 "$rc_nochat" "missing --chat is refused"
expect_code 2 "$rc_nomsg" "missing --msg-id is refused"
expect_code 2 "$rc_channel_colon" "a channel containing the event-id delimiter is refused"
expect_code 2 "$rc_chat_colon" "a chat containing the event-id delimiter is refused"
expect_code 2 "$rc_topic_colon" "a topic containing the event-id delimiter is refused"
expect_code 2 "$rc_msg_colon" "a message id containing the event-id delimiter is refused"
assert_absent "$DATA_R/captain-log" "a refused append writes nothing"
pass "non-Captain roles and ambiguous event-id components are refused"

# --- concurrent appends serialize the replay decision -----------------------
DATA_X=$(fresh_data concurrent)
START_X="$TMP_ROOT/concurrent.start"
pids=()
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
  (
    while [ ! -e "$START_X" ]; do sleep 0.01; done
    printf 'same event from worker %s' "$i" | FM_DATA_OVERRIDE="$DATA_X" "$CL" \
      append --role captain --chat 20 --msg-id 1 > "$TMP_ROOT/concurrent.$i.out"
  ) &
  pids+=("$!")
done
: > "$START_X"
for pid in "${pids[@]}"; do
  wait "$pid" || fail "a concurrent append failed"
done
concurrent_count=$(grep -F -c $'\ttelegram:20:-:1\t' "$DATA_X/captain-log/"*.log)
assert_equals "1" "$concurrent_count" "concurrent retries persist one event record"
replay_count=$(grep -h -c '^replay telegram:20:-:1$' "$TMP_ROOT"/concurrent.*.out | awk '{ total += $1 } END { print total + 0 }')
assert_equals "11" "$replay_count" "all losing concurrent appends report replay"
pass "concurrent appends make one serialized replay decision"

# --- credential safety: content never comes from argv or the environment ----
DATA_C=$(fresh_data creds)
set +e
TG_BOT_TOKEN=SECRET_BRIDGE_TOKEN printf 'ordinary message' | \
  FM_DATA_OVERRIDE="$DATA_C" "$CL" append --role captain --chat 7 --msg-id 1 >/dev/null 2>&1
# A stray positional (e.g. a token slipped onto the command line) is rejected.
FM_DATA_OVERRIDE="$DATA_C" "$CL" append --role captain --chat 7 --msg-id 2 SECRET_ON_ARGV >/dev/null 2>&1
rc_argv=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_argv" "content on the command line is rejected"
assert_no_grep "SECRET_BRIDGE_TOKEN" "$DATA_C/captain-log/"*.log "a bridge credential in the environment is never captured"
pass "content comes only from stdin or a file; argv and environment are never captured"

# --- bounded retrieval ------------------------------------------------------
DATA_B=$(fresh_data bounded)
for i in 1 2 3; do
  printf 'repeated topic number %s' "$i" | FM_DATA_OVERRIDE="$DATA_B" "$CL" \
    append --role captain --chat 8 --msg-id "$i" >/dev/null
done
bounded=$(FM_DATA_OVERRIDE="$DATA_B" "$CL" search --limit 2 'repeated topic')
shown=$(printf '%s\n' "$bounded" | grep -c '^-- ')
assert_equals "2" "$shown" "search output is bounded by --limit"
assert_contains "$bounded" "more match(es) not shown" "search names how many matches were withheld"
pass "retrieval output is bounded"

# --- Captain-directed redaction and purge -----------------------------------
DATA_D=$(fresh_data redact)
printf 'a password is hunter2' | FM_DATA_OVERRIDE="$DATA_D" "$CL" \
  append --role captain --chat 9 --msg-id 50 >/dev/null
printf 'keep this one' | FM_DATA_OVERRIDE="$DATA_D" "$CL" \
  append --role captain --chat 9 --msg-id 51 >/dev/null
FM_DATA_OVERRIDE="$DATA_D" "$CL" redact --event-id telegram:9:-:50 --reason "secret" >/dev/null
after=$(FM_DATA_OVERRIDE="$DATA_D" "$CL" search --all)
assert_contains "$after" "(redacted)" "a redacted entry is marked"
assert_contains "$after" "by captain order: secret" "the redaction records the reason"
assert_not_contains "$after" "hunter2" "the secret text is gone after redaction"
assert_contains "$after" "keep this one" "redaction leaves other entries intact"
FM_DATA_OVERRIDE="$DATA_D" "$CL" redact --event-id telegram:9:-:50 --purge >/dev/null
purged=$(FM_DATA_OVERRIDE="$DATA_D" "$CL" search --all)
assert_not_contains "$purged" "telegram:9:-:50" "a purged entry is hidden from retrieval"
assert_contains "$purged" "keep this one" "purge leaves other entries intact"
retry=$(printf 'attempted resurrection' | FM_DATA_OVERRIDE="$DATA_D" "$CL" \
  append --role captain --chat 9 --msg-id 50)
assert_contains "$retry" "replay telegram:9:-:50" "a bridge retry cannot resurrect purged content"
FM_DATA_OVERRIDE="$DATA_D" "$CL" redact --event-id telegram:9:-:50 --reason later >/dev/null
after_retry=$(FM_DATA_OVERRIDE="$DATA_D" "$CL" search --all)
assert_not_contains "$after_retry" "attempted resurrection" "the retried body remains absent"
assert_not_contains "$after_retry" "telegram:9:-:50" "later redaction does not expose a purge tombstone"
set +e
FM_DATA_OVERRIDE="$DATA_D" "$CL" redact --event-id telegram:9:-:999 --reason x >/dev/null 2>&1
rc_missing=$?
set -e 2>/dev/null || true
expect_code 3 "$rc_missing" "redacting an unknown event id reports not-found"
pass "purge preserves replay identity without retaining or exposing content"

# --- append cannot be lost under a concurrent redaction rewrite -------------
DATA_T=$(fresh_data transaction)
TX_TMP="$TMP_ROOT/transaction-tmp"
mkdir -p "$TX_TMP"
LARGE_BODY="$TMP_ROOT/large-body"
UNIQUE_BODY="$TMP_ROOT/unique-body"
dd if=/dev/zero bs=1048576 count=4 2>/dev/null | tr '\000' x > "$LARGE_BODY"
printf 'survives concurrent redact' > "$UNIQUE_BODY"
printf 'redact this' | FM_DATA_OVERRIDE="$DATA_T" "$CL" \
  append --role captain --chat 30 --msg-id victim >/dev/null
FM_DATA_OVERRIDE="$DATA_T" "$CL" append --role captain --chat 30 --msg-id large \
  --file "$LARGE_BODY" >/dev/null
TMPDIR="$TX_TMP" FM_DATA_OVERRIDE="$DATA_T" "$CL" \
  redact --event-id telegram:30:-:victim --reason concurrent >/dev/null &
redact_pid=$!
replacement_seen=0
replacement_checks=0
while [ "$replacement_checks" -lt 500 ]; do
  for candidate in "$TX_TMP"/fm-captain-log.* "$DATA_T/captain-log"/.fm-captain-log.*; do
    if [ -e "$candidate" ]; then
      replacement_seen=1
      break
    fi
  done
  [ "$replacement_seen" = 0 ] || break
  replacement_checks=$((replacement_checks + 1))
  sleep 0.01
done
[ "$replacement_seen" = 1 ] || fail "redaction never entered its rewrite transaction"
FM_DATA_OVERRIDE="$DATA_T" "$CL" append --role captain --chat 30 --msg-id concurrent \
  --file "$UNIQUE_BODY" >/dev/null
wait "$redact_pid" || fail "concurrent redaction failed"
transaction_result=$(FM_DATA_OVERRIDE="$DATA_T" "$CL" search 'survives concurrent redact')
assert_contains "$transaction_result" "survives concurrent redact" "redaction does not overwrite a concurrent append"
pass "append and redaction share one lossless transaction boundary"

# --- excluded from the injected startup-memory budget -----------------------
HOME_B="$TMP_ROOT/budget"
mkdir -p "$HOME_B/config" "$HOME_B/data"
printf '7500\n' > "$HOME_B/config/startup-memory-budget"
printf '# Captain preferences\nsome rule\n' > "$HOME_B/data/captain.md"
printf 'secret teaching that must not be budget counted' | \
  FM_DATA_OVERRIDE="$HOME_B/data" "$CL" append --role captain --chat 1 --msg-id 1 >/dev/null
report=$(FM_HOME="$HOME_B" "$BUDGET" report)
assert_contains "$report" "file=data/captain.md" "budget still measures the curated files"
assert_not_contains "$report" "captain-log" "the raw archive is not part of the budgeted startup memory"
pass "the raw archive is excluded from the injected startup-memory budget"

pass "fm-captain-log: all behaviors verified"
