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
assert_contains "$help" "shared PID-liveness lock" "help identifies the shared archive lock contract"
assert_contains "$help" "accepted residual risk" "help discloses the accepted PID-reuse wait risk"
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

BASE64_SHIM_DIR="$TMP_ROOT/base64-shim"
REAL_BASE64=$(command -v base64)
if printf 'Zg==' | "$REAL_BASE64" -d >/dev/null 2>&1; then
  REAL_BASE64_DECODE_FLAG=-d
else
  REAL_BASE64_DECODE_FLAG=-D
fi
mkdir -p "$BASE64_SHIM_DIR"
cat > "$BASE64_SHIM_DIR/base64" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -d) exit 64 ;;
  -D)
    shift
    exec "$FM_TEST_REAL_BASE64" "$FM_TEST_REAL_BASE64_DECODE_FLAG" "$@"
    ;;
  *) exec "$FM_TEST_REAL_BASE64" "$@" ;;
esac
EOF
chmod +x "$BASE64_SHIM_DIR/base64"
portable_decode=$(FM_TEST_REAL_BASE64="$REAL_BASE64" \
  FM_TEST_REAL_BASE64_DECODE_FLAG="$REAL_BASE64_DECODE_FLAG" \
  PATH="$BASE64_SHIM_DIR:$PATH" FM_DATA_OVERRIDE="$DATA" \
  "$CL" search 'line two 123')
assert_contains "$portable_decode" "line two 123" "search falls back to the BSD base64 decode interface"
pass "archive decoding supports GNU and BSD base64 interfaces"

ENCODE_FAIL_SHIM_DIR="$TMP_ROOT/encode-fail-shim"
ENCODE_FILE="$TMP_ROOT/encode-file"
mkdir -p "$ENCODE_FAIL_SHIM_DIR"
printf 'file content must not be truncated' > "$ENCODE_FILE"
cat > "$ENCODE_FAIL_SHIM_DIR/base64" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -d|-D) exec "$FM_TEST_REAL_BASE64" "$@" ;;
  *) printf 'cGFydGlhbA=='; exit 64 ;;
esac
EOF
chmod +x "$ENCODE_FAIL_SHIM_DIR/base64"
DATA_E=$(fresh_data encode-failure)
set +e
printf 'stdin content must not be truncated' | FM_TEST_REAL_BASE64="$REAL_BASE64" \
  PATH="$ENCODE_FAIL_SHIM_DIR:$PATH" FM_DATA_OVERRIDE="$DATA_E" "$CL" \
    append --role captain --chat 556 --msg-id stdin >/dev/null 2>&1
rc_stdin_encode=$?
FM_TEST_REAL_BASE64="$REAL_BASE64" PATH="$ENCODE_FAIL_SHIM_DIR:$PATH" \
  FM_DATA_OVERRIDE="$DATA_E" "$CL" append --role captain --chat 556 \
    --msg-id file --file "$ENCODE_FILE" >/dev/null 2>&1
rc_file_encode=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_stdin_encode" "append rejects a failed stdin encoding pipeline"
expect_code 2 "$rc_file_encode" "append rejects a failed file encoding pipeline"
assert_absent "$DATA_E/captain-log" "failed message encoding publishes no archive state"
printf 'redaction content remains intact' | FM_DATA_OVERRIDE="$DATA_E" "$CL" \
  append --role captain --chat 556 --msg-id redact >/dev/null
set +e
FM_TEST_REAL_BASE64="$REAL_BASE64" PATH="$ENCODE_FAIL_SHIM_DIR:$PATH" \
  FM_DATA_OVERRIDE="$DATA_E" "$CL" redact \
    --event-id telegram:556:-:redact --reason requested >/dev/null 2>&1
rc_tombstone_encode=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_tombstone_encode" "redact rejects a failed tombstone encoding pipeline"
encode_failure_result=$(FM_DATA_OVERRIDE="$DATA_E" "$CL" search 'redaction content remains intact')
assert_contains "$encode_failure_result" "redaction content remains intact" "failed tombstone encoding leaves content unchanged"
set +e
purge_without_encoder=$(FM_TEST_REAL_BASE64="$REAL_BASE64" \
  PATH="$ENCODE_FAIL_SHIM_DIR:$PATH" FM_DATA_OVERRIDE="$DATA_E" "$CL" \
    redact --event-id telegram:556:-:redact --purge 2>/dev/null)
rc_purge_without_encoder=$?
set -e 2>/dev/null || true
expect_code 0 "$rc_purge_without_encoder" "purge does not depend on reason-tombstone encoding"
assert_contains "$purge_without_encoder" "purged telegram:556:-:redact" "purge completes when base64 encoding fails"
purge_without_encoder_result=$(FM_DATA_OVERRIDE="$DATA_E" "$CL" search 'redaction content remains intact')
assert_not_contains "$purge_without_encoder_result" "redaction content remains intact" "purge removes content without base64"
pass "encoding failures cannot publish truncated content or block purge"

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
FM_DATA_OVERRIDE="$DATA_P" "$CL" search '.*' >/dev/null
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
FM_DATA_OVERRIDE="$DATA_S" "$CL" search '.*' >/dev/null 2>&1
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
FM_DATA_OVERRIDE="$DATA_F" "$CL" search '.*' >/dev/null 2>&1
rc_symlink_file_search=$?
FM_DATA_OVERRIDE="$DATA_F" "$CL" redact --event-id telegram:12:-:1 --reason x >/dev/null 2>&1
rc_symlink_file_redact=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_symlink_file_append" "append refuses a symlinked archive file"
expect_code 2 "$rc_symlink_file_search" "search refuses a symlinked archive file"
expect_code 2 "$rc_symlink_file_redact" "redact refuses a symlinked archive file"
assert_equals "outside bytes" "$(cat "$OUTSIDE_FILE")" "refused accesses leave the symlink target unchanged"
pass "all archive access paths fail closed on symlinks"

DATA_Q=$(fresh_data preflight)
printf 'preflight victim remains unchanged' | FM_DATA_OVERRIDE="$DATA_Q" "$CL" \
  append --role captain --chat 13 --msg-id victim >/dev/null
PREFLIGHT_LOG="$DATA_Q/captain-log/$month.log"
PREFLIGHT_SNAPSHOT="$TMP_ROOT/preflight-month.snapshot"
PREFLIGHT_ABANDONED="$DATA_Q/captain-log/.fm-captain-log.abandoned"
PREFLIGHT_OUTSIDE="$TMP_ROOT/preflight-outside.log"
cp "$PREFLIGHT_LOG" "$PREFLIGHT_SNAPSHOT"
printf 'abandoned replacement bytes' > "$PREFLIGHT_ABANDONED"
chmod 0600 "$PREFLIGHT_ABANDONED"
printf 'outside preflight bytes\n' > "$PREFLIGHT_OUTSIDE"
ln -s "$PREFLIGHT_OUTSIDE" "$DATA_Q/captain-log/9999-12.log"
set +e
printf 'must not be appended' | FM_DATA_OVERRIDE="$DATA_Q" "$CL" \
  append --role captain --chat 13 --msg-id new >/dev/null 2>&1
rc_preflight_append=$?
FM_DATA_OVERRIDE="$DATA_Q" "$CL" redact \
  --event-id telegram:13:-:victim --reason requested >/dev/null 2>&1
rc_preflight_redact=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_preflight_append" "append validates every month before cleanup or access"
expect_code 2 "$rc_preflight_redact" "redact validates every month before cleanup or rewrite"
assert_present "$PREFLIGHT_ABANDONED" "unsafe archive state prevents abandoned-file cleanup"
cmp -s "$PREFLIGHT_SNAPSHOT" "$PREFLIGHT_LOG" \
  || fail "unsafe later archive state allowed an earlier month rewrite"
rm -f "$DATA_Q/captain-log/9999-12.log"
ln -s "$PREFLIGHT_OUTSIDE" "$DATA_Q/captain-log/0000-01.log"
set +e
preflight_search=$(FM_DATA_OVERRIDE="$DATA_Q" "$CL" \
  search 'preflight victim remains unchanged' 2>/dev/null)
rc_preflight_search=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_preflight_search" "search validates every month before retrieval"
assert_equals "" "$preflight_search" "unsafe later search input produces no partial output"
assert_present "$PREFLIGHT_ABANDONED" "unsafe search state prevents abandoned-file cleanup"
pass "all archive commands validate the complete month set before access"

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

DATA_V=$(fresh_data option-values)
for option in --role --channel --chat --topic --msg-id --file; do
  set +e
  FM_DATA_OVERRIDE="$DATA_V" "$CL" append "$option" >/dev/null 2>&1
  rc_missing_value=$?
  set -e 2>/dev/null || true
  expect_code 2 "$rc_missing_value" "append rejects a trailing $option without a value"
done
set +e
FM_DATA_OVERRIDE="$DATA_V" "$CL" search --limit >/dev/null 2>&1
rc_search_limit=$?
FM_DATA_OVERRIDE="$DATA_V" "$CL" redact --event-id >/dev/null 2>&1
rc_redact_event=$?
FM_DATA_OVERRIDE="$DATA_V" "$CL" redact --reason >/dev/null 2>&1
rc_redact_reason=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_search_limit" "search rejects a trailing --limit without a value"
expect_code 2 "$rc_redact_event" "redact rejects a trailing --event-id without a value"
expect_code 2 "$rc_redact_reason" "redact rejects a trailing --reason without a value"
pass "value-taking options fail through the documented validation path"

for removed_mode in path dir; do
  set +e
  FM_DATA_OVERRIDE="$DATA_V" "$CL" "$removed_mode" >/dev/null 2>&1
  rc_removed_mode=$?
  set -e 2>/dev/null || true
  expect_code 2 "$rc_removed_mode" "$removed_mode is not a public command"
done
set +e
FM_DATA_OVERRIDE="$DATA_V" "$CL" search --all >/dev/null 2>&1
rc_search_all=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_search_all" "search --all is not a public convenience mode"
set +e
printf 'must not pass a terminator' | FM_DATA_OVERRIDE="$DATA_V" "$CL" append \
  --role captain --chat 14 --msg-id 1 -- >/dev/null 2>&1
rc_append_terminator=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_append_terminator" "append rejects an unneeded option terminator"
DATA_U=$(fresh_data terminators)
printf 'terminator target remains raw' | FM_DATA_OVERRIDE="$DATA_U" "$CL" \
  append --role captain --chat 14 --msg-id 2 >/dev/null
set +e
FM_DATA_OVERRIDE="$DATA_U" "$CL" redact --event-id telegram:14:-:2 \
  --reason ordinary -- --purge >/dev/null 2>&1
rc_redact_terminator=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_redact_terminator" "redact rejects an unneeded option terminator"
terminator_result=$(FM_DATA_OVERRIDE="$DATA_U" "$CL" search 'terminator target remains raw')
assert_contains "$terminator_result" "terminator target remains raw" "a rejected terminator cannot alter content"
pass "the archive CLI exposes only its required command surface"

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
printf 'ordinary message' | TG_BOT_TOKEN=SECRET_BRIDGE_TOKEN \
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

set +e
FM_DATA_OVERRIDE="$DATA_B" "$CL" search --limit 999999999999999999999999 \
  'repeated topic' >/dev/null 2>&1
rc_limit_overflow=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_limit_overflow" "search rejects a limit outside Bash's integer range"
pass "search limits remain safe for shell integer comparison"

set +e
FM_DATA_OVERRIDE="$DATA_B" "$CL" search '[' >/dev/null 2>&1
rc_invalid_regex=$?
set -e 2>/dev/null || true
expect_code 2 "$rc_invalid_regex" "search rejects an invalid regular expression"
pass "search validates its public regular expression"

# --- Captain-directed redaction and purge -----------------------------------
DATA_D=$(fresh_data redact)
printf 'a password is hunter2' | FM_DATA_OVERRIDE="$DATA_D" "$CL" \
  append --role captain --chat 9 --msg-id 50 >/dev/null
printf 'keep this one' | FM_DATA_OVERRIDE="$DATA_D" "$CL" \
  append --role captain --chat 9 --msg-id 51 >/dev/null
FM_DATA_OVERRIDE="$DATA_D" "$CL" redact --event-id telegram:9:-:50 --reason "secret" >/dev/null
after=$(FM_DATA_OVERRIDE="$DATA_D" "$CL" search '.*')
assert_contains "$after" "(redacted)" "a redacted entry is marked"
assert_contains "$after" "by captain order: secret" "the redaction records the reason"
assert_not_contains "$after" "hunter2" "the secret text is gone after redaction"
assert_contains "$after" "keep this one" "redaction leaves other entries intact"
FM_DATA_OVERRIDE="$DATA_D" "$CL" redact --event-id telegram:9:-:50 --purge >/dev/null
purged=$(FM_DATA_OVERRIDE="$DATA_D" "$CL" search '.*')
assert_not_contains "$purged" "telegram:9:-:50" "a purged entry is hidden from retrieval"
assert_contains "$purged" "keep this one" "purge leaves other entries intact"
retry=$(printf 'attempted resurrection' | FM_DATA_OVERRIDE="$DATA_D" "$CL" \
  append --role captain --chat 9 --msg-id 50)
assert_contains "$retry" "replay telegram:9:-:50" "a bridge retry cannot resurrect purged content"
FM_DATA_OVERRIDE="$DATA_D" "$CL" redact --event-id telegram:9:-:50 --reason later >/dev/null
after_retry=$(FM_DATA_OVERRIDE="$DATA_D" "$CL" search '.*')
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

DATA_I=$(fresh_data interruption)
INTERRUPTED_BODY="$TMP_ROOT/interrupted-body"
dd if=/dev/zero bs=4096 count=1 2>/dev/null | tr '\000' z > "$INTERRUPTED_BODY"
printf 'survives interrupted append' | FM_DATA_OVERRIDE="$DATA_I" "$CL" \
  append --role captain --chat 40 --msg-id survivor >/dev/null
set +e
(
  ulimit -c 0
  ulimit -f 1
  FM_DATA_OVERRIDE="$DATA_I" "$CL" append --role captain --chat 40 \
    --msg-id interrupted --file "$INTERRUPTED_BODY"
) >/dev/null 2>&1
rc_interrupted_append=$?
set -e 2>/dev/null || true
[ "$rc_interrupted_append" -ne 0 ] || fail "the file-size limit did not interrupt append"
survivor_result=$(FM_DATA_OVERRIDE="$DATA_I" "$CL" search 'survives interrupted append')
assert_contains "$survivor_result" "survives interrupted append" "an interrupted append leaves the prior archive readable"
retry_interrupted=$(printf 'complete retry body' | FM_DATA_OVERRIDE="$DATA_I" "$CL" \
  append --role captain --chat 40 --msg-id interrupted)
assert_contains "$retry_interrupted" "appended telegram:40:-:interrupted" "an interrupted event can be retried instead of becoming a false replay"
retry_result=$(FM_DATA_OVERRIDE="$DATA_I" "$CL" search 'complete retry body')
assert_contains "$retry_result" "complete retry body" "the complete retry is published after interruption"
pass "append publishes complete records atomically"

DATA_K=$(fresh_data stale-lock)
MOVE_SHIM_DIR="$TMP_ROOT/move-shim"
MOVE_ENTERED="$TMP_ROOT/move.entered"
MOVE_RELEASE="$TMP_ROOT/move.release"
KILLED_BODY="$TMP_ROOT/killed-body"
SECRET_BODY='remove every retained copy after interrupted append'
SECRET_ENCODED=$(printf '%s' "$SECRET_BODY" | base64 | tr -d '\n')
mkdir -p "$MOVE_SHIM_DIR"
cat > "$MOVE_SHIM_DIR/mv" <<'EOF'
#!/usr/bin/env bash
: > "$FM_TEST_MOVE_ENTERED"
while [ ! -e "$FM_TEST_MOVE_RELEASE" ]; do
  sleep 0.01
done
exit 99
EOF
chmod +x "$MOVE_SHIM_DIR/mv"
printf '%s' "$SECRET_BODY" | FM_DATA_OVERRIDE="$DATA_K" "$CL" \
  append --role captain --chat 41 --msg-id victim >/dev/null
printf 'publish only after a complete retry' > "$KILLED_BODY"
FM_TEST_MOVE_ENTERED="$MOVE_ENTERED" FM_TEST_MOVE_RELEASE="$MOVE_RELEASE" \
  PATH="$MOVE_SHIM_DIR:$PATH" FM_DATA_OVERRIDE="$DATA_K" "$CL" append \
    --role captain --chat 41 --msg-id interrupted --file "$KILLED_BODY" \
    >/dev/null 2>&1 &
stale_holder_pid=$!
move_checks=0
while [ ! -e "$MOVE_ENTERED" ] && [ "$move_checks" -lt 500 ]; do
  move_checks=$((move_checks + 1))
  sleep 0.01
done
[ -e "$MOVE_ENTERED" ] || fail "append did not reach its publish boundary"
kill -KILL "$stale_holder_pid" 2>/dev/null || fail "could not interrupt the lock holder"
: > "$MOVE_RELEASE"
set +e
wait "$stale_holder_pid" >/dev/null 2>&1
stale_holder_rc=$?
set -e 2>/dev/null || true
[ "$stale_holder_rc" -ne 0 ] || fail "the interrupted lock holder exited successfully"
stale_copy=''
for candidate in "$DATA_K/captain-log"/.fm-captain-log.*; do
  [ -f "$candidate" ] || continue
  if grep -Fq -- "$SECRET_ENCODED" "$candidate"; then
    stale_copy=$candidate
    break
  fi
done
[ -n "$stale_copy" ] || fail "interrupted append did not retain the staged regression fixture"
FM_DATA_OVERRIDE="$DATA_K" "$CL" redact --event-id telegram:41:-:victim --purge >/dev/null
if grep -r -Fq -- "$SECRET_ENCODED" "$DATA_K/captain-log"; then
  fail "purge left Captain content in the archive tree"
fi
for candidate in "$DATA_K/captain-log"/.fm-captain-log.*; do
  [ ! -e "$candidate" ] && [ ! -L "$candidate" ] \
    || fail "purge left an abandoned replacement file"
done
retry_killed=$(FM_DATA_OVERRIDE="$DATA_K" "$CL" append --role captain \
  --chat 41 --msg-id interrupted --file "$KILLED_BODY")
assert_contains "$retry_killed" "appended telegram:41:-:interrupted" "a killed append can be retried after lock recovery"
recovered_result=$(FM_DATA_OVERRIDE="$DATA_K" "$CL" search 'publish only after a complete retry')
assert_contains "$recovered_result" "publish only after a complete retry" "the complete retry remains searchable"
pass "dead-owner recovery clears abandoned content before purge"

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
