#!/usr/bin/env bash
# Behavioral coverage for the private Captain-message archive: capture with
# multiline fidelity, idempotent replay, private permissions, role refusal,
# bounded retrieval, Captain-directed redaction and purge, credential safety,
# and exclusion from the injected startup-memory budget.
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
dir_mode=$(stat -c '%a' "$DATA/captain-log")
file_mode=$(stat -c '%a' "$DATA/captain-log/"*.log)
assert_equals "700" "$dir_mode" "archive directory is 0700"
assert_equals "600" "$file_mode" "archive file is 0600"
pass "the archive is private by file mode"

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
set -e 2>/dev/null || true
expect_code 2 "$rc_group" "group role is refused"
expect_code 2 "$rc_unknown" "unknown role is refused"
expect_code 2 "$rc_nochat" "missing --chat is refused"
expect_code 2 "$rc_nomsg" "missing --msg-id is refused"
assert_absent "$DATA_R/captain-log" "a refused append writes nothing"
pass "non-Captain roles and malformed events are refused and write nothing"

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
assert_not_contains "$purged" "telegram:9:-:50" "a purged entry is removed entirely"
assert_contains "$purged" "keep this one" "purge leaves other entries intact"
set +e
FM_DATA_OVERRIDE="$DATA_D" "$CL" redact --event-id telegram:9:-:999 --reason x >/dev/null 2>&1
rc_missing=$?
set -e 2>/dev/null || true
expect_code 3 "$rc_missing" "redacting an unknown event id reports not-found"
pass "Captain-directed redaction and purge work and a missing id is reported"

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
