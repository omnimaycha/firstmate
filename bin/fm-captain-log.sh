#!/usr/bin/env bash
# fm-captain-log.sh - private, append-only capture and search for the Captain's
# own messages (the Firstmate "second brain" raw archive).
#
# WHY: Captain teachings arrive on a live channel (e.g. the local Telegram
# bridge) that injects text into the session and persists nothing, so a model
# change or new session loses whatever Firstmate did not distill. This tool is
# the durable, searchable store of what the Captain actually said, kept separate
# from the curated startup-memory files.
#
# This store is DELIBERATELY NOT part of startup memory: it is never printed by
# session start and never counted by config/startup-memory-budget, so it can
# grow without costing prompt tokens and is reached on demand through `search`.
# Curation of distilled facts stays owned by the /stow skill and the external
# memory-layering contract (docs/configuration.md); this tool only owns raw
# capture and retrieval and never restates those contracts.
#
# ROLE BOUNDARY: only the Captain's own messages are captured. `--role` must be
# `captain` (direct) or `captain-group` (Captain's own message in a registered
# group). Any other role, including `group`, is refused. Other members' view/ask
# messages and unknown chats are not the Captain's teachings and are not stored.
#
# SECRETS AND PRIVACY: message content is taken only from stdin or `--file`,
# never from the command line, so a secret the Captain sends never lands in the
# process table or shell history, and no bridge credential is ever read by this
# tool. Content is base64-encoded ONLY to keep each multiline message on one
# binary-safe record line: base64 is an encoding, not confidentiality, and
# provides no privacy. The ONLY privacy control is the file mode - the directory
# is 0700 and files are 0600. A verbatim archive is as sensitive as its
# contents, so a secret the Captain sends is in the archive until removed:
# `redact` replaces an entry's body with a tombstone, and `redact --purge`
# deletes the line entirely. That is the Captain-directed delete path.
#
# Usage:
#   fm-captain-log.sh append --role <captain|captain-group> --chat <id> \
#       --msg-id <id> [--channel <name>] [--topic <id>] [--file <path>]
#       (message content on stdin unless --file is given)
#   fm-captain-log.sh search [--limit <n>] [--all] [--] [<regex>]
#   fm-captain-log.sh redact --event-id <id> --reason <text> [--purge]
#   fm-captain-log.sh path        (print the current month's archive file)
#   fm-captain-log.sh dir         (print the archive directory)
#
# `append` is idempotent on the composed event id
# `<channel>:<chat>:<topic>:<msg-id>`: a repeat of the same event is not stored
# twice and prints `replay <event-id>`. This lets the bridge retry safely.
#
# EXIT CODES: 0 success (including idempotent replay); 2 usage/validation error
# (bad role, missing field, unsafe value); 3 not found (redact).
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FM_ROOT="${FM_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/.." && pwd)}"
FM_HOME="${FM_HOME:-${FM_ROOT_OVERRIDE:-$FM_ROOT}}"
DATA="${FM_DATA_OVERRIDE:-$FM_HOME/data}"
ARCHIVE_DIR="$DATA/captain-log"

REC_VERSION=fmcl1
TAB=$'\t'
SEARCH_DEFAULT_LIMIT=20

usage() {
  sed -n '35,51{s/^# \{0,1\}//;p;}' "$0"
}

die() {
  printf 'fm-captain-log: %s\n' "$1" >&2
  exit "${2:-2}"
}

# A metadata component must be a short safe token so it can never break the
# TAB-delimited record or the fixed-string idempotency grep.
valid_token() {
  case "$1" in
    ''|*[!A-Za-z0-9_.:-]*) return 1 ;;
    *) return 0 ;;
  esac
}

b64_encode_file() { base64 < "$1" | tr -d '\n'; }
b64_encode_str() { printf '%s' "$1" | base64 | tr -d '\n'; }
b64_decode() { printf '%s' "$1" | base64 -d; }

ensure_archive_dir() {
  if [ ! -d "$ARCHIVE_DIR" ]; then
    mkdir -p "$ARCHIVE_DIR"
    chmod 0700 "$ARCHIVE_DIR"
  fi
}

# Echo every record line for an event id across all month files, or nothing.
find_record() {
  local event_id=$1 f
  [ -d "$ARCHIVE_DIR" ] || return 0
  for f in "$ARCHIVE_DIR"/*.log; do
    [ -e "$f" ] || continue
    grep -F -- "${TAB}${event_id}${TAB}" "$f" 2>/dev/null || true
  done
}

cmd_append() {
  local role='' channel=telegram chat='' topic='' msg_id='' file=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --role) role=${2:-}; shift 2 ;;
      --channel) channel=${2:-}; shift 2 ;;
      --chat) chat=${2:-}; shift 2 ;;
      --topic) topic=${2:-}; shift 2 ;;
      --msg-id) msg_id=${2:-}; shift 2 ;;
      --file) file=${2:-}; shift 2 ;;
      --) shift; break ;;
      -*) die "append: unknown option $1" ;;
      *) die "append: unexpected argument $1" ;;
    esac
  done

  case "$role" in
    captain|captain-group) : ;;
    '') die "append: --role is required" ;;
    *) die "append: refused role '$role' (only captain or captain-group are captured)" ;;
  esac
  [ -n "$chat" ] || die "append: --chat is required"
  [ -n "$msg_id" ] || die "append: --msg-id is required"
  [ -n "$topic" ] || topic='-'
  valid_token "$channel" || die "append: unsafe --channel value"
  valid_token "$chat" || die "append: unsafe --chat value"
  valid_token "$topic" || die "append: unsafe --topic value"
  valid_token "$msg_id" || die "append: unsafe --msg-id value"

  local event_id="${channel}:${chat}:${topic}:${msg_id}"

  if [ -n "$(find_record "$event_id")" ]; then
    printf 'replay %s\n' "$event_id"
    return 0
  fi

  local body
  if [ -n "$file" ]; then
    [ -f "$file" ] || die "append: --file not found: $file"
    body=$(b64_encode_file "$file")
  else
    local tmp
    tmp=$(mktemp "${TMPDIR:-/tmp}/fm-captain-log.XXXXXX")
    chmod 0600 "$tmp"
    cat > "$tmp"
    body=$(b64_encode_file "$tmp")
    rm -f "$tmp"
  fi

  local captured_at month target
  captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  month=${captured_at%%T*}
  month=${month%-*}
  ensure_archive_dir
  target="$ARCHIVE_DIR/${month}.log"
  if [ ! -e "$target" ]; then
    : > "$target"
    chmod 0600 "$target"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$REC_VERSION" "$event_id" "$role" "$channel" "$chat" "$topic" \
    "$captured_at" 0 "$body" >> "$target"
  printf 'appended %s\n' "$event_id"
}

# Decode and print one record's 9 TAB-separated fields as a readable block.
print_record() {
  local line=$1 _v event_id role channel chat topic captured redacted body mark=''
  IFS="$TAB" read -r _v event_id role channel chat topic captured redacted body <<EOF
$line
EOF
  [ "$redacted" = 1 ] && mark=' (redacted)'
  printf -- '-- %s [%s] chat=%s topic=%s id=%s%s\n' \
    "$captured" "$role" "$chat" "$topic" "$event_id" "$mark"
  b64_decode "$body"
  printf '\n'
}

cmd_search() {
  local limit=$SEARCH_DEFAULT_LIMIT all=0 query='' f line decoded shown=0 matched=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --limit) limit=${2:-}; shift 2 ;;
      --all) all=1; shift ;;
      --) shift; break ;;
      -*) die "search: unknown option $1" ;;
      *) break ;;
    esac
  done
  [ "$#" -eq 0 ] || { query=$1; shift; }
  [ "$#" -eq 0 ] || die "search: unexpected extra argument"
  case "$limit" in ''|*[!0-9]*) die "search: --limit must be a number" ;; esac
  [ "$all" = 1 ] || [ -n "$query" ] || die "search: a <regex> is required unless --all is given"

  if [ ! -d "$ARCHIVE_DIR" ]; then
    printf 'no captain-log archive yet (%s)\n' "$ARCHIVE_DIR"
    return 0
  fi

  # Newest months first, and newest lines first within each, so a bounded view
  # shows the most recent matches.
  while IFS= read -r f; do
    [ -e "$f" ] || continue
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      decoded=$(b64_decode "${line##*"$TAB"}")
      if [ "$all" = 1 ] || printf '%s' "$decoded" | grep -Eiq -- "$query"; then
        matched=$((matched + 1))
        if [ "$shown" -lt "$limit" ]; then
          print_record "$line"
          shown=$((shown + 1))
        fi
      fi
    done < <(tac "$f" 2>/dev/null || tail -r "$f")
  done < <(find "$ARCHIVE_DIR" -maxdepth 1 -name '*.log' | sort -r)

  if [ "$matched" -gt "$shown" ]; then
    printf -- '... %s more match(es) not shown (raise --limit to see them)\n' \
      "$((matched - shown))"
  fi
  [ "$matched" -gt 0 ] || printf 'no matches\n'
}

cmd_redact() {
  local event_id='' reason='' purge=0 f line found=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --event-id) event_id=${2:-}; shift 2 ;;
      --reason) reason=${2:-}; shift 2 ;;
      --purge) purge=1; shift ;;
      --) shift; break ;;
      *) die "redact: unknown option $1" ;;
    esac
  done
  [ -n "$event_id" ] || die "redact: --event-id is required"
  [ "$purge" = 1 ] || [ -n "$reason" ] || die "redact: --reason is required unless --purge"
  [ -d "$ARCHIVE_DIR" ] || die "redact: no archive" 3

  local tomb_at tomb
  tomb_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  tomb=$(b64_encode_str "[redacted ${tomb_at} by captain order: ${reason}]")

  for f in "$ARCHIVE_DIR"/*.log; do
    [ -e "$f" ] || continue
    grep -Fq -- "${TAB}${event_id}${TAB}" "$f" || continue
    local tmp
    tmp=$(mktemp "${TMPDIR:-/tmp}/fm-captain-log.XXXXXX")
    chmod 0600 "$tmp"
    while IFS= read -r line; do
      case "$line" in
        *"${TAB}${event_id}${TAB}"*)
          found=1
          [ "$purge" = 1 ] && continue
          local _v eid role channel chat topic captured _redacted _body
          IFS="$TAB" read -r _v eid role channel chat topic captured _redacted _body <<EOF
$line
EOF
          printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$_v" "$eid" "$role" "$channel" "$chat" "$topic" \
            "$captured" 1 "$tomb" >> "$tmp"
          ;;
        *) printf '%s\n' "$line" >> "$tmp" ;;
      esac
    done < "$f"
    cat "$tmp" > "$f"
    rm -f "$tmp"
  done
  [ "$found" = 1 ] || die "redact: event id not found: $event_id" 3
  if [ "$purge" = 1 ]; then
    printf 'purged %s\n' "$event_id"
  else
    printf 'redacted %s\n' "$event_id"
  fi
}

case "${1:-}" in
  append) shift; cmd_append "$@" ;;
  search) shift; cmd_search "$@" ;;
  redact) shift; cmd_redact "$@" ;;
  path)
    month=$(date -u +%Y-%m)
    printf '%s/%s.log\n' "$ARCHIVE_DIR" "$month"
    ;;
  dir) printf '%s\n' "$ARCHIVE_DIR" ;;
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
