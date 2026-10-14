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
# BEGIN HELP
# Usage:
#   fm-captain-log.sh append --role <captain|captain-group> --chat <id> \
#       --msg-id <id> [--channel <name>] [--topic <id>] [--file <path>]
#       (message content on stdin unless --file is given)
#   fm-captain-log.sh search [--limit <n>] [--] <regex>
#   fm-captain-log.sh redact --event-id <id> --reason <text> [--purge]
#
# Retention policy:
#   Archive only messages whose sender the bridge authenticated as the Captain:
#   direct messages use `captain`, and the Captain's own messages in registered
#   groups use `captain-group`. Never archive another group member's messages.
#   The authenticated bridge/caller assigns the role; `--role` does not prove
#   sender identity. Message content remains until Captain-directed `redact` or
#   `redact --purge`; redact replaces it with a reason tombstone, while purge
#   keeps only a non-content replay tombstone. The archive may contain secrets
#   and never claims to be secret-free. Its sole privacy control is 0700
#   directory and 0600 file modes.
#
# `append` is idempotent on the composed event id
# `<channel>:<chat>:<topic>:<msg-id>`: a repeat of the same event is not stored
# twice and prints `replay <event-id>`. This lets the bridge retry safely.
#
# EXIT CODES: 0 success (including idempotent replay); 2 usage/validation error
# (bad role, missing field, unsafe value); 3 not found (redact).
# END HELP
set -eu

umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FM_ROOT="${FM_ROOT_OVERRIDE:-$(cd "$SCRIPT_DIR/.." && pwd)}"
FM_HOME="${FM_HOME:-${FM_ROOT_OVERRIDE:-$FM_ROOT}}"
DATA="${FM_DATA_OVERRIDE:-$FM_HOME/data}"
ARCHIVE_DIR="$DATA/captain-log"
ARCHIVE_LOCK="$ARCHIVE_DIR/.lock"
ARCHIVE_TEMP_PREFIX=.fm-captain-log.

REC_VERSION=fmcl1
TAB=$'\t'
SEARCH_DEFAULT_LIMIT=20
LOCK_HELD=0
TEMP_FILE=''

usage() {
  sed -n '/^# BEGIN HELP$/,/^# END HELP$/{
    /^# BEGIN HELP$/d
    /^# END HELP$/d
    s/^# \{0,1\}//
    p
  }' "$0"
}

die() {
  printf 'fm-captain-log: %s\n' "$1" >&2
  exit "${2:-2}"
}

require_option_value() {
  local command=$1 option=$2
  [ "$#" -ge 3 ] || die "$command: $option requires a value"
}

valid_token() {
  case "$1" in
    ''|*[!A-Za-z0-9_.-]*) return 1 ;;
    *) return 0 ;;
  esac
}

valid_event_id() {
  [[ "$1" =~ ^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$ ]]
}

b64_encode_file() { base64 < "$1" | tr -d '\n'; }
b64_encode_str() { printf '%s' "$1" | base64 | tr -d '\n'; }
b64_decode() {
  printf '%s' "$1" | base64 -d 2>/dev/null \
    || printf '%s' "$1" | base64 -D 2>/dev/null
}

path_owner() {
  if [ "$(uname)" = Darwin ]; then
    /usr/bin/stat -f %u "$1" 2>/dev/null
  else
    stat -c %u "$1" 2>/dev/null
  fi
}

path_mode() {
  if [ "$(uname)" = Darwin ]; then
    /usr/bin/stat -f %Lp "$1" 2>/dev/null
  else
    stat -c %a "$1" 2>/dev/null
  fi
}

path_links() {
  if [ "$(uname)" = Darwin ]; then
    /usr/bin/stat -f %l "$1" 2>/dev/null
  else
    stat -c %h "$1" 2>/dev/null
  fi
}

archive_dir_safe() {
  local owner mode
  [ ! -L "$ARCHIVE_DIR" ] || die "archive directory is symlinked"
  [ -e "$ARCHIVE_DIR" ] || return 1
  [ -d "$ARCHIVE_DIR" ] || die "archive path is not a directory"
  owner=$(path_owner "$ARCHIVE_DIR") || die "cannot inspect archive directory ownership"
  [ "$owner" = "$(id -u)" ] || die "archive directory is not owned by the current user"
  chmod 0700 "$ARCHIVE_DIR" || die "cannot secure archive directory"
  mode=$(path_mode "$ARCHIVE_DIR") || die "cannot inspect archive directory mode"
  [ "$mode" = 700 ] || die "archive directory mode is not 0700"
}

ensure_archive_dir() {
  if [ ! -e "$ARCHIVE_DIR" ] && [ ! -L "$ARCHIVE_DIR" ]; then
    mkdir -p "$ARCHIVE_DIR" || die "cannot create archive directory"
  fi
  archive_dir_safe || die "archive directory is absent"
}

archive_file_safe() {
  local file=$1 owner mode links
  [ ! -L "$file" ] || die "archive file is symlinked: $file"
  [ -f "$file" ] || die "archive file is not a regular file: $file"
  owner=$(path_owner "$file") || die "cannot inspect archive file ownership: $file"
  [ "$owner" = "$(id -u)" ] || die "archive file is not owned by the current user: $file"
  links=$(path_links "$file") || die "cannot inspect archive file links: $file"
  [ "$links" = 1 ] || die "archive file is hardlinked: $file"
  chmod 0600 "$file" || die "cannot secure archive file: $file"
  mode=$(path_mode "$file") || die "cannot inspect archive file mode: $file"
  [ "$mode" = 600 ] || die "archive file mode is not 0600: $file"
}

clear_abandoned_replacements() {
  local stale
  for stale in "$ARCHIVE_DIR"/"$ARCHIVE_TEMP_PREFIX"*; do
    [ -e "$stale" ] || [ -L "$stale" ] || continue
    if [ -L "$stale" ]; then
      rm -f -- "$stale" || die "cannot remove abandoned replacement: $stale"
      continue
    fi
    archive_file_safe "$stale"
    rm -f -- "$stale" || die "cannot remove abandoned replacement: $stale"
  done
}

archive_lock_release() {
  if [ "$LOCK_HELD" = 1 ]; then
    fm_lock_release "$ARCHIVE_LOCK" || true
    LOCK_HELD=0
  fi
}

cleanup() {
  [ -z "$TEMP_FILE" ] || rm -f -- "$TEMP_FILE" 2>/dev/null || true
  archive_lock_release
}

trap cleanup EXIT

archive_lock_acquire() {
  archive_dir_safe || die "archive directory is absent"
  if ! declare -F fm_lock_acquire_wait >/dev/null 2>&1; then
    FM_STATE_OVERRIDE=$ARCHIVE_DIR
    # shellcheck source=bin/fm-wake-lib.sh
    . "$SCRIPT_DIR/fm-wake-lib.sh"
  fi
  fm_lock_acquire_wait "$ARCHIVE_LOCK" || die "cannot lock archive"
  LOCK_HELD=1
  clear_abandoned_replacements
}

begin_archive_replacement() {
  local operation=$1
  TEMP_FILE=$(mktemp "$ARCHIVE_DIR/${ARCHIVE_TEMP_PREFIX}XXXXXX") \
    || die "$operation: cannot create replacement file"
  chmod 0600 "$TEMP_FILE" || die "$operation: cannot secure replacement file"
  archive_file_safe "$TEMP_FILE"
}

publish_archive_replacement() {
  local operation=$1 target=$2
  if [ -e "$target" ] || [ -L "$target" ]; then
    archive_file_safe "$target"
  fi
  archive_file_safe "$TEMP_FILE"
  mv -f -- "$TEMP_FILE" "$target" || die "$operation: cannot publish replacement file"
  TEMP_FILE=''
  archive_file_safe "$target"
}

record_exists() {
  local event_id=$1 f
  for f in "$ARCHIVE_DIR"/*.log; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    archive_file_safe "$f"
    grep -Fq -- "${TAB}${event_id}${TAB}" "$f" && return 0
  done
  return 1
}

cmd_append() {
  local role='' channel=telegram chat='' topic='' msg_id='' file=''
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --role) require_option_value append "$@"; role=$2; shift 2 ;;
      --channel) require_option_value append "$@"; channel=$2; shift 2 ;;
      --chat) require_option_value append "$@"; chat=$2; shift 2 ;;
      --topic) require_option_value append "$@"; topic=$2; shift 2 ;;
      --msg-id) require_option_value append "$@"; msg_id=$2; shift 2 ;;
      --file) require_option_value append "$@"; file=$2; shift 2 ;;
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

  local event_id="${channel}:${chat}:${topic}:${msg_id}" body
  if [ -n "$file" ]; then
    [ -f "$file" ] || die "append: --file not found: $file"
    body=$(b64_encode_file "$file")
  else
    body=$(base64 | tr -d '\n')
  fi

  local captured_at month target
  captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  month=${captured_at%%T*}
  month=${month%-*}
  ensure_archive_dir
  archive_lock_acquire
  archive_dir_safe || die "archive directory is absent"
  if record_exists "$event_id"; then
    printf 'replay %s\n' "$event_id"
    return 0
  fi
  target="$ARCHIVE_DIR/${month}.log"
  if [ -e "$target" ] || [ -L "$target" ]; then
    archive_file_safe "$target"
  fi
  begin_archive_replacement append
  if [ -e "$target" ]; then
    cat "$target" > "$TEMP_FILE" || die "append: cannot stage archive file"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$REC_VERSION" "$event_id" "$role" "$channel" "$chat" "$topic" \
    "$captured_at" 0 "$body" >> "$TEMP_FILE" \
    || die "append: cannot stage archive record"
  publish_archive_replacement append "$target"
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
  local limit=$SEARCH_DEFAULT_LIMIT query='' regex_status f line decoded shown=0 matched=0
  local _v _event_id _role _channel _chat _topic _captured redacted _body
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --limit) require_option_value search "$@"; limit=$2; shift 2 ;;
      --) shift; break ;;
      -*) die "search: unknown option $1" ;;
      *) break ;;
    esac
  done
  [ "$#" -eq 0 ] || { query=$1; shift; }
  [ "$#" -eq 0 ] || die "search: unexpected extra argument"
  case "$limit" in ''|*[!0-9]*) die "search: --limit must be a number" ;; esac
  [ -n "$query" ] || die "search: a <regex> is required"
  if grep -Eq -- "$query" </dev/null 2>/dev/null; then
    :
  else
    regex_status=$?
    [ "$regex_status" -eq 1 ] || die "search: invalid <regex>"
  fi

  if ! archive_dir_safe; then
    printf 'no captain-log archive yet (%s)\n' "$ARCHIVE_DIR"
    return 0
  fi
  archive_lock_acquire
  archive_dir_safe || die "archive directory is absent"

  while IFS= read -r f; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    archive_file_safe "$f"
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      IFS="$TAB" read -r _v _event_id _role _channel _chat _topic _captured redacted _body <<EOF
$line
EOF
      case "$redacted" in
        0|1) decoded=$(b64_decode "$_body") ;;
        2) continue ;;
        *) die "archive contains an invalid record: $f" ;;
      esac
      if printf '%s' "$decoded" | grep -Eiq -- "$query"; then
        matched=$((matched + 1))
        if [ "$shown" -lt "$limit" ]; then
          print_record "$line"
          shown=$((shown + 1))
        fi
      fi
    done < <(tac "$f" 2>/dev/null || tail -r "$f")
  done < <(printf '%s\n' "$ARCHIVE_DIR"/*.log | sort -r)

  if [ "$matched" -gt "$shown" ]; then
    printf -- '... %s more match(es) not shown (raise --limit to see them)\n' \
      "$((matched - shown))"
  fi
  [ "$matched" -gt 0 ] || printf 'no matches\n'
}

cmd_redact() {
  local event_id='' reason='' purge=0 f line found=0 purge_written=0
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --event-id) require_option_value redact "$@"; event_id=$2; shift 2 ;;
      --reason) require_option_value redact "$@"; reason=$2; shift 2 ;;
      --purge) purge=1; shift ;;
      --) shift; break ;;
      *) die "redact: unknown option $1" ;;
    esac
  done
  [ -n "$event_id" ] || die "redact: --event-id is required"
  valid_event_id "$event_id" || die "redact: unsafe --event-id value"
  [ "$purge" = 1 ] || [ -n "$reason" ] || die "redact: --reason is required unless --purge"
  archive_dir_safe || die "redact: no archive" 3
  archive_lock_acquire
  archive_dir_safe || die "redact: no archive" 3

  local tomb_at tomb
  tomb_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  tomb=$(b64_encode_str "[redacted ${tomb_at} by captain order: ${reason}]")

  for f in "$ARCHIVE_DIR"/*.log; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    archive_file_safe "$f"
    grep -Fq -- "${TAB}${event_id}${TAB}" "$f" || continue
    begin_archive_replacement redact
    while IFS= read -r line; do
      case "$line" in
        *"${TAB}${event_id}${TAB}"*)
          found=1
          if [ "$purge" = 1 ]; then
            if [ "$purge_written" = 0 ]; then
              printf '%s\t%s\tpurged\t-\t-\t-\t%s\t2\t\n' \
                "$REC_VERSION" "$event_id" "$tomb_at" >> "$TEMP_FILE"
              purge_written=1
            fi
            continue
          fi
          local _v eid role channel chat topic captured _redacted _body
          IFS="$TAB" read -r _v eid role channel chat topic captured _redacted _body <<EOF
$line
EOF
          if [ "$_redacted" = 2 ]; then
            printf '%s\n' "$line" >> "$TEMP_FILE"
            continue
          fi
          printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$_v" "$eid" "$role" "$channel" "$chat" "$topic" \
            "$captured" 1 "$tomb" >> "$TEMP_FILE"
          ;;
        *) printf '%s\n' "$line" >> "$TEMP_FILE" ;;
      esac
    done < "$f"
    publish_archive_replacement redact "$f"
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
  -h|--help) usage ;;
  *) usage >&2; exit 2 ;;
esac
