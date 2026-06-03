#!/usr/bin/env bash
# Process-management helpers for the bootstrap wizard.

PIDS_FILE="${TMPDIR:-/tmp}/.credo-bootstrap.pids"
declare -a TRACKED_PIDS=()

_file_mtime() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f '%m' "$1" 2>/dev/null || echo 0
  else
    stat -c '%Y' "$1" 2>/dev/null || echo 0
  fi
}

_save_pids_file() {
  local json="[" first=true pid
  for pid in "${TRACKED_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      if $first; then first=false; else json+=","; fi
      json+="$pid"
    fi
  done
  json+="]"
  printf '%s\n' "$json" > "$PIDS_FILE"
}

track_pid() {
  TRACKED_PIDS+=("$1")
  _save_pids_file
}

kill_stale_pids() {
  [[ -f "$PIDS_FILE" ]] || return 0
  local killed=0 pid
  while IFS= read -r pid; do
    if kill -KILL "$pid" 2>/dev/null; then
      killed=$(( killed + 1 ))
    fi
  done < <(jq -r '.[]' "$PIDS_FILE" 2>/dev/null || true)
  rm -f "$PIDS_FILE"
  if (( killed > 0 )); then
    echo "Stopped $killed leftover service(s) from a previous run."
  fi
}

kill_tracked_pids() {
  local pid
  for pid in "${TRACKED_PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  TRACKED_PIDS=()
  rm -f "$PIDS_FILE"
}

# Start a service in the background; output is appended to log_file.
# Prints the PID to stdout.
start_service() {
  local exec_path="$1" log_file="$2"
  shift 2
  mkdir -p "$(dirname "$log_file")"
  touch "$log_file"
  "$exec_path" "$@" >> "$log_file" 2>&1 &
  echo $!
}

# Wait for one or more regex patterns to appear in a log file, printing new
# lines to stdout as they arrive.  Varargs: varname1 pattern1 [varname2 pattern2 ...]
# Each varname is set to BASH_REMATCH[1] (capture group 1), or "1" if no group.
capture_from_log() {
  local log_file="$1" timeout_sec="${2:-60}"
  shift 2

  local -a _vars=() _pats=() _done=()
  local _total=0
  while (( $# >= 2 )); do
    _vars+=("$1")
    _pats+=("$2")
    _done+=("no")
    _total=$(( _total + 1 ))
    shift 2
  done

  local _start _found=0 _printed=0
  _start=$(date +%s)

  while (( _found < _total )); do
    local _elapsed=$(( $(date +%s) - _start ))
    if (( _elapsed >= timeout_sec )); then
      printf 'Error: timed out after %ds waiting for service output\n' "$timeout_sec" >&2
      return 1
    fi

    local _lineno=0 _line
    while IFS= read -r _line; do
      _lineno=$(( _lineno + 1 ))
      if (( _lineno > _printed )); then
        printf '  %s\n' "$_line"
      fi
      local _i
      for (( _i = 0; _i < _total; _i++ )); do
        if [[ "${_done[$_i]}" == "no" && "$_line" =~ ${_pats[$_i]} ]]; then
          _done[$_i]="yes"
          _found=$(( _found + 1 ))
          local _cap="${BASH_REMATCH[1]:-1}"
          printf -v "${_vars[$_i]}" '%s' "$_cap"
        fi
      done
    done < "$log_file"
    _printed=$_lineno

    if (( _found < _total )); then
      sleep 0.5
    fi
  done
}

# Start a background tail -f that labels each line; prints PID to stdout.
tail_log_start() {
  local log_file="$1" label="$2"
  tail -f -n 0 "$log_file" 2>/dev/null | sed "s/^/  [$label] /" &
  echo $!
}

tail_log_stop() {
  local pid="$1"
  kill "$pid" 2>/dev/null || true
}

# Run a command synchronously; propagates non-zero exit.
run_command() {
  local exec_path="$1"
  shift
  "$exec_path" "$@"
}

# Wait for certificate files to appear (or be recently modified).
# issued_after: unix timestamp in seconds
# Varargs: "label:cert_path" pairs
wait_for_certs() {
  local issued_after="$1"
  shift
  local timeout_sec=300

  declare -A _pending=()
  local _arg
  for _arg in "$@"; do
    _pending["${_arg#*:}"]="${_arg%%:*}"
  done

  local _deadline=$(( $(date +%s) + timeout_sec ))
  local _last_dot=$(date +%s)

  while (( ${#_pending[@]} > 0 )); do
    if (( $(date +%s) > _deadline )); then
      local _labels="" _p
      for _p in "${!_pending[@]}"; do _labels+=" ${_pending[$_p]}"; done
      printf 'Error: timed out waiting for certificates:%s\nCheck corgi logs for errors.\n' "$_labels" >&2
      return 1
    fi

    local _cert_path
    for _cert_path in "${!_pending[@]}"; do
      if [[ -f "$_cert_path" ]]; then
        printf '\n'
        local _mtime
        _mtime=$(_file_mtime "$_cert_path")
        if (( _mtime >= issued_after )); then
          printf '  Certificate issued: %s\n' "${_pending[$_cert_path]}"
        else
          printf '  Certificate already present: %s\n' "${_pending[$_cert_path]}"
        fi
        unset '_pending[$_cert_path]'
        _last_dot=$(date +%s)
      fi
    done

    if (( ${#_pending[@]} > 0 )); then
      sleep 3
      if (( $(date +%s) - _last_dot >= 10 )); then
        printf '.' >/dev/tty
        _last_dot=$(date +%s)
      fi
    fi
  done
}
