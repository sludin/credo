#!/usr/bin/env bash
# Interactive prompt helpers.
# Each function sets REPLY_VAL; use /dev/tty so prompts appear even inside $() captures.

REPLY_VAL=""

expand_home() {
  local p="$1"
  printf '%s' "${p/#\~/$HOME}"
}

ask() {
  local question="$1" default="${2:-}" display
  if [[ -n "$default" ]]; then
    display="$question [$default]: "
  else
    display="$question: "
  fi
  printf '%s' "$display" >/dev/tty
  local input
  IFS= read -r input </dev/tty || input=""
  # trim surrounding whitespace
  input="${input#"${input%%[![:space:]]*}"}"
  input="${input%"${input##*[![:space:]]}"}"
  REPLY_VAL="${input:-$default}"
}

ask_required() {
  local question="$1" default="${2:-}"
  while true; do
    ask "$question" "$default"
    if [[ -n "$REPLY_VAL" ]]; then return; fi
    printf '  This field is required.\n' >&2
  done
}

ask_int() {
  local question="$1" default="${2:-}"
  while true; do
    ask "$question" "$default"
    if [[ "$REPLY_VAL" =~ ^[0-9]+$ ]]; then return; fi
    printf '  Please enter a valid integer.\n' >&2
  done
}
