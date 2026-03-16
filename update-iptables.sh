#!/usr/bin/env bash
# update-iptables - A low level Linux firewall
#
# Author: James Cherti
# URL: https://github.com/jamescherti/update-iptables
#
# Description:
# ------------
# This script automatically sets commonly used permissions for files or
# directories.
#
# The update-iptables script provides a bash script for managing network traffic
# and routing.
#
# For system administrators who require absolute control over packet states,
# network address translation, and custom routing chains, this script defines
# rules without the opaque abstraction layers of modern firewall managers.
#
# It allows you to build a modular firewall by integrating drop-in configuration
# files while maintaining exact visibility into how every packet traverses the
# kernel network stack.
#
# Updates rules can be loaded from:
#   - /etc/default/update-iptables
#   - Any files that is in the directory: /etc/default/update-iptables.d/
#
# Requirements:
# -------------
# - iptables (which includes: iptables, ip6tables, iptables-save)
# - Optional: diff
#
# License:
# --------
# Copyright (C) 2012-2026 James Cherti
#
# Distributed under terms of the GNU General Public License version 3.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

# shellcheck disable=SC1091
set -euf -o pipefail

FIRST_SUCCESSFUL_RUN_FILE="/run/update-iptables.first-run"
NETWORK_ZONE_FILE="/run/update-iptables.network-zone"
IPTABLES_FILE_BEFORE="/etc/.update-iptables-rules-v4.before"
IPTABLES_FILE_AFTER="/etc/.update-iptables-rules-v4.after"

UPDATE_IPTABLES_CFG_FILE="/etc/update-iptables.rules"
UPDATE_IPTABLES_RULES_CFG_DIR="/etc/update-iptables.d"

NETWORK_ZONE="unknown" # Default zone
VERBOSE=1

#
# Allow essential ICMPv6 types for proper IPv6 operation (Neighbor Discovery,
# Router Solicitation, MTU discovery). Without this, IPv6 connectivity will fail.
#
# shellcheck disable=SC2329
# shellcheck disable=SC2317
ui_allow_ipv6_ndp() {
  ip6tables -A UI_INPUT -p ipv6-icmp -m hl --hl-eq 255 -j ACCEPT
  ip6tables -A UI_OUTPUT -p ipv6-icmp -m hl --hl-eq 255 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 128 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 129 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 135 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 136 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 133 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 134 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 1 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 2 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 3 -j ACCEPT
  ip6tables -A UI_INPUT -p icmpv6 --icmpv6-type 4 -j ACCEPT
}

# Accept traffic belonging to already established connections or packets related
# to them. This rule ensures that once a connection has been permitted by a
# specific rule, all subsequent packets for that session are processed quickly
# and efficiently without re-evaluating the entire rule set.
# shellcheck disable=SC2329
# shellcheck disable=SC2317
ui_allow_established() {
  if [[ $# -eq 0 ]]; then
    ip46tables \
      -A UI_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip46tables \
      -A UI_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip46tables \
      -A UI_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  else
    local chain
    for chain in "$@"; do
      ip46tables \
        -A "$@" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    done
  fi
}

# Allow all legitimate internal traffic on the 'lo' interface, which is required
# for local applications and services to communicate. This function also drops
# packets on non-loopback interfaces that spoof loopback IP addresses
# (127.0.0.0/8 and ::1/128) to protect the system from external manipulation and
# network pollution.
_UI_LOOPBACK_DONE=0
# shellcheck disable=SC2329
# shellcheck disable=SC2317
ui_allow_loopback() {
  if [[ $_UI_LOOPBACK_DONE -eq 0 ]]; then
    _UI_LOOPBACK_DONE=1

    # ANTI-SPOOFING: Drop packets claiming to be loopback from outside If a
    # packet claims to be from the loopback subnet/address, but it arrived on
    # any interface other than 'lo', drop it immediately.
    iptables -A UI_INPUT -s 127.0.0.0/8 ! -i lo -j DROP
    ip6tables -A UI_INPUT -s ::1/128 ! -i lo -j DROP

    # ANTI-POLLUTION: Prevent loopback traffic from leaving the machine This
    # prevents accidentally routing packets destined for loopback out into the
    # physical network, preventing routing loops.
    iptables -A UI_OUTPUT -d 127.0.0.0/8 ! -o lo -j DROP
    ip6tables -A UI_OUTPUT -d ::1/128 ! -o lo -j DROP

    # ACCEPT: LOOPBACK INPUT
    # Accept traffic from the "loopback" interface.
    ip46tables -A UI_INPUT -i lo -j ACCEPT

    # ACCEPT: LOOPBACK OUTPUT
    # Accept traffic to the "loopback" interface.
    ip46tables -A UI_OUTPUT -o lo -j ACCEPT
  fi
}

# ACCEPT: LOOPBACK OUTPUT FOR SPECIFIC USERS
# Accept traffic to the "loopback" interface only if the user exists.
# shellcheck disable=SC2329
ui_allow_users_output_loopback() {
  local user
  for user in "$@"; do
    if getent passwd "$user" >/dev/null 2>&1; then
      iptables -A UI_OUTPUT -o lo -m owner --uid-owner "$user" -j ACCEPT
      ip6tables -A UI_OUTPUT -o lo -m owner --uid-owner "$user" -j ACCEPT
    fi
  done
}

#
# Accept all incoming ICMP echo requests, also known as pings. Only the first
# packet will count as new, the others will be handled by the RELATED,
# ESTABLISHED rule. Since the computer is not a router, no other ICMP with
# state NEW needs to be allowed.
#
# shellcheck disable=SC2329
# shellcheck disable=SC2317
ui_allow_ping() {
  iptables -A UI_INPUT -p icmp --icmp-type 8 \
    -m conntrack --ctstate NEW \
    -m limit --limit 2/sec --limit-burst 5 \
    -m comment --comment "Accept IPv4 ping" -j ACCEPT

  ip6tables -A UI_INPUT -p ipv6-icmp --icmpv6-type 128 \
    -m conntrack --ctstate NEW \
    -m limit --limit 2/sec --limit-burst 5 \
    -m comment --comment "Accept IPv6 ping" -j ACCEPT
}

#
# Permit outbound network traffic for a specific list of local system users. The
# function iterates through the provided usernames, verifies their existence on
# the system, and appends rules to the UI_OUTPUT chain using the 'owner' module
# to match traffic by UID.
#
# Usernames that do not exist on the host are silently ignored.
#
# shellcheck disable=SC2329
# shellcheck disable=SC2317
ui_allow_users_output() {
  local cur_user
  for cur_user in "$@"; do
    if id "$cur_user" &>/dev/null; then
      iptables -A UI_OUTPUT -m owner --uid-owner "$cur_user" -j ACCEPT
    fi
  done
}

iptables() {
  if [[ $VERBOSE -eq 1 ]]; then
    echo "[CMD] $*"
  fi

  # -w: Add automatic xtables lock waiting.
  command "$IPTABLES_CMD" -w 5 "$@" || return "$?"

  return 0
}

ip6tables() {
  if [[ $VERBOSE -eq 1 ]]; then
    echo "[CMD] $*"
  fi

  # -w: Add automatic xtables lock waiting.
  command "$IP6TABLES_CMD" -w 5 "$@" || return "$?"

  return 0
}

ip46tables() {
  iptables "$@"
  ip6tables "$@"
}

# shellcheck disable=SC2329
# shellcheck disable=SC2317
_ui_error_handler() {
  local errno="$?"
  echo "Error: ${BASH_SOURCE[1]}:${BASH_LINENO[0]}" \
    "(${BASH_COMMAND} exited with status $errno)" >&2
  exit "${errno}"
}

_UI_FIRST_TITLE=1
_ui_log_title() {
  if [[ $_UI_FIRST_TITLE -ne 0 ]]; then
    _UI_FIRST_TITLE=0
  else
    echo
  fi

  echo '========================================================='
  echo "$@"
  echo '========================================================='
}

ATEXIT_DONE=0
_ui_atexit() {
  local errno="$?"

  trap - INT TERM EXIT QUIT ERR

  if [[ $ATEXIT_DONE -eq 0 ]]; then
    ATEXIT_DONE=1
    _ui_log_title 'ATEXIT'

    if [[ $errno -eq 0 ]]; then
      touch "$FIRST_SUCCESSFUL_RUN_FILE"
    fi

    if [[ $errno -ne 0 ]]; then
      echo >&2
      echo "ERROR with iptables!" >&2
      echo "[INFO] Locking down policies to DROP due to failure." >&2
      ip46tables -P FORWARD DROP
      ip46tables -P INPUT DROP
      ip46tables -P OUTPUT DROP
    else
      if [[ -n "$IPTABLES_FILE_AFTER" ]]; then
        echo "[SAVE] Rules saved to: $IPTABLES_FILE_AFTER"
        touch "$IPTABLES_FILE_AFTER"
        chmod 600 "$IPTABLES_FILE_AFTER"

        echo >"$IPTABLES_FILE_AFTER"
        if type -P iptables-save &>/dev/null; then
          iptables-save >>"$IPTABLES_FILE_AFTER"
        fi

        if type -P ip6tables-save &>/dev/null; then
          ip6tables-save >>"$IPTABLES_FILE_AFTER"
        fi
      fi

      if [[ -n "$IPTABLES_FILE_BEFORE" ]]; then
        if cmp -s "$IPTABLES_FILE_AFTER" "$IPTABLES_FILE_BEFORE"; then
          echo "[INFO] Nothing has changed."
        elif type -P diff &>/dev/null \
          && [[ -n "$IPTABLES_FILE_AFTER" ]]; then
          if [[ -f "$IPTABLES_FILE_AFTER" ]] \
            && [[ -f "$IPTABLES_FILE_BEFORE" ]]; then
            echo "Diff:"
            echo "-------------------------------------------------------------"
            diff --color=auto -rupN \
              "$IPTABLES_FILE_BEFORE" "$IPTABLES_FILE_AFTER" || true
            echo "-------------------------------------------------------------"
          fi
        fi
      fi

      echo
      echo "Success!"
    fi
  fi

  exit "$errno"
}

# shellcheck disable=SC2329
ui_enable_logging() {
  local item
  for item in UI_INPUT UI_OUTPUT UI_FORWARD; do
    # Safely create and flush the logging chain
    ip46tables -N "LOGGING_$item" 2>/dev/null || true
    ip46tables -F "LOGGING_$item"

    # Append the logging chain to the end of the main chain
    iptables -C "$item" -j "LOGGING_$item" 2>/dev/null \
      || iptables -A "$item" -j "LOGGING_$item"
    ip6tables -C "$item" -j "LOGGING_$item" 2>/dev/null \
      || ip6tables -A "$item" -j "LOGGING_$item"

    # Log the packet, then return to let standard routing handle it
    # cooperatively
    iptables -A "LOGGING_$item" -m limit --limit 10/min --limit-burst 20 \
      -j LOG --log-prefix "[UPDATE-IPTABLES $item] " --log-level 4
    ip6tables -A "LOGGING_$item" -m limit --limit 10/min --limit-burst 20 \
      -j LOG --log-prefix "[UPDATE-IP6TABLES $item] " --log-level 4

    ip46tables -A "LOGGING_$item" -j RETURN
  done
}

_ui_source_all_update_iptables_files() {
  local directory="$UPDATE_IPTABLES_RULES_CFG_DIR"
  local file

  if [[ -d "$directory" ]]; then
    while IFS= read -r file; do
      if [[ -r "$file" ]]; then
        _ui_log_title "[RULES] $file"
        # shellcheck disable=SC1090
        source "$file"
      else
        echo "[IGNORED] Cannot read: $file"
      fi
    done < <(find "$directory" -name '*.rules' -type f | sort)
  else
    echo "Directory $directory does not exist."
  fi
}

_ui_parse_args() {
  UI_RESET=0
  OPTIND=1
  while getopts ":hrv" opt; do
    case ${opt} in
    r)
      UI_RESET=1
      ;;
    v)
      VERBOSE=1
      ;;
    h)
      {
        echo "Usage: $0 [-h] [-r] [-v] [flush|flush-all]"
        echo
        echo "-r    Reset zone and the previous rules"
        echo "-v    Enable verbose output for iptables commands"
        echo "-h    Show this help message and exit"
      } >&2
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Invalid option: -$OPTARG requires an argument" >&2
      exit 1
      ;;
    esac
  done
}

_ui_init() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: You need root privileges to run this script." >&2
    exit 1
  fi

  IPTABLES_CMD=$(type -P iptables)
  IP6TABLES_CMD=$(type -P ip6tables)

  if [[ -z "$IPTABLES_CMD" ]] || [[ -z "$IP6TABLES_CMD" ]]; then
    echo "Error: iptables or ip6tables command not found in PATH." >&2
    exit 1
  fi

  _ui_parse_args "$@"
  shift $((OPTIND - 1))

  trap "_ui_error_handler" ERR
  set -o errtrace

  if [[ $UI_RESET -eq 0 ]]; then
    echo "$NETWORK_ZONE" >"$NETWORK_ZONE_FILE"
    rm -f "$FIRST_SUCCESSFUL_RUN_FILE"
    # TODO add this back?
    # echo >"$IPTABLES_FILE_BEFORE"
  else
    if [[ -f "$NETWORK_ZONE_FILE" ]]; then
      NETWORK_ZONE=$(head -n 1 "$NETWORK_ZONE_FILE")
    fi
  fi

  # Arg: flush
  if [[ $# -gt 0 ]] && [[ $1 == "flush" ]]; then
    # flush (delete) only managed chains cooperatively
    for chain in UI_INPUT UI_OUTPUT UI_FORWARD UI_PREROUTING UI_POSTROUTING; do
      ip46tables -F "$chain" 2>/dev/null || true
      iptables -t nat -F "$chain" 2>/dev/null || true
      ip6tables -t nat -F "$chain" 2>/dev/null || true
    done

    echo "Success: iptables custom rules flushed successfully."
    exit 0
  fi

  if [[ $# -gt 0 ]] && [[ $1 == "flush-all" ]]; then
    rm -f "$FIRST_SUCCESSFUL_RUN_FILE"

    ip46tables -F
    ip46tables -Z
    ip46tables -X

    ip46tables --policy INPUT ACCEPT
    ip46tables --policy OUTPUT ACCEPT
    ip46tables --policy FORWARD ACCEPT

    echo "Success: iptables rules flushed successfully."
    exit 0
  fi

  if [[ $IPTABLES_FILE_BEFORE != "" ]]; then
    touch "$IPTABLES_FILE_BEFORE"
    chmod 600 "$IPTABLES_FILE_BEFORE"
    echo >"$IPTABLES_FILE_BEFORE"
    if type -P iptables-save &>/dev/null; then
      iptables-save >>"$IPTABLES_FILE_BEFORE"
    fi

    if type -P ip6tables-save &>/dev/null; then
      ip6tables-save >>"$IPTABLES_FILE_BEFORE"
    fi
  fi

  trap '_ui_atexit' INT TERM EXIT QUIT

  # Default policy
  #
  # Setting the default policy to DROP before flushing and rebuilding the custom
  # chains to eliminate the brief window where packets could bypass the firewall
  # and fall through to an open default policy.
  _ui_default_policy

  # Reset iptables chains
  #
  # NOTE: -n: prevents iptables from hanging on reverse DNS lookups (missing the
  # -n flag). This will freeze your terminal if the network is down.
  for chain in UI_INPUT UI_OUTPUT UI_FORWARD; do
    _ui_log_title "FLUSH CHAIN: $chain"
    if iptables -L "$chain" -n &>/dev/null; then
      iptables -F "$chain" || true
      if iptables -t nat -L -n &>/dev/null; then
        iptables -t nat -F "$chain" || true
      fi

      if iptables -t mangle -L -n &>/dev/null; then
        iptables -t mangle -F "$chain" || true
      fi
    else
      iptables -N "$chain" || true
    fi

    _ui_log_title "FLUSH IPv6 CHAIN: $chain"
    if "$IP6TABLES_CMD" -L "$chain" -n &>/dev/null; then
      ip6tables -F "$chain" || true
      if ip6tables -t nat -L -n &>/dev/null; then
        ip6tables -t nat -F "$chain" || true
      fi

      if ip6tables -t mangle -L -n &>/dev/null; then
        ip6tables -t mangle -F "$chain" || true
      fi
    else
      ip6tables -N "$chain"
    fi
  done

  # Create the chains
  # TODO Check if prerouting and postrouting exist?
  iptables -t nat -F UI_PREROUTING &>/dev/null || true
  iptables -t nat -N UI_PREROUTING &>/dev/null || true
  iptables -t nat -F UI_POSTROUTING &>/dev/null || true
  iptables -t nat -N UI_POSTROUTING &>/dev/null || true

  if ip6tables -t nat -L -n &>/dev/null; then
    ip6tables -t nat -F UI_PREROUTING &>/dev/null || true
    ip6tables -t nat -N UI_PREROUTING &>/dev/null || true
    ip6tables -t nat -F UI_POSTROUTING &>/dev/null || true
    ip6tables -t nat -N UI_POSTROUTING &>/dev/null || true
  fi

  # Attach chains
  if ! iptables -C OUTPUT -j UI_OUTPUT 2>/dev/null; then
    iptables -I OUTPUT 1 -j UI_OUTPUT
  fi
  if ! iptables -C INPUT -j UI_INPUT 2>/dev/null; then
    iptables -I INPUT 1 -j UI_INPUT
  fi
  if ! ip6tables -C OUTPUT -j UI_OUTPUT 2>/dev/null; then
    ip6tables -I OUTPUT 1 -j UI_OUTPUT
  fi
  if ! ip6tables -C INPUT -j UI_INPUT 2>/dev/null; then
    ip6tables -I INPUT 1 -j UI_INPUT
  fi

  # Add my postrouting to postrouting
  if ! iptables -t nat -C POSTROUTING -j UI_POSTROUTING 2>/dev/null; then
    iptables -t nat -I POSTROUTING 1 -j UI_POSTROUTING
  fi

  # Add my prerouting to prerouting
  if ip6tables -t nat -L -n &>/dev/null; then
    if ! ip6tables -t nat -C PREROUTING -j UI_PREROUTING 2>/dev/null; then
      ip6tables -t nat -I PREROUTING 1 -j UI_PREROUTING
    fi

    if ! ip6tables -t nat -C POSTROUTING -j UI_POSTROUTING 2>/dev/null; then
      ip6tables -t nat -I POSTROUTING 1 -j UI_POSTROUTING
    fi
  fi

  if ! iptables -t nat -C PREROUTING -j UI_PREROUTING 2>/dev/null; then
    iptables -t nat -I PREROUTING 1 -j UI_PREROUTING
  fi

  if ! iptables -C FORWARD -j UI_FORWARD 2>/dev/null; then
    iptables -I FORWARD 1 -j UI_FORWARD
  fi

  if ! ip6tables -C FORWARD -j UI_FORWARD 2>/dev/null; then
    ip6tables -I FORWARD 1 -j UI_FORWARD
  fi
}

_ui_default_policy() {
  _ui_log_title "DEFAULT POLICY"

  ip46tables -P FORWARD DROP
  ip46tables -P INPUT DROP
  ip46tables -P OUTPUT DROP
}

_ui_main() {
  _ui_init "$@"

  # CUSTOM RULES
  if [[ -f "$UPDATE_IPTABLES_CFG_FILE" ]]; then
    _ui_log_title "[RULES] $UPDATE_IPTABLES_CFG_FILE"
    # shellcheck disable=SC1090
    source "$UPDATE_IPTABLES_CFG_FILE"
  fi
  _ui_source_all_update_iptables_files

  _ui_atexit
}

# MAIN
_ui_main "$@"
