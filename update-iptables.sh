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
# Updates rules can be laoded from:
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
UI_NETWORK_ZONE_FILE="/run/update-iptables.network-zone"
IPTABLES_FILE_BEFORE="/etc/.update-iptables-rules-v4.before"
IPTABLES_FILE_AFTER="/etc/.update-iptables-rules-v4.after"

UPDATE_IPTABLES_CFG_FILE="/etc/update-iptables.rules"
UPDATE_IPTABLES_RULES_CFG_DIR="/etc/update-iptables.d"

UI_NETWORK_ZONE="unknown" # Default zone
VERBOSE=1

# Allow all legitimate internal traffic on the 'lo' interface, which is required
# for local applications and services to communicate. This function also drops
# packets on non-loopback interfaces that spoof loopback IP addresses
# (127.0.0.0/8 and ::1/128) to protect the system from external manipulation and
# network pollution.
_UI_LOOPBACK_DONE=0
# shellcheck disable=SC2329
ui_allow_loopback() {
  if [[ $_UI_LOOPBACK_DONE -eq 0 ]]; then
    _UI_LOOPBACK_DONE=1
    # ACCEPT: LOOPBACK INPUT
    #
    # Accept traffic from the "loopback" interface, which is necessary for
    # many applications and services.
    #

    # If a packet claims to be from the loopback subnet (127.0.0.0/8), but it
    # arrived on any interface other than the actual loopback interface (! -i
    # lo), drop it immediately.
    # TODO fix
    # iptables -A UI_INPUT -s 127.0.0.0/8 ! -i lo -j DROP
    # ip6tables -A UI_INPUT -s ::1/128 ! -i lo -j DROP

    # This prevents your machine from accidentally routing packets destined for
    # loopback out into the physical network, which prevents routing loops and
    # network pollution.
    # TODO fix
    # iptables -A UI_OUTPUT -d 127.0.0.0/8 ! -o lo -j DROP
    # ip6tables -A UI_OUTPUT -d ::1/128 ! -o lo -j DROP

    ui_46iptables -A UI_INPUT -i lo -j ACCEPT

    # ACCEPT: LOOPBACK OUTPUT
    #
    # Accept the traffic from the "loopback" interface, which is necessary for
    # many applications and services.
    #
    ui_46iptables -A UI_OUTPUT -o lo -j ACCEPT
  fi
}

iptables_noecho() {
  # -w: Add automatic xtables lock waiting.
  "$IPTABLES_CMD" -w 5 "$@" || return "$?"
  return 0
}

iptables() {
  if [[ $VERBOSE -eq 1 ]]; then
    echo "[CMD] $*"
  fi

  # -w: Add automatic xtables lock waiting.
  "$IPTABLES_CMD" -w 5 "$@" || return "$?"

  return 0
}

ip6tables() {
  if [[ $VERBOSE -eq 1 ]]; then
    echo "[CMD] $*"
  fi

  # -w: Add automatic xtables lock waiting.
  "$IP6TABLES_CMD" -w 5 "$@" || return "$?"

  return 0
}

ui_46iptables() {
  iptables "$@"
  ip6tables "$@"
}

# shellcheck disable=SC2329
_ui_error_handler() {
  local errno="$?"
  trap - INT TERM EXIT QUIT ERR
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
      ui_46iptables -P FORWARD DROP
      ui_46iptables -P INPUT DROP
      ui_46iptables -P OUTPUT DROP
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
            echo "--------------------------------------------------------------------"
            diff --color -rupN "$IPTABLES_FILE_BEFORE" "$IPTABLES_FILE_AFTER" || true
            echo "--------------------------------------------------------------------"
          fi
        fi
      fi

      echo
      echo "Success!"
    fi
  fi

  exit "$errno"
}

_ui_enable_logging() {
  local item
  for item in UI_INPUT UI_OUTPUT UI_FORWARD; do
    # Safely create and flush the logging chain
    ui_46iptables -N "LOGGING_$item" 2>/dev/null || true
    ui_46iptables -F "LOGGING_$item"

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

    ui_46iptables -A "LOGGING_$item" -j RETURN
  done
}

# This function establishes defensive firewall rules to drop malformed, spoofed,
# and invalid network packets while ensuring essential IPv6 communications
# remain functional.
#
# The configuration executes the following primary operations:
#
# - ICMPv6 Allowance: Explicitly accepts necessary ICMPv6 traffic, including
#   Neighbor Discovery Protocol (NDP) packets restricted to a 255 hop limit and
#   other control messages, preventing them from being dropped by subsequent
#   state checks.
#
# - Stateful Invalid Drop: Leverages the kernel's connection tracking module to
#   identify and drop packets classified as INVALID across all primary chains
#   (INPUT, FORWARD, OUTPUT) for both IPv4 and IPv6 protocols.
#
# - Anti-Spoofing Protection: Dynamically identifies the system's default
#   external interface and applies rules to drop incoming packets that falsely
#   claim to originate from reserved, private (RFC 1918), or loopback IP address
#   spaces.
#
# Bogus TCP Flag Mitigation: Drops TCP packets containing illogical flag
# combinations (such as SYN-FIN or SYN-RST) to defend against network mapping
# and stack exploitation attempts.
#
# shellcheck disable=SC2329
ui_drop_invalid() {
  # Accept untracked ICMPv6 Neighbor Discovery before dropping INVALID
  ip6tables -A UI_INPUT -p ipv6-icmp -m hl --hl-eq 255 -j ACCEPT
  ip6tables -A UI_OUTPUT -p ipv6-icmp -m hl --hl-eq 255 -j ACCEPT

  # Allow essential ICMPv6 types for proper IPv6 operation
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

  # DROP: INVALID INPUT
  #
  # Drop any traffic with an "INVALID" state match. Traffic can fall into four
  # "state" categories: NEW, ESTABLISHED, RELATED and INVALID.  This is what
  # makes this a "stateful" firewall rather than a less secure "stateless" one.
  # States are tracked using the "nf_conntrack_" kernel module which are loaded
  # automatically by the kernel as you add rules.
  #
  # Note: 1. This rule will drop all packets with invalid headers and checksums,
  #       invalid TCP flags, invalid ICMP messages (such as a port unreachable
  #       when we did not send anything to the host), and out of sequence
  #       packets which can be caused by sequence prediction or other similar
  #       attacks. The "DROP" target will drop a packet without any response,
  #       contrary to REJECT which politely refuses the packet. We use DROP
  #       because there is no REJECT response to packets that are INVALID, and
  #       we do not want to acknowledge that we received these packets.
  #
  #         2. ICMPv6 Neighbor Discovery packets remain untracked, and will
  #         always be classified "INVALID" though they are not corrupted or the
  #         like. Keep this in mind, and accept them before this rule: iptables
  #         -A INPUT -p 41 -j ACCEPT
  for mode in UI_INPUT UI_FORWARD UI_OUTPUT; do
    ui_46iptables -A "$mode" -m conntrack --ctstate INVALID -m comment \
      --comment "DROP invalid" -j DROP
  done

  # TODO: In ui_drop_invalid, you have about 13 separate rules to drop spoofed
  # local IPs from the external interface. While 13 rules will not slow down a
  # modern CPU, if you ever decide to block large lists of IPs (like blocking
  # entire countries or known botnets), using iptables rules will cause
  # significant latency. For large lists, you would want to use ipset, which
  # uses O(1) hash table lookups.

  # Reject packets from RFC1918 class networks (i.e., spoofed)
  # Drop spoofed packets claiming to be from private/local networks
  # Replace 'eth0' with your actual external interface name
  # TODO auto detect ext_if
  local ext_if
  # Auto-detect the external interface by looking up the default route
  ext_if=""
  ext_if=$(ip route show default | awk '/default/ {print $5}' | head -n 1) \
    || true

  # Ensure that the interface exists
  if [[ -n "$ext_if" ]] && ip link show "$ext_if" &>/dev/null; then
    iptables -A UI_INPUT -i "$ext_if" -s 127.0.0.0/8 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -s 10.0.0.0/8 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -s 169.254.0.0/16 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -s 172.16.0.0/12 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -s 192.168.0.0/16 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -s 224.0.0.0/4 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -d 224.0.0.0/4 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -s 240.0.0.0/5 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -d 240.0.0.0/5 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -s 0.0.0.0/8 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -d 0.0.0.0/8 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -d 239.255.255.0/24 -j DROP
    iptables -A UI_INPUT -i "$ext_if" -d 255.255.255.255 -j DROP
  fi

  # Drop bogus TCP packets
  # Beyond packet spoofing, there are other types of bogus packets an
  # attacker might generate to try to expose flows in your network stack.
  # Take the SYN and FIN flags, for example. TCP SYN is used to request
  # that a TCP connection be opened on a server; TCP FIN is used to
  # terminate an existing connection. So,does it make any sense to send a
  # packet that has both SYN and FIN set together?
  #
  # Not at all. These kinds of packets are "bogus", in that they use flag
  # combinations which make no sense. However, some network implementations
  # can be fooled into some strange behavior when such unexpected packets
  # are received. The best defense, then, is just to reject them all.
  # Here's how to restrict bogus packets using iptables:
  iptables -A UI_INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
  iptables -A UI_INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
}

_ui_source_all_update_iptables_files() {
  local directory="$UPDATE_IPTABLES_RULES_CFG_DIR"
  local file

  if [[ -d "$directory" ]]; then
    while IFS= read -r file; do
      if [[ -r "$file" ]]; then
        echo "[SOURCE] $file"
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
    echo "$UI_NETWORK_ZONE" >"$UI_NETWORK_ZONE_FILE"
    rm -f "$FIRST_SUCCESSFUL_RUN_FILE"
    # TODO add this back?
    # echo >"$IPTABLES_FILE_BEFORE"
  else
    if [[ -f "$UI_NETWORK_ZONE_FILE" ]]; then
      UI_NETWORK_ZONE=$(head -n 1 "$UI_NETWORK_ZONE_FILE")
    fi
  fi

  # Arg: flush
  if [[ $# -gt 0 ]] && [[ $1 == "flush" ]]; then
    # flush (delete) only managed chains cooperatively
    for chain in UI_INPUT UI_OUTPUT UI_FORWARD UI_PREROUTING UI_POSTROUTING; do
      ui_46iptables -F "$chain" 2>/dev/null || true
      iptables -t nat -F "$chain" 2>/dev/null || true
    done

    echo "Success: iptables custom rules flushed successfully."
    exit 0
  fi

  if [[ $# -gt 0 ]] && [[ $1 == "flush-all" ]]; then
    rm -f "$FIRST_SUCCESSFUL_RUN_FILE"

    ui_46iptables -F
    ui_46iptables -Z
    ui_46iptables -X

    ui_46iptables --policy INPUT ACCEPT
    ui_46iptables --policy OUTPUT ACCEPT
    ui_46iptables --policy FORWARD ACCEPT

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

  # Reset iptables chains
  for chain in UI_INPUT UI_OUTPUT UI_FORWARD; do
    _ui_log_title "FLUSH CHAIN: $chain"
    if iptables_noecho -A "$chain"; then
      iptables -F "$chain" || true
      # Note: nat table support for IPv6 requires a newer kernel (3.7+)
      iptables -t nat -L -n &>/dev/null \
        && iptables -t nat -F "$chain" || true
      iptables -t mangle -L -n &>/dev/null \
        && iptables -t mangle -F "$chain" || true
    else
      # Create the chain
      iptables -N "$chain" || true
    fi

    _ui_log_title "FLUSH IPv6 CHAIN: $chain"
    if "$IP6TABLES_CMD" -A "$chain" 2>/dev/null; then
      # Note: nat table support for IPv6 requires a newer kernel (3.7+)
      ip6tables -t nat -L -n &>/dev/null \
        && ip6tables -t nat -F "$chain" || true
      ip6tables -t mangle -L -n &>/dev/null \
        && ip6tables -t mangle -F "$chain" || true
    else
      ip6tables -N "$chain"
    fi
  done
}

_ui_default_policy() {
  _ui_log_title "DEFAULT POLICY"

  # Always ensure NAT chains exist
  iptables -t nat -F "UI_PREROUTING" &>/dev/null || true
  iptables -t nat -N "UI_PREROUTING" &>/dev/null || true

  iptables -t nat -F "UI_POSTROUTING" &>/dev/null || true
  iptables -t nat -N "UI_POSTROUTING" &>/dev/null || true

  ui_46iptables -P FORWARD DROP
  ui_46iptables -P INPUT DROP
  ui_46iptables -P OUTPUT DROP
}

_ui_main() {
  _ui_init "$@"

  # Attach chains
  iptables -C OUTPUT -j UI_OUTPUT 2>/dev/null \
    || iptables -I OUTPUT 1 -j UI_OUTPUT
  iptables -C INPUT -j UI_INPUT 2>/dev/null \
    || iptables -I INPUT 1 -j UI_INPUT
  ip6tables -C OUTPUT -j UI_OUTPUT 2>/dev/null \
    || ip6tables -I OUTPUT 1 -j UI_OUTPUT
  ip6tables -C INPUT -j UI_INPUT 2>/dev/null \
    || ip6tables -I INPUT 1 -j UI_INPUT

  # Add my postrouting to postrouting
  iptables -t nat -C POSTROUTING -j UI_POSTROUTING 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -j UI_POSTROUTING
  # Add my prerouting to prerouting
  iptables -t nat -C PREROUTING -j UI_PREROUTING 2>/dev/null \
    || iptables -t nat -I PREROUTING 1 -j UI_PREROUTING

  iptables -C FORWARD -j UI_FORWARD 2>/dev/null \
    || iptables -I FORWARD 1 -j UI_FORWARD
  ip6tables -C FORWARD -j UI_FORWARD 2>/dev/null \
    || ip6tables -I FORWARD 1 -j UI_FORWARD

  # ACCEPT ESTABLISHED INPUT/OUTPUT
  # --------------------------------
  # Every packet that is received by any network interface will pass the INPUT
  # chain fist, if it is destined for this machine. In this chain, we make sure
  # that only the packets that we want are accepted.
  #
  # The first rule added to the INPUT chain will allow traffic that belongs to
  # established connections, or new valid traffic that is related to these
  # connections such as ICMP errors, or echo replies (the packets a host return
  # when pinged).
  #
  # Some ICMP messages are very important and help manage congestion and MTU,
  # and are accepted by this rule.
  #
  # The connection state ESTABLISHED implies that either another rule previously
  # allowed the initial (--ctstate NEW) connection attempt or the connection was
  # already active (for example an active remote SSH connection) when setting
  # the rule below.
  ui_46iptables -A UI_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ui_46iptables -A UI_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ui_46iptables -A UI_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  _ui_log_title "MAIN RULES"
  if [[ -f "$UPDATE_IPTABLES_CFG_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$UPDATE_IPTABLES_CFG_FILE"
  fi
  _ui_source_all_update_iptables_files

  _ui_enable_logging

  _ui_default_policy

  _ui_atexit
}

# MAIN
_ui_main "$@"
