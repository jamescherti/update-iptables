# update-iptables - A low-level Linux firewall for advanced users
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

The [update-iptables](https://github.com/jamescherti/update-iptables) script implements a firewall for managing network traffic and routing.

It supports a modular configuration model through drop-in scripts located in `/etc/update-iptables.d/`. Each file is a shell script executed sequentially during firewall initialization.

This low-level firewall script is intended for Linux system administrators who require precise control over packet states, network address translation, and custom routing chains. Rules are defined directly through `iptables` without the abstraction layers commonly introduced by modern firewall management tools.

If this low-level firewall proves useful, please support the project by **⭐ starring update-iptables on GitHub**, helping more developers discover it.

## Requirements

- `bash`
- iptables (`iptables`, `ip6tables`, and `iptables-save`)
- Optional: `diff` and `cmp`

## Installation

Install `update-iptables` system-wide with the following commands:

```bash
git clone https://github.com/jamescherti/update-iptables
cd update-iptables
sudo ./install.sh
````

Enable the firewall service at boot:

```
systemctl enable update-iptables
```

## Usage

By default, `update-iptables` **blocks all traffic**, including input, output, and forwarding, except for connections on the loopback interface.

### Adding Custom Rules

Custom rules can be added by creating a `.rules` script in the `/etc/update-iptables.d/` directory. Files in this directory are sourced sequentially during firewall initialization, allowing modular and organized rule management.

Create a new file in `/etc/update-iptables.d/` with a descriptive name, ending with `.rules`. For example:

```bash
sudo nano /etc/update-iptables.d/10-my-rules.rules
```

Add your `iptables` commands in the file. For example:

```bash
# Accept traffic belonging to already established connections or packets related
# to them. This rule ensures that once a connection has been permitted by a
# specific rule, all subsequent packets for that session are processed quickly
# and efficiently without re-evaluating the entire rule set.
allow_established

# Allow all legitimate internal traffic on the 'lo' interface,
# which is required for local applications and services to communicate.
# This function also drops packets on non-loopback interfaces that spoof loopback
# IP addresses (127.0.0.0/8 and ::1/128) to protect the system from
# external manipulation and network pollution.
allow_loopback

# Accept all incoming ICMP echo requests, also known as pings. Only the first
# packet will count as new, the others will be handled by the RELATED,
# ESTABLISHED rule. Since the computer is not a router, no other ICMP with
# state NEW needs to be allowed.
allow_ping

# Permit outbound network traffic for a specific list of local system users.
# (Usernames that do not exist on the host are silently ignored.)
allow_users_output systemd-timesync sockd proxy root alpm

# SSH
iptables -A UI_INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
```

Reload the firewall to apply the new rules:

```bash
sudo systemctl restart update-iptables
```

The new rule will be integrated automatically, respecting the modular structure of the firewall.

## Features

* **Low-level `iptables` control**: Defines firewall rules directly using `iptables` and `ip6tables` without intermediate management layers.

* **Modular configuration**: Supports drop-in rule scripts located in `/etc/update-iptables.d/`. Files with the `.rules` extension are sourced sequentially, allowing incremental and organized firewall configuration.

* **Stateful firewall rules**: Uses connection tracking (`conntrack`) to manage `NEW`, `ESTABLISHED`, `RELATED`, and `INVALID` packet states.

* **IPv4 and IPv6 support**: Applies rules consistently to both `iptables` and `ip6tables`.

* **Custom rule chains**: Introduces dedicated chains (`UI_INPUT`, `UI_OUTPUT`, `UI_FORWARD`, `UI_PREROUTING`, `UI_POSTROUTING`) to isolate managed rules from system chains.

* **Per-user network policies**: Allows outgoing traffic to be restricted or permitted based on the Unix user ID using the `owner` module.

* **Secure default policy**: Uses restrictive default policies (DROP) until rules are successfully applied.

* **Automatic rule validation and rollback behavior**: In case of failure during execution, all policies are locked down to DROP to avoid leaving the system in an insecure state.

* **Packet logging support**: Optional logging chains record packets passing through firewall chains with rate limiting.

* **Spoofing and malformed packet protection**: Drops packets with invalid connection states, suspicious TCP flag combinations, and spoofed source addresses.

* **Localhost protection rules**: Ensures correct handling of loopback traffic while preventing spoofed loopback packets from external interfaces.

* **Rule diff inspection**: Saves firewall rules before and after execution and optionally displays a diff when changes occur.

* **Verbose execution mode**: Displays executed `iptables` commands when verbose mode is enabled.

* **Safe rule flushing**: Supports cooperative flushing of managed chains or full firewall reset through command-line options.

## License

Copyright (C) 2012-2026 [James Cherti](https://www.jamescherti.com)

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.

## Links

- [update-iptables @GitHub](https://github.com/jamescherti/update-iptables): A low-level Linux Firewall
