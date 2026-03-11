# update-iptables - A low-level Linux Firewall

## Introduction

The `update-iptables` Bash script implements a firewall for managing network traffic and routing.

It supports a modular configuration model through drop-in scripts located in `/etc/update-iptables-rules.d/`. Each file is a Bash script executed sequentially during firewall initialization.

This firewall is intended for Linux system administrators who require precise control over packet states, network address translation, and custom routing chains. Rules are defined directly through `iptables` without the abstraction layers commonly introduced by modern firewall management tools.

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

By default, `update-iptables` blocks all traffic, including input, output, and forwarding, except for connections on the loopback interface.

### Adding Custom Rules

Custom rules can be added by creating a `.rules` script in the `/etc/update-iptables-rules.d/` directory. Files in this directory are sourced sequentially during firewall initialization, allowing modular and organized rule management.

Create a new file in `/etc/update-iptables-rules.d/` with a descriptive name, ending with `.rules`. For example:

```bash
sudo nano /etc/update-iptables-rules.d/10-ssh.rules
```

Add your `iptables` commands in the file. For example, to allow incoming SSH connections:

```bash
iptables -A MY_INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A MY_OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```

Reload the firewall to apply the new rules:

```bash
sudo systemctl restart update-iptables
```

The new rule will be integrated automatically, respecting the modular structure of the firewall.

## Features

* **Low-level `iptables` control**: Defines firewall rules directly using `iptables` and `ip6tables` without intermediate management layers.

* **Modular configuration**: Supports drop-in rule scripts located in `/etc/update-iptables-rules.d/`. Files with the `.rules` extension are sourced sequentially, allowing incremental and organized firewall configuration.

* **Stateful firewall rules**: Uses connection tracking (`conntrack`) to manage `NEW`, `ESTABLISHED`, `RELATED`, and `INVALID` packet states.

* **IPv4 and IPv6 support**: Applies rules consistently to both `iptables` and `ip6tables`.

* **Custom rule chains**: Introduces dedicated chains (`MY_INPUT`, `MY_OUTPUT`, `MY_FORWARD`, `MY_PREROUTING`, `MY_POSTROUTING`) to isolate managed rules from system chains.

* **NAT and routing support**: Provides helper functions for NAT and network routing, including masquerading and network bridging.

* **Per-user network policies**: Allows outgoing traffic to be restricted or permitted based on the Unix user ID using the `owner` module.

* **Secure default policy**: Uses restrictive default policies (`DROP`) until rules are successfully applied.

* **Automatic rule validation and rollback behavior**: In case of failure during execution, all policies are locked down to `DROP` to avoid leaving the system in an insecure state.

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
