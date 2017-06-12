#!/bin/bash

# https://www.netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-7.html

# Assumptions: 
# It is assumed that the URG flag is not being used legitimately. All segments with URG set will be dropped. You can change this behavior by commenting out the line with URG URG and uncomment the following lines.
# There is only one interface on the host, not counting the loopback.

# Notes:
# PREROUTING Chain: Tests immediately after being received by an interface.
# PREROUTING is used with the raw, mangle and nat tables
#
# INPUT Chain: Tests right before being handed to a local process.
# INPUT OUTPUT are used with the default filter table.
#
# UDP as a client is handled with the RELATED clause at the end

# Flush all current rules from iptables. First, change the INPUT policy to ACCEPT, or you can lock yourself out
iptables -P INPUT ACCEPT
iptables -F

# Allow access for local host on the loopback. This might be overkill, but it is safer.
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
 
# Don't forward traffic
iptables -P FORWARD DROP 

# Drop invalid packets
iptables -A INPUT -m state –state INVALID -j DROP

# Drop all fragments. This may cause problems for VPNs that do not work right. If it does, then comment ot the lines.
iptables -t raw -A PREROUTING  -f -j LOG --log-level 7 --log-prefix "FRAG-DROP: "
iptables -t raw -A PREROUTING  -f -j DROP

# Limit the incoming icmp ping request to 1/sec. See the README for details on limits. Adjust the rate as needed:
iptables -A INPUT -p icmp -m limit --limit  1/s --limit-burst 1 -j ACCEPT
iptables -A INPUT -p icmp -m limit --limit 1/s --limit-burst 1 -j LOG --log-level 7 --log-prefix "PING-DROP: "
iptables -A INPUT -p icmp -j DROP

# Allow other icmp
iptables -t raw -A PREROUTING -p icmp --icmp-type any -j ACCEPT

# Protect against common tcp attacks
# Block tcp packets that have no tcp flags set.
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
# Block tcp packets that have all tcp flags set.
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP

# Drop all packets with the URG flag set. This flag is seldom used in modern applications.
#If this causes a problem, comment out this line and uncomment the lines after
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL URG -j LOG --log-prefix "URG-DROP:"
iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL URG -j DROP

# Uncomment these rules if you need URG flag support.
# Drop SYN,URG
#iptables -t raw -A PREROUTING -p tcp --tcp-flags SYN,URG SYN,URG -j DROP
# Block tcp packets with FIN and URG. This will catch the traditional XMAS.
#iptables -t raw -A PREROUTING -p tcp --tcp-flags ALL FIN,URG -j DROP

# Block illegal tcp flags combinations
# Block tcp packets with SYN and FYN
iptables -t raw -A PREROUTING  -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
# Block tcp packets with SYN and RST
iptables -t raw -A PREROUTING  -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
# Allow SYN alone
iptables -t raw -A PREROUTING -p tcp --tcp-flags SYN SYN -j ACCEPT

# Make sure NEW incoming tcp connections are SYN packets; otherwise we need to drop them
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Drop excessive RST packets to avoid RST attacks, by given the next real data packet in the sequence a better chance to arrive first.
# This is a global limit, adjust as needed.
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Allow SSH connections on tcp port 22 from devices in 10/8
# This is essential when working on remote servers via SSH to prevent locking yourself out of the system
iptables -t raw -A PREROUTING -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT

# Enable dhcp
iptables -I INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT

# Accept packets belonging to established and related connections. 
# This needs to be one of the last access rules 
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Change the INPUT to default Drop 
# Do not put any rules below this line!
iptables -A INPUT -j LOG --log-level 7 --log-prefix "DEFAULT-DROP: "
iptables -A INPUT -j DROP

# Set default policies for INPUT, FORWARD and OUTPUT chains
# Make sure OUTPUT is ACCEPT or things will break quickly
# In this case, the INPUT DROP is redundant, enable if you want belts and suspenders. Remember, -F does not flush the policy.
#iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Save settings
/sbin/service iptables save

# List rules and stats for the tables
iptables -nvL --line-numbers
iptables -t raw -nvL --line-numbers
#iptables -t nat -nvL --line-numbers