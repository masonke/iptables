Project to develop and maintain an iptables rule set that will provide protection from common attacks. 

V1 Sept 13, 2016 - Initial version completed.
V2 Sept 14, 2016 - Notes on running the script (in progress)

Running the script
In the default mode, the script will allow all outbound traffic and inbound SSH. It limits pings to 1/sec
To enable other protocols, you need to allow them. Working rules for 80 and 443 are commented out just below the ssh line. You can uncomment these and edit as needed.
Other rules and explanation of syntax are located in additional_examples.txt
There are also examples there for rate limiting to block syn attacks, allowing specific address, and rate limiting per source IP.

List rules and stats for the lines in the tables
    iptables -nvL --line-numbers
    iptables -t raw -nvL --line-numbers
    iptables -t nat -nvL --line-numbers
    
Clear all iptables lines. The input accept is optional, but can prevent you from locking yourself out by accident.
    iptables -P INPUT ACCEPT
    iptables -F


Assumptions: 
It is assumed that the URG flag is not being used legitimately. All segments with URG set will be dropped. You can change this behavior by commenting out the line with URG URG and uncomment the following lines.
There is only one interface on the host, not counting the loopback.

Fragments are not expected and will be logged and dropped.

Notes:
PREROUTING Chain: Tests immediately after being received by an interface.
Used with the raw, mangle and nat tables, higher performance than INPUT


INPUT Chain: Tests right before being handed to a local process.
Used with the default filter table.

See additional_examples.txt for specific examples and explanations.