# Overview

Software Defined Networks (SDN) is a paradigm for centrally controlling the
behavior of network switches with a standard protocol (e.g., OpenFlow). The
logic for forwarding the traffic in the network is centralized in a single
software component called the _controller_.

The idea of this proof of concept project, is to integrate a firewall gateway
into an SDN cotrolled network, such that depending on a configurable policy,
traffic in the network would either bypass the gateway or will be forwarded to
the gateway to decide on what to do (depending on the gateway policy).

Whenever a switch encounters an unknown packet it will forward it to the
controller.

*   The controller uses a discovery module, which sends out test packets to map
    the links between the different switch ports. 

	The controller listens to the events about discovered links and builds
	paths leading from each switch to the port that is connected to the
	firewall gateway. These paths are then used when forwarding non-bypassed IP
	packets to the firewall gateway.

*   Non-IP packets are forwarded - the controller notifies the switch to
    register a flow with the specific packet parameters with the action to
    forward matching packets to the appropriate switch port. If the destination
    is yet unknown to the controller, it will ask the switch to flood the
    packet to all the ports. For every packet that it sees, the controller
    learns that the source MAC address is behind the port in the switch from
    which the packet came.

*   IP packets are inspected against a connection table. If found, the action
    (see the next bullet) that is specified in the table is performed.

*   Unknown IP packets are matched against the bypass policy rules, the action
    that is specified in the rule (either bypass, or forward to the firewall)
    is enforced. Bypass is normal forwarding (such as what is done to non-IP
    packets). Forwarding to the firewall means, in every switch, forwarding to
    the port leading to the firewall gateway. Packets that come from the port
    that leads to the gateway are assumed to have been already inspected, and
    so they are forwarded just like bypassed packets.


# Environment

SDN experiments are often done in a virtualized network framework called
[Mininet](https://github.com/mininet/mininet/wiki/Introduction-to-Mininet). It
allows the user to specify an arbitrary number of hosts connected by switches
and controlled by a controller, where everything is run on a single host
(often, the Mininet host is a VM running on a personal desktop/laptop).

For the controller (the software component, with which the switches talk to
make decisions about forwarding), we chose
[POX](https://openflow.stanford.edu/display/ONL/POX+Wiki) - a Python based,
research oriented OpenFlow controller.

We configure Mininet with a custom topology.

In our custom POX module (fw.py), we use the POX discovery module to enable
automatic learning of the switch topology (finding out the path from every
switch to the firewall gateway port). We also use webcore and webservice
modules to support web services


# Limitations

*   There is an assumption that the firewall gateway would either drop a packet
    or accept it without modifying the connection parameters (e.g., no NAT),
    this allows the controller to recognize the packet after it was forwarded
    to the firewall.

*   IP fragments are dropped.

*   Only IPv4 is handled.

*   Once a connection has expired from the controller connection table, packets
    with reverse connection parameters (of the expired connection) might match
    a bypass rule. This means that the connection would be registered as a
    bypass connection and packets that actually belong to the original expired
    connection would not be forwarded to the firewall anymore.

*   The long timeout on TCP connection means that most TCP connections would
    occupy resources in the controller connection table, long after they have
    closed.


# Setup

## Ubuntu Server VM

*   Install an Ubuntu server 12.04.2 32bit on VirtualBox (another VM technology
    can be used as well):

    *   Add a host only interface.

    *   Choose the ssh server option when installing Ubuntu.

    *   Disable the password requirement for sudo:

            $ sudo sed -i 's/^\(%sudo.*)\) ALL/\1 NOPASSWD: ALL/' /etc/sudoers

## Code

*   Install the demo code from GitHub:

        $ sudo apt-get install git
        $ cd ~
        $ git clone https://github.com/CheckPointSW/sdn.git

## Mininet

*   Install Mininet/POX - you must have Internet access!

        $ ~/sdn/setup.sh

*   Run Mininet with custom topology and POX using our fw component:

    (the POX fw module logs are at /tmp/c0-pox.log)

        $ sudo mn --custom ~/sdn/custom.py --topo fw --controller pox --mac


# Configuration

## Mininet Topology

Configures the Mininet switches and hosts (it is read by custom.py):

*   `switches` - a list of Mininet switch names

*   `links` - a list of lists. Each sub list specifies `[NODE1, PORT1, NODE2,
	PORT2]`, where a `NODE` is either a switch (listed in switches before), or
	a host (either `hNN` or `fw1`). `PORT` need only be specified for switches,
	it should be null for hosts.

*   Example (see -  ~/sdn/topo.json in the source code):

		{
    		"switches": ["s1", "s2", "s3"],
    		"links": [
        		["s1", 1, "fw1", null],
        		["s1", 2, "s2", 1],
        		["s1", 3, "s3", 1],
        		["s2", 2, "h22", null],
        		["s2", 3, "h23", null],
        		["s3", 2, "h32", null],
        		["s3", 3, "h33", null]
    		]
		}

## Firewall Bypass Policy

Configures the fw bypass/forwarding policy (it is read by fw.py):

*   `fw1` - the port to which the firewall gateway is connected: `[SWITCH,
    PORT]` (this must match the fw1 link in topo.json)

*   `policy` - contains timeouts and rules

	*   `timeouts` - a map between IP protocol numbers and time in seconds, the
	    time indicates how long the controller will remember an inactive
	    connection with the respective IP protocol

	*   `rules` - a list of lists. Each sub list specifies `[SRC, DST, SERVICE,
	    ACTION]`

		* `SRC`, `DST` - either a host name or a list of host names

		* `SERVICE`: see the comment before the matchService() function in
		  fw.py

		* `ACTION`: true means allow bypass, false means forward to the
		  firewall

* Example (see - ~/sdn/fw.json in the source code):

		{
    		"fw1": ["s1", 1],
    		"policy": {
        		"timeouts": {
            		"0": 40,
            		"1": 40,
            		"6": 3600,
            		"17": 40
        		},
        		"rules": [
            		["h22", "h33", null, true],
            		["h33", ["h22", "h23"], null, true],
            		["h23", "h32", [1, {"6": [80, 443]}, {"17": 53}, "50-51"], true],
            		[null, null, null, false]
        		]
    		}
		}


# Firewall Integration

## Simulation

*   To simulate a firewall that drops all the traffic - do nothing.

*   To simulate a firewall that accepts all the traffic:

	Run the "bridge" (when Mininet is already running) with a localhost echo
	server:

        $ socat tcp-listen:31173,reuseaddr exec:cat & ~/sdn/bridge.py replay localhost:31173

    (press Ctrl-C to stop)

	"bridge.py replay" starts tcpdump on the Mininet fw1 "host" interface and
	forwards the packets on a socket to the destination network address,
	packets that return from socket are written to the fw1 "host" interface
	using tcpreplay.

## Firewall Gateway on another VM

*   Asssumptions:

    *    The gateway can run on a VM.

	*    The gateway has a working Python envrionment.

	*    The gateway will filter traffic that comes in on a tap (tun/tap)
		 interface. The interface is connected to a Linux bridge, which is
		 configured to work in hairpin mode.

*   Start a VM with a firewall gateway that has an interface on the same
    host-only network as the Mininet VM.

*   Run the tunneling bridge client/server on the sdn and gateway VMs (run a
    single script from the sdn VM).

        $ ~/sdn/bridge.sh GATEWAY-ADDRESS

    (press Return or Ctrl-C to stop)

	"bridge.sh" runs a local "bridge.py replay" to forward the traffic to the
	firewall gateway. It also runs (over ssh) a remote "bridge.py tap" on the
	firewall gateway that creates a tap interface and listens for a connection
	from the Mininet VM and forwards that packets into the tap interface, and
	from the tap interface back to the Mininet VM.


# Web Services

POX exposes a set of extensible web services as follows:

*   General:

        $ curl -D - http://127.0.0.1:8000/

*   OpenFlow:

        $ curl -D - -d '{"method":"get_switches", "id": 0}' http://127.0.0.1:8000/OF/pretty
        $ curl -D - -d '{"method":"get_flow_stats", "params":["00-00-00-00-00-01"], "id": 0}' http://127.0.0.1:8000/OF/pretty

*   Our POX FW extension:

        $ curl -D - http://127.0.0.1:8000/FW/


# Miscellaneous Helper Scripts

*   Use ~/sdn/m to control hosts in a running Mininet.

    *   Print the host address:

            $ ~/sdn/m h22 addr

    *   List all the hosts:
            $ ~/sdn/m -l
	*   Ping another host (the arguments on the command line are automatically
	    resolved):

            $ ~/sdn/m h22 ping h32

*   Ping all the (non fw\*) hosts in the Mininet network:

        $ ~/sdn/pingall.sh

*   Tunnel the firwall traffic elsewhere - see usage of ~/sdn/bridge.py and
    ~/sdn/bridge.sh in Firewall Integration above.


# References

*   POX wiki: <https://openflow.stanford.edu/display/ONL/POX+Wiki>

*   Introduction to Mininet:
    <https://github.com/mininet/mininet/wiki/Introduction-to-Mininet>

*   Mininet documentation:
    <https://github.com/mininet/mininet/wiki/Documentation>

*   OpenFlow tutorial: <http://www.openflow.org/wk/index.php/OpenFlow_Tutorial>

*   OpenFlow 1.0.0 spec:
    <http://www.openflow.org/documents/openflow-spec-v1.0.0.pdf>

