#   Copyright 2013 Check Point Software Technologies LTD
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import json
import os
import re
import subprocess
import threading
import time

from heapdict import heapdict

from pox.core import core
from pox.lib.addresses import IPAddr
from pox.lib.packet import ICMP
from pox.lib.packet import ethernet, icmp, ipv4, tcp, udp
from pox.lib.revent import *
from pox.openflow import libopenflow_01 as of
from pox.openflow import discovery, webservice
from pox.web import webcore

# add missing ICMP protocol info
ICMP.TYPE_PARAM_PROB = 12
ICMP.TYPE_TIMESTAMP_REQUEST = 13
ICMP.TYPE_TIMESTAMP_REPLY = 14
ICMP.requests = {
    ICMP.TYPE_ECHO_REQUEST: ICMP.TYPE_ECHO_REPLY,
    ICMP.TYPE_TIMESTAMP_REQUEST: ICMP.TYPE_TIMESTAMP_REPLY}
ICMP.replies = {
    ICMP.TYPE_ECHO_REPLY: ICMP.TYPE_ECHO_REQUEST,
    ICMP.TYPE_TIMESTAMP_REPLY: ICMP.TYPE_TIMESTAMP_REQUEST}

log = core.getLogger()

switches = {}
switchLock = threading.RLock()

responses = []
zombies = set([])
responseCondition = threading.Condition()

edges = {}
edgeLock = threading.RLock()
fwEdges = {}

# PATH_ENTRY:
# dpid: [next-port-for-client-to-server, next-port for server-to-client]
# (client-to-server is not-reversed, server-to-client is reversed)
paths = {}
pathLock = threading.RLock()

timeouts = {}
RULE_SRC = 0
RULE_DST = 1
RULE_SERVICE = 2
RULE_ACTION = 3
rules = []

class Key(object):
    SRC = 0
    SPORT = 1
    DST = 2
    DPORT = 3
    PROTO = 4

    def __init__(self, *arg):
        if len(arg) != 5:
            raise Exception('Key must contain exactly 5 elements')
        self.key = tuple(arg)

    def rev(self, allowReq=False):
        if self.key[Key.PROTO] == ipv4.ICMP_PROTOCOL:
            if self.key[Key.SPORT] in ICMP.replies:
                sport, dport = (ICMP.replies[self.key[Key.SPORT]],
                        self.key[Key.DPORT])
            elif self.key[Key.SPORT] in ICMP.requests and allowReq:
                sport, dport = (ICMP.requests[self.key[Key.SPORT]],
                        self.key[Key.DPORT])
            else:
                return self.key
        else:
            sport, dport = self.key[Key.DPORT], self.key[Key.SPORT]
        return Key(self.key[Key.DST], sport, self.key[Key.SRC], dport,
                self.key[Key.PROTO])

    def expiration(self):
        return time.time() + timeouts.get(self.key[Key.PROTO], timeouts[0])

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        return self.key == other.key

    def __getitem__(self, index):
        return self.key[index]

    def __str__(self):
        return '(' + ' '.join([str(a) for a in self.key]) + ')'

    def __repr__(self):
        return 'Key' + repr(self.key)


class Connection(object):
    s = heapdict()
    lock = threading.RLock()
    PURGE_PERIOD = 2
    lastPurge = 0

    def __init__(self, key, action, expiration=0):
        self.key = key
        self.action = action
        if not expiration and not key is None:
            self.expiration = self.key.expiration()
        else:
            self.expiration = expiration
        removed = []
        with Connection.lock:
            now = time.time()
            if now > Connection.lastPurge + Connection.PURGE_PERIOD:
                while len(Connection.s) > 0:
                    k, c = Connection.s.peekitem()
                    if not c.expiration < now:
                        break
                    k, c = Connection.s.popitem()
                    removed.append(k)
                Connection.lastPurge = now
            nextPurge = Connection.lastPurge + Connection.PURGE_PERIOD - now
            core.callDelayed(nextPurge, Connection.purge)
            if not key is None and self.expiration > now:
                Connection.s[key] = self
        for k in removed:
            clearFlows(k)

    def refresh(self):
        with Connection.lock:
            del Connection.s[self.key]
            self.expiration = self.key.expiration()
            Connection.s[self.key] = self

    def __lt__(self, other):
        return self.expiration < other.expiration

    def __str__(self):
        return '%s -> expiration: %.1f action: %s' % (
                self.key, self.expiration - time.time(), self.action)

    def __repr__(self):
        return 'Connection(' + ', '.join([repr(self.key), repr(self.action),
                repr(self.expiration)]) + ')'

    @staticmethod
    def get(key):
        for reverse in [False, True]:
            if reverse:
                key = key.rev()
            with Connection.lock:
                conn = Connection.s.get(key)
            if conn:
                return conn, reverse
        return None, False

    @staticmethod
    def purge():
        Connection(None, False)

    @staticmethod
    def dump():
        lines = []
        with Connection.lock:
            conns = Connection.s.values()
        for conn in conns:
            lines.append(str(conn))
        return lines


def readPolicy(home):
    # these 2 functions are specific to Mininet
    def mnHostToAddr(host):
        a = subprocess.check_output([os.path.join(home, 'm'), host, 'addr'])
        a = IPAddr(a.strip())
        log.info(host + ': ' + str(a))
        return a
    def mnSwitchToDpid(switch):
        if not re.match(r's\d+$', switch):
            raise Excpetion('Unexpected switch name')
        return int(switch[1:], 10)

    with open(os.path.join(home, 'fw.json')) as configFile:
        config = json.load(configFile)

    def readLink(link):
        return (mnSwitchToDpid(link[0]), link[1])
    for rev in [False, True]:
        fwEdges[rev] = readLink(config['fw1'])
    log.info(repr(fwEdges))

    for p, t in config['policy']['timeouts'].iteritems():
        timeouts[int(p, 10)] = t

    # the rules are in a list
    # each rule is a list:
    # [SRC, DST, SERVICE, ACTION]
    #
    # SRC and DST are either None or a string with a host name or address, or a
    # list of host names or addresses
    #
    # SERVICE: see matchService() below
    #
    # ACTION is True for bypass, False for forward to fw

    ntoa = {}
    def resolve(h):
        if h is None:
            return h
        if isinstance(h, str) or isinstance(h, unicode):
            h = [h]
        result = []
        for n in h:
            n = str(n)
            if n not in ntoa:
                ntoa[n] = mnHostToAddr(n)
            result.append(ntoa[n])
        return set(result)
    for rule in config['policy']['rules']:
        rule[RULE_SRC] = resolve(rule[RULE_SRC])
        rule[RULE_DST] = resolve(rule[RULE_DST])
        rules.append(rule)

# called with edgeLock and with pathLock
def updatePaths(queue, index):
    visited = set([])
    while len(visited) < len(switches) and len(queue) > 0:
        newQueue = []
        for e in queue:
            if e[0] in visited or e[0] not in edges:
                continue
            visited.add(e[0])
            if e[0] not in paths:
                paths[e[0]] = {}
            paths[e[0]][index] = e[1]
            for edge in edges[e[0]].values():
                if edge[0] in visited:
                    continue
                newQueue.append(edge)
        queue = newQueue

# SERVICE: 'None' | PROTO | PROTO-LIST
#   PROTO-LIST: '[' PROTO (',' PROTO)* ']'
#   PROTO: NUMBER | '"' NUMBER '-' NUMBER '"' |
#           '{' '"' TCP-OR-UDP '"' ':' PORT-SPEC '}'
#   TCP-OR-UDP: '6' | '17'
#   PORT-SPEC: PORT | PORT-LIST
#   PORT-LIST: '[' PORT (',' PORT)* ']'
#   PORT: NUMBER | '"' NUMBER '-' NUMBER '"'
def matchService(service, proto, port):
    return matchNameRangeList(service, proto, port, matchNameRangeList)

def matchNameRangeList(service, proto, port=None, dictMatch=None):
    log.info('match nrl %s %s %s %s' % (service, proto, port, dictMatch))
    if service is None:
        return True
    if not isinstance(service, list):
        service = [service]
    for s in service:
        svc = s
        if isinstance(svc, dict):
            if dictMatch is None or port is None or str(proto) not in svc:
                continue
            return matchNameRangeList(svc[str(proto)], port)
        if isinstance(svc, unicode):
            svc = str(svc)
        if isinstance(svc, int):
            svc = "%d-%d" % (svc, svc)
        begin, end = svc.split('-')
        if int(begin, 10) <= proto <= int(end, 10):
            return True
    return False

def isError(ip):
    return isinstance(ip.next, icmp) and ip.next.type in set([
            ICMP.TYPE_DEST_UNREACH, ICMP.TYPE_SRC_QUENCH,
            ICMP.TYPE_REDIRECT, ICMP.TYPE_TIME_EXCEED, ICMP.TYPE_PARAM_PROB])

def match(ip):
    if ip.flags & ipv4.MF_FLAG or ip.frag:
        # a fragment
        return None, False
    ports = [None, None]
    if isinstance(ip.next, udp) or isinstance(ip.next, tcp):
        ports = [ip.next.srcport, ip.next.dstport]
    outerIp = ip
    if isinstance(ip.next, icmp):
        if isError(ip):
            ip = ipv4(raw=ip.raw[ip.hl * 4 + 8:])
            ports = [None, None]
            if isinstance(ip.next, udp) or isinstance(ip.next, tcp):
                ports = [ip.next.srcport, ip.next.dstport]
        else:
            ports = [ip.next.type, ip.next.code]

    key = Key(ip.srcip, ports[0], ip.dstip, ports[1], ip.protocol)

    log.info(key)

    conn, reverse = Connection.get(key)
    if not conn is None:
        adj = ''
        if ip != outerIp:
            reverse = not reverse
            adj = 'inner '
        elif reverse:
            adj = 'reverse '
        log.info('matched %sconn %s\n%s' % (adj, key, conn))
        return conn, reverse


    action = False
    for rule in rules:
        if rule[RULE_SRC] is None or key[Key.SRC] in rule[RULE_SRC]:
            if rule[RULE_DST] is None or key[Key.DST] in rule[RULE_DST]:
                if matchService(rule[RULE_SERVICE],
                        key[Key.PROTO], key[Key.DPORT]):
                    log.info('matched rule: ' + repr(rule))
                    action = rule[RULE_ACTION]
                    break

    conn = Connection(key, action)
    log.info('new conn: %s %s' % (action, key))
    return conn, reverse

def dumpOF(ofp):
    duration = getattr(ofp, 'duration_sec', None)
    if not duration is None:
        ns = getattr(ofp, 'duration_nsec', None)
        if not ns is None:
            ns = ns
            duration += ns / 1e9
            duration  = '%.1f' % duration
    return '%s->%s %04x (%s %s %s %s %s) %s/(%s, %s)' % (
            ofp.match.in_port, ofp.cookie, ofp.match.dl_type,
            ofp.match.nw_src, ofp.match.tp_src,
            ofp.match.nw_dst, ofp.match.tp_dst, ofp.match.nw_proto,
            duration,
            getattr(ofp, 'idle_timeout', None),
            getattr(ofp, 'hard_timeout', None))

def clearFlows(k):
    with switchLock:
        sws = switches.values()
    for s in sws:
        for reverse in [False, True]:
            key = k
            if reverse:
                key = k.rev(True)
            msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
            msg.match = of.ofp_match()
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = key[Key.PROTO]
            msg.match.nw_src = key[Key.SRC]
            msg.match.nw_dst = key[Key.DST]
            if not key[Key.SPORT] is None:
                match.tp_src = key[Key.SPORT]
            if not key[Key.DPORT] is None:
                match.tp_dst = key[Key.DPORT]
            s.connection.send(msg)


class FWSwitch(EventMixin):
    def __init__(self, connection):
        self.log = core.getLogger('fw(' + str(connection.dpid) + ')')
        self.connection = connection
        self.macToPort = {}
        self.listenTo(connection)

    def _handle_PacketIn(self, event):
        self.log.debug(Connection.dump())
        p = event.parsed
        port = None
        for i in [0]:
            self.log.debug('packet in (%d.%d): %s' % (
                    self.connection.dpid, event.port, p.dump()))
            # forward non ipv4 packets
            if not isinstance(p.next, ipv4):
                break
            ip = p.next
            conn, reverse = match(ip)
            if conn is None: # a fragment
                # FIXME: we might want to do better with fragments
                self.drop(event)
                return
            isErr = isError(ip)
            if not isErr:
                conn.refresh()
            # for non-bypassed connections set the out port according to the 
            # upstream path to the firewall, unless we are coming downstream
            # from the firewall
            if not conn.action:
                # FIXME: this might throw an exception if the path have not
                # yet been discovered
                with pathLock:
                    backPort = paths[self.connection.dpid][not reverse]
                    forwPort = paths[self.connection.dpid][reverse]
                if event.port != backPort:
                    port = forwPort

        self.forward(event, port=port)

    def forward(self, event, port=None):
        p = event.parsed

        if not isinstance(p.next, ipv4):
            self.macToPort[p.src] = event.port

        if p.dst.is_multicast:
            self.flood(event)
            return

        if p.dst not in self.macToPort:
            self.flood(event)
            return

        if port is None:
            port = self.macToPort[p.dst]
        if port == event.port:
            self.log.warning('will not forward back to the same port:\n' +
                    p.dump())
            self.drop(event)
            return
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(event.parsed, event.port)
        msg.actions.append(of.ofp_action_output(port=port))
        msg.cookie = port
        msg.data = event.ofp
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        self.connection.send(msg)
        self.log.info('pushed: %s' % dumpOF(msg))
        return

    def flood(self, event):
        self.log.debug('flood')
        if isinstance(event.parsed.next, ipv4):
            self.log.warning('refusing to flood an ipv4 packet')
            self.drop(event)
            return
        msg = of.ofp_packet_out()
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = event.port
        msg.data = event.ofp
        self.connection.send(msg)

    def drop(self, event):
        self.log.info('drop')
        msg = of.ofp_packet_out()
        msg.in_port = event.port
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)

    def _handle_FlowStatsReceived(self, event):
        out = []
        for o in event.ofp:
            for s in o.body:
                out.append('%s: %s' % (self.connection.dpid, dumpOF(s)))
            with responseCondition:
                responses.append((o.xid, out))
                responseCondition.notifyAll()


class FW(EventMixin):
    def __init__(self):
        self.listenTo(core)

    def _handle_GoingUpEvent(self, event):
        log.info('GoingUpEvent')
        self.listenTo(core.openflow)
        self.listenTo(core.openflow_discovery)

    def _handle_ConnectionUp(self, event):
        log.info('ConnectionUP %s' % (event.connection,))
        with switchLock:
            switches[event.dpid] = FWSwitch(event.connection)

    def _handle_ConnectionDown(self, event):
        log.info('ConnectionDown %s' % (event.connection,))
        with switchLock:
            del switches[event.dpid]

    def _handle_LinkEvent(self, event):
        log.info('LinkEvent: added: %s removed: %s link: %s' % (
            event.added, event.removed, event.link))
        with edgeLock:
            if event.added and not event.removed:
                if event.link.dpid2 not in edges:
                    edges[event.link.dpid2] = {}
                edges[event.link.dpid2][event.link.port2] = (
                        event.link.dpid1, event.link.port1)
            elif event.removed and not event.added:
                if (event.link.dpid2 not in edges or 
                        event.link.port2 not in edges[event.link.dpid2] or
                        edges[event.link.dpid2][event.link.port2][0] !=
                                event.link.dpid1 or
                        edges[event.link.dpid2][event.link.port2][1] !=
                                event.link.port1):
                    raise Exception('Unknown link')
                del edges[event.link.dpid2][event.link.port2]
            else:
                raise Exception('Unexpected link event type')
            with pathLock:
                paths.clear()
                updatePaths([fwEdges[False]], False)
                updatePaths([fwEdges[True]], True)
                log.info(repr(paths))


def dumpFlows():
    pending = set([])
    with switchLock:
        sws = switches.values()
    for s in sws:
        msg = of.ofp_stats_request()
        msg.body = of.ofp_flow_stats_request()
        msg.body.match = of.ofp_match()
        msg.body.match.dl_type = ethernet.IP_TYPE
        msg.body.table_id = 0xff
        msg.body.out_port = of.OFPP_NONE
        pending.add(msg.xid)
        s.connection.send(msg)
    flows = []
    expiration = time.time() + 5
    while len(pending) > 0:
        timeout = expiration - time.time()
        if timeout <= 0:
            break
        responseCondition.acquire()
        responseCondition.wait(timeout)
        with responseCondition:
            unHandled = []
            while len(responses) > 0:
                r = responses.pop(0)
                if r[0] not in pending:
                    if r[0] in zombies:
                        zombies.remove(r[0])
                        continue
                    unHandled.append(r)
                    continue
                pending.remove(r[0])
                flows.extend(r[1])
            responses.extend(unHandled)
    with responseCondition:
        for xid in pending:
            zombies.add(xid)
    flows.sort()
    return flows, len(pending) > 0


class FWRequestHandler(webcore.SplitRequestHandler):
    def do_GET(self):
        conns = Connection.dump()
        flows, partial = dumpFlows()
        response = 'Flows%s:\n%s\n\nConnections:\n%s\n\nTotal: %s%s %s' % (
                ' (partial)' if partial else '', '\n'.join(flows),
                '\n'.join(conns),
                len(flows), '*' if partial else '', len(conns))
        self.send_response(200, "OK")
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)


def launch(home):
    readPolicy(home)
    # Send full packets to controller
    core.openflow.miss_send_len = 0xffff
    discovery.launch(explicit_drop='False')
    webcore.launch()
    webservice.launch()
    core.registerNew(FW)
    core.WebServer.set_handler("/FW/", FWRequestHandler)


