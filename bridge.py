#!/usr/bin/env python

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

import fcntl
import os
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

from select import select

dirname = os.path.dirname(os.path.abspath(sys.argv[0]))

localAddrs = set([])
procs = []
brs = []

def log(msg):
    f = sys.stderr
    for c in msg:
        rl, wl, xl = select([], [f], [])
        f.write(c)

def safeLog(msg):
    try:
        log(msg)
    except:
        pass

def ll(*args):
    log(' '.join([str(a) for a in args]) + '\n')

currentError = None
def error(msg):
    global currentError
    if currentError:
        safeLog('%s: already handling %s\n' % (msg, currentError))
        return
    currentError = Exception(msg)
    raise currentError
    
def addToLocal(host):
    '''Add the MAC address of the host to localAddrs'''
    addr = subprocess.check_output(os.path.join(dirname, 'm') + ' ' +
            host + ' ip link show ' + host + '-eth0  | ' + 
            'sed -n -e \'s/^.*link.ether \\([0-9a-f:]*\\) .*$/\\1/p\'',
            shell=True).strip()
    localAddrs.add(struct.pack('BBBBBB',
            *[int(b, 16) for b in addr.split(':')]))

def isLocal(packet):
    return packet[:6] in localAddrs or packet[6:12] in localAddrs

def tcpdump(host):
    '''Return a file object that reads packets from the host interface
    
    Run tcmpdump over the host interface with a filter for IP packets
    '''
    cmd = [os.path.join(dirname, 'm'),
            host, 'tcpdump', '-i', host + '-eth0', '-U', '-w', '-', 'ip']
    procs.append(subprocess.Popen(cmd, stdout=subprocess.PIPE))
    return procs[-1].stdout
    
def tcpreplay(host):
    '''Return a file object that writes packets to the host interface

    Run tcpreplay from a fifo and a dd process that reads from stdin and writes
    to the fifo, the dd stdin is returned
    '''
    fifo = host + 'fifo'
    try:
        subprocess.check_call([os.path.join(dirname, 'm'),
                host, 'mkfifo', fifo])
        cmd = [os.path.join(dirname, 'm'),
                host, 'tcpreplay', '-t', '-i', host + '-eth0', fifo]
        procs.append(subprocess.Popen(cmd))
        cmd = [os.path.join(dirname, 'm'),
                host, 'dd', 'of=' + fifo, 'bs=1']
        procs.append(subprocess.Popen(cmd, stdin=subprocess.PIPE))
    finally:
        subprocess.call('sleep 3; rm -f ' + fifo + ' &', shell=True)
    return procs[-1].stdin
    
def connect(addr):
    host, port = addr.split(':')
    port = int(port, 10)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock
    
def hexDump(buf):
    if not isinstance(buf, str):
        return repr(buf)
    out = ['']
    for i in xrange(0, len(buf), 16):
        line = ['%02x' % ord(b) for b in buf[i:i + 16]]
        r = i + 16 - len(buf)
        if r > 0:
            line.extend(['  '] * (i + 16 - len(buf)))
        line.append('')
        line = ' '.join(line)
        line += ''.join(
                [b if 32 <= ord(b) < 127 else '.' for b in buf[i:i + 16]])
        if r > 0:
            line += ''.join([' '] * (i + 16 - len(buf)))
        out.append(line)
    return '\n'.join(out)


class Cache(object):
    def __init__(self):
        self.d = {}

    def add(self, item):
        self.d[item] = time.time() + 3

    def __contains__(self, item):
        now = time.time()
        for i in self.d.keys():
            if self.d[i] < now:
                del self.d[i]
        return item in self.d

    def remove(self, item):
        if item in self.d:
            del self.d[item]


class RawReader(object):
    '''Base class for low level reading

    By default, read one byte - the SockReader overrides with receiving one
    frame
    '''
    MAX_FRAME = 2000 # > PcapReader.HLEN + ethernet-header-len + MTU

    def __init__(self, fileObj):
        self.fileObj = fileObj

    def fileno(self):
        return self.fileObj.fileno()

    def readSome(self):
        return self.fileObj.read(1)

    def readChunk(self):
        b = self.readSome()
        return b


class RawWriter(object):
    '''Base class for low level writing

    By default, write the whole buffer - the SockWriter overrides with sending
    the whole buffer
    '''
    def __init__(self, fileObj):
        self.fileObj = fileObj

    def writeAll(self, buf):
        self.fileObj.write(buf)

    def writePacket(self, packet):
        self.writeAll(packet)


class SockReader(RawReader):
    def readSome(self):
        return self.fileObj.recv(RawReader.MAX_FRAME)


class SockWriter(RawWriter):
    def __init__(self, fileObj):
        self.fileObj = fileObj

    def writeAll(self, buf):
        self.fileObj.sendall(buf)


class Socket(object):
    '''Implement an automatically reconnecting socket

    For a server socket, keep the listening socket and when the data socket is
    closed, try to accept a new data socket and use it.
    For a client socket, keep the socket address and when the data socket is
    closed connect a new one and use it
    '''
    def __init__(self, sockOrAddr):
        self.isServer = not isinstance(sockOrAddr, str)
        if self.isServer:
            self.sock = sockOrAddr
        else:
            self.addr = sockOrAddr
        self.fileObj = None

    def fileno(self):
        if self.hasFileObj():
            return self.fileObj.fileno()
        if self.isServer:
            return self.sock.fileno()
        # else: hasFileObj() has already raised

    def recv(self, len):
        if self.hasFileObj():
            chunk = self.fileObj.recv(len)
            if chunk: # not EOF
                return chunk
            self.fileObj.shutdown(socket.SHUT_RD|socket.SHUT_WR)
            self.fileObj.close()
            self.fileObj = None
            return ''
        return ''

    def sendall(self, buf):
        if self.hasFileObj():
            return self.fileObj.sendall(buf)

    def hasFileObj(self):
        if self.fileObj:
            return True
        if self.isServer:
            rl, wl, xl = select([self.sock], [], [], 0)
            if not len(rl):
                return False
            self.fileObj, addr = self.sock.accept()
            ll('Accepted from', addr)
            return True
        else:
            try:
                self.fileObj = connect(self.addr)
            except Exception, e:
                error(str(e))
            return True


class PcapReader(RawReader):
    '''Implement packet data reader that handles the PCAP format'''
    HEADER = 1
    DATA = 2
    HLEN = 16

    def __init__(self, name, reader):
        self.name = name
        self.reader = reader
        self.initState()

    def initState(self):
        self.buf = ''
        self.state = PcapReader.HEADER
        self.nextLen = PcapReader.HLEN

    def fileno(self):
        return self.reader.fileno()
    
    def updateBuf(self):
        total = len(self.buf)
        buf = [self.buf]
        while True:
            rl, wl, xl = select([self], [], [], 0)
            if not len(rl):
                break
            b = self.reader.readChunk()
            if not b:
                ll('%s unexpeted EOF' % self.name)
                self.initState()
                return
            buf.append(b)
            total += len(b)
        self.buf = ''.join(buf)

    def readPacket(self):
        self.updateBuf()
        packet = None
        while True:
            if len(self.buf) < self.nextLen:
                break

            if self.state == PcapReader.DATA:
                ll(self.name, 'data',
                        hexDump(self.buf[PcapReader.HLEN:self.nextLen]))
                packet = self.buf[:self.nextLen]
                self.buf = self.buf[self.nextLen:]
                self.nextLen = PcapReader.HLEN
                self.state = PcapReader.HEADER
                break

            if self.state == PcapReader.HEADER:
                ll(self.name, 'header', hexDump(self.buf[:self.nextLen]))
                self.nextLen += struct.unpack('I', self.buf[8:12])[0]
                self.state = PcapReader.DATA
                continue

            error("%s invalid state %d" % (self.name, self.state))

        return packet

            
class TunReader(RawReader):
    '''Emulate reading and writing PCAP format packets with a tun/tap device'''
    def fileno(self):
        return self.fileObj

    def readPacket(self):
        rl, wl, xl = select([self], [], [], 0)
        if not len(rl):
            return None
        buf = os.read(self.fileObj, RawReader.MAX_FRAME)
        head = '\0' * 8
        head += struct.pack('I', len(buf))
        head += struct.pack('I', len(buf))
        return head + buf


class TunWriter(RawWriter):
    def writePacket(self, packet):
        os.write(self.fileObj, packet[PcapReader.HLEN:])


class Iface(object):
    '''Implement an interface with a PCAP packet reader and writer
    
    An optional cache is used for the tcpdump reader and tcpreplay writer,
    where a replayed packet is immediately read by tcpdump and needs to be
    ignored
    '''
    def __init__(self, name, reader, writer, withCache=False):
        self.name = name
        self.reader = reader
        self.writer = writer
        self.cache = Cache() if withCache else None

    def fileno(self):
        return self.reader.fileno()

    def readPacket(self):
        packet = self.reader.readPacket()
        if not packet:
            return None
        if not self.cache:
            return packet
        data = packet[PcapReader.HLEN:]
        if isLocal(data):
            ll(self.name, 'ignoring a "local" packet...')
            return ''
        if data in self.cache:
            ll(self.name, 'ignoring...')
            self.cache.remove(data)
            return ''
        ll(self.name, 'forwarding...')
        return packet

    def writePacket(self, packet):
        self.writer.writePacket(packet)
        if self.cache:
            self.cache.add(packet[PcapReader.HLEN:])
        
        
class Bridge(object):
    '''Implement a repeater that forwards packet in PCAP format

    Hold 2 Iface instances each connected to a source/sink of packet data
    '''
    def __init__(self, name, i1, i2):
        self.name = name
        self.fds = set([])
        self.i1 = i1
        self.i2 = i2
        self.fds.add(self.i1)
        self.fds.add(self.i2)

    def process(self):
        '''Repeately read and write pending packets from the interfaces'''
        packet1 = ''
        packet2 = ''
        while not (packet1 is None and packet2 is None):
            if not packet1 is None:
                packet1 = self.i1.readPacket()
                if packet1:
                    self.i2.writePacket(packet1)
            if not packet2 is None:
                packet2 = self.i2.readPacket()
                if packet2:
                    self.i1.writePacket(packet2)

    @staticmethod
    def processAll(bridges, waitForStdin=False):
        '''Reapeately iterate over a list of bridges

        Optionally, abort on any input on stdin
        '''
        rl = list(set.union(*[br.fds for br in bridges]))
        if waitForStdin:
            rl.append(sys.stdin)
        rl, wl, xl = select(rl, [], [])
        if sys.stdin in rl:
            error('we are asked to stop...')
        for br in bridges:
            if len(br.fds & set(rl)):
                br.process()


def cap2replay(argv):
    if len(argv) != 1:
        usage()
    addToLocal('fw1')
    fw1replay = tcpreplay('fw1')
    fw1dump = tcpdump('fw1')
    fw1replay.write(fw1dump.read(24))
    log('pids %s\n' % ' '.join([str(p.pid) for p in procs]))

    def mkBridge(name, dump, replay, addr):
        sock = Socket(addr)
        return Bridge(name,
                Iface(name, PcapReader(name, RawReader(dump)),
                        RawWriter(replay), True),
                Iface(name, PcapReader(name, SockReader(sock)),
                        SockWriter(sock)))
    bridge = mkBridge('fw1:', fw1dump, fw1replay, argv[0])
    while all(p.poll() is None for p in procs):
        Bridge.processAll([bridge])

def mkTun(br):
    if not os.path.exists('/dev/net/tun'):
        subprocess.check_call(['modprobe', 'tun'])
        # wait for the device
        for i in xrange(30):
            time.sleep(.1)
            if os.path.exists('/dev/net/tun'):
                break
    tap = os.open("/dev/net/tun", os.O_RDWR)
    TUNSETIFF = 0x400454ca
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000
    result = fcntl.ioctl(tap, TUNSETIFF,
            struct.pack("16sH", 16 * '\0', IFF_TAP|IFF_NO_PI))
    name = result[:16].strip('\0')
    subprocess.check_call(['ifconfig', name, 'up'])
    subprocess.check_call(['brctl', 'addif', br, name])
    subprocess.check_call(['brctl', 'hairpin', br, name, 'on'])
    ll(tap, name)
    return tap, name

def cap2tap(argv):
    if len(argv) != 1:
        usage()
    br = None
    for i in xrange(1, 10):
        br = 'br%d' % i
        if subprocess.call(['brctl', 'addbr', br]):
            continue
        subprocess.check_call(['ifconfig', br, 'up'])
        brs.append(br)
        break
    else:
        error('could not allocate a bridge')
    def mkBridge(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', int(port, 10)))
        sock.listen(1)
        serverSock = Socket(sock)
        tap, name = mkTun(br)
        name += ':'
        return Bridge(name,
                Iface(name, PcapReader(name, SockReader(serverSock)),
                        SockWriter(serverSock)),
                Iface(name, TunReader(tap), TunWriter(tap)))
    bridge = mkBridge(argv[0])
    mkTun(br) # add dummy tap to make the br bridge work
    subprocess.check_call(['brctl', 'showifs', br])
    while all(p.poll() is None for p in procs):
        Bridge.processAll([bridge], True)

def call(args):
    safeLog(' '.join(args) + '\n')
    return subprocess.call(args)

def cleanup():
    safeLog('cleaning up...\n')
    for br in brs:
        call(['ifconfig', br, 'down'])
        call(['brctl', 'delbr', br])
    safeLog('pids %s\n' % ' '.join([str(p.pid) for p in procs]))
    for p in procs:
        rc = p.poll()
        if rc is None:
            if call(['kill', str(p.pid)]):
                safeLog('failed to kill %s\n' % p.pid)
        else:
            safeLog('pid %s exited with status %s\n' % (p.pid, rc))

def usage():
    log("""
Usage:
    %s replay GATEWAY:PORT
or
    %s tap PORT
""")
    sys.exit(1)

if __name__ == '__main__':
    def sigHandler(signum, frame):
        error('caught signal %d' % signum)
    for sig in [signal.SIGHUP, signal.SIGINT, signal.SIGQUIT,
            signal.SIGPIPE, signal.SIGTERM]:
        signal.signal(signal.SIGTERM, sigHandler)
    try:
        if len(sys.argv) < 2 or sys.argv[1] == '-h':
            usage()
        handler = {'tap': cap2tap, 'replay': cap2replay}.get(
                sys.argv[1], None)
        if handler is None:
            usage()
        handler(sys.argv[2:])
    finally:
        cleanup()

