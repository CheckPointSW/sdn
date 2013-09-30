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

import inspect
import json
import mininet
import os

dirname = os.path.dirname(
        os.path.abspath(inspect.getfile(inspect.currentframe())))

class FW(mininet.topo.Topo):
    def __init__(self):
        mininet.topo.Topo.__init__(self)
        with open(os.path.join(dirname, 'topo.json')) as topoFile:
            topo = json.load(topoFile)
        nodes = {}
        for switch in topo['switches']:
            switch = str(switch)
            nodes[switch] = self.addSwitch(switch)
        def getNode(name):
            name = str(name)
            if not name in nodes:
                nodes[name] = self.addHost(name)
            return nodes[name]
        for link in topo['links']:
            self.addLink(getNode(link[0]), getNode(link[2]), link[1], link[3])

class POX(mininet.node.Controller):
    def __init__(self, name,
            command=os.environ['HOME'] + '/pox/pox.py',
            cargs='fw --home=%s' % dirname):
        mininet.node.Controller.__init__(self, name,
                command=command, cargs=cargs)

    def start(self):
        mininet.moduledeps.pathCheck(self.command)
        cout = '/tmp/pox-' + self.name + '.log'
        if self.cdir is not None:
            self.cmd('cd ' + self.cdir)
        self.cmd(self.command, self.cargs, '>', cout, '2>&1', '&')
        self.poxPid = self.cmd('echo $!').strip()
        self.execed = False

    def stop(self):
        print self.cmd('kill ' + self.poxPid)
        self.terminate()

topos = {'fw': FW}
controllers = {'pox': POX}
