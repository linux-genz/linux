#!/usr/bin/env python3

# Copyright (C) 2018-2019 Hewlett Packard Enterprise Development LP.
# All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2, available from the file
# COPYING in the main directory of this source tree, or the
# BSD license below:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials provided
#     with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import json
import sys
import mmap
import subprocess
from wildcat import zuuid, MR, UU
from tests import Tests
from time import time
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ServerEndpoint, TCP4ClientEndpoint
from twisted.internet.endpoints import connectProtocol
from twisted.internet.error import CannotListenError
from twisted.internet.protocol import Protocol, Factory
from twisted.internet.task import LoopingCall
from twisted.python import log

PING_INTERVAL = 60

# Magic to get JSONEncoder to call to_json method, if it exists
def _default(self, obj):
    return getattr(obj.__class__, 'to_json', _default.default)(obj)

_default.default = json.JSONEncoder().default
json.JSONEncoder.default = _default

def gotProtocol(p):
    '''The callback to start the protocol exchange. We let connecting
    nodes in state 'SENDHELLO' start the hello handshake'''
    if p.state == 'SENDHELLO':
        p.send_hello()

class MyProtocol(Protocol):
    def __init__(self, factory, state, kind):
        self.factory = factory
        self.state = state
        self.kind = kind
        self.remote_nodeid = None
        self.nodeid = self.factory.nodeid
        self.lc_ping = LoopingCall(self.send_ping)
        self.lastping = time()
        self.pagesize = int(subprocess.check_output('getconf PAGESIZE',
                                                    shell=True))

    def write(self, line):
        self.transport.write(bytes(line + '\n', 'utf-8'))

    def connectionMade(self):
        remote_ip = self.transport.getPeer()
        host_ip = self.transport.getHost()
        self.remote_ip = remote_ip.host + ':' + str(remote_ip.port)
        self.host_ip = host_ip.host + ':' + str(host_ip.port)
        print('Connection with', self.transport.getPeer())

    def connectionLost(self, reason):
        if self.remote_nodeid in self.factory.peers:
            self.factory.peers.pop(self.remote_nodeid)
            if self.lc_ping.running:
                self.lc_ping.stop()
            try:
                self.factory.conn.do_UUID_FREE(self.remote_nodeid)
            except OSError:
                pass
        remote = self.remote_nodeid if self.remote_nodeid else self.remote_ip
        print('{} disconnected from {}'.format(self.nodeid, remote))

    def dataReceived(self, data):
        #print('dataReceived: type(data)={}, data={}'.format(type(data), data))
        data_str = data.decode('utf-8')
        for line in data_str.splitlines():
            line = line.strip()
            jlds = json.loads(line)
            msgtype = jlds['msgtype']
            if self.state in ['GETHELLO', 'SENTHELLO'] and msgtype == 'hello':
                self.handle_hello(line)
            elif msgtype == 'ping':
                self.handle_ping(line)
            elif msgtype == 'pong':
                self.handle_pong(line)
            elif msgtype == 'addr':
                self.handle_addr(line)
            elif msgtype == 'getaddr':
                self.handle_getaddr(line)
            elif msgtype == 'mrregs':
                self.handle_mrregs(jlds['mr'])
            else:
                print('Got unexpected msgtype {}'.format(msgtype))

    def send_hello(self):
        hello = json.dumps({'nodeid': str(self.nodeid), 'msgtype': 'hello'})
        remote = self.remote_nodeid if self.remote_nodeid else self.remote_ip
        print('{} sending hello to {}'.format(self.nodeid, remote))
        self.write(hello)
        self.state = 'SENTHELLO'

    def send_ping(self):
        ping = json.dumps({'msgtype': 'ping'})
        print('Pinging', self.remote_nodeid)
        self.write(ping)

    def send_pong(self):
        pong = json.dumps({'msgtype': 'pong'})
        print('Ponging', self.remote_nodeid)
        self.write(pong)

    def send_addr(self, mine=False):
        now = time()
        if mine:
            peers = [(self.host_ip, str(self.nodeid))]
            print('{} sending my addr to {}'.format(self.nodeid,
                                                    self.remote_nodeid))
        else:
            peers = [(peer.remote_ip, str(peer.remote_nodeid))
                     for peer in self.factory.peers.values()
                     if peer.kind == 'TO' and peer.lastping > now-240]
            print('{} sending my peers {} to {}'.format(self.nodeid, peers,
                                                        self.remote_nodeid))
        addr = json.dumps({'msgtype': 'addr', 'peers': peers})
        self.write(addr)

    def send_getaddr(self):
        getaddr = json.dumps({'msgtype': 'getaddr'})
        print('Sending getaddr to', self.remote_nodeid)
        self.write(getaddr)

    def send_mrregs(self):
        mr = [v for v in self.factory.conn.mrreg.values()]
        mrregs = json.dumps({'msgtype': 'mrregs', 'mr': mr})
        print('Sending MR_REG info to', self.remote_nodeid)
        self.write(mrregs)

    def handle_ping(self, ping):
        print('Got ping from', self.remote_nodeid)
        self.send_pong()

    def handle_pong(self, pong):
        print('Got pong from', self.remote_nodeid)
        ###Update the timestamp
        self.lastping = time()

    def handle_addr(self, addr):
        addr = json.loads(addr)
        for remote_ip, remote_nodeid_str in addr['peers']:
            remote_nodeid = zuuid(remote_nodeid_str)
            if (remote_nodeid not in self.factory.peers and
                remote_nodeid != self.nodeid):
                print('Connecting to new peer {}'.format(remote_nodeid_str))
                host, port = remote_ip.split(':')
                point = TCP4ClientEndpoint(reactor, host, int(port))
                d = connectProtocol(point, MyProtocol(self.factory,
                                                      'SENDHELLO', 'TO'))
                d.addCallback(gotProtocol)

    def handle_getaddr(self, getaddr):
        self.send_addr()

    def handle_hello(self, hello):
        hello = json.loads(hello)
        self.remote_nodeid = zuuid(hello['nodeid'])
        if self.remote_nodeid == self.nodeid:
            print('Ignoring connection to myself.')
            self.transport.loseConnection()
        elif self.remote_nodeid.gcid == self.nodeid.gcid:
            print('Configuration error - local and remote nodes have the same GCID ({})'.format(self.nodeid.gcid_str))
            self.transport.loseConnection()
        else:
            if self.state == 'GETHELLO':
                self.send_hello()
            else:
                print('Starting ping to {}'.format(self.remote_nodeid))
                self.lc_ping.start(PING_INTERVAL)
            self.state = 'READY'
            self.factory.peers[self.remote_nodeid] = self
            # Revisit: temporary UU.IS_FAM
            self.factory.conn.do_UUID_IMPORT(self.remote_nodeid, UU.IS_FAM, None)
            if self.factory.responder:
                self.send_mrregs()
            ###inform our new peer about us
            self.send_addr(mine=True)
            ###and ask them for more peers
            self.send_getaddr()

    def handle_mrregs(self, mr):
        if not self.factory.requester:
            if self.factory.verbosity:
                print('Ignoring mrregs - not requester')
            return
        for v in mr:
            req = v[0]
            if req['__class__'] != 'req_MR_REG':
                print('Error: expected req_MR_REG, got {}'.format(
                    req['__class__']))
                continue
            access = req['__value__']['access']
            sz = req['__value__']['len']
            rsp = v[1]
            if rsp['__class__'] != 'rsp_MR_REG':
                print('Error: expected rsp_MR_REG, got {}'.format(
                    rsp['__class__']))
                continue
            rsp_zaddr = rsp['__value__']['rsp_zaddr']
            # Revisit: support non-INDIVIDUAL regions
            put_get_remote = MR.PUT_REMOTE|MR.GET_REMOTE|MR.INDIVIDUAL
            test_remote = ((access & put_get_remote) == put_get_remote)
            if self.factory.load_store:
                access |= MR.REQ_CPU
            if self.factory.verbosity:
                print('mr: rsp_zaddr={:#x}, sz={:#x}, access={:#x}'.format(
                    rsp_zaddr, sz, access))
            
            if test_remote:
                conn = self.factory.conn
                rmr = conn.do_RMR_IMPORT(self.remote_nodeid,
                                         rsp_zaddr, sz, access)
                mask = (-self.pagesize) & ((1 << 64) - 1)
                mmsz = (sz + (self.pagesize - 1)) & mask
                if self.factory.load_store:
                    if self.factory.verbosity:
                        print('mr mmap: mmsz={}, offset={:#x}'.format(
                            mmsz, rmr.offset))
                    rmm = mmap.mmap(conn.fno, mmsz, offset=rmr.offset)
                else:
                    rmm = None
                t = Tests(self.factory.lmr, self.factory.lmm, rmr, sz, rmm,
                          self.factory.xdm, self.factory.verbosity,
                          self.factory.load_store, self.pagesize)
                t.all_tests()
                conn.do_RMR_FREE(self.remote_nodeid, rsp_zaddr, sz, access,
                                 rmr.req_addr)
            else:
                print('skipping tests because mr lacks remote put/get access')
        # end for v
        if self.factory.net_exit:
            reactor.stop()

class MyFactory(Factory):
    def __init__(self, conn, lmr, lmm, xdm, verbosity, load_store,
                 requester, responder, net_exit):
        self.conn = conn
        self.lmr = lmr
        self.lmm = lmm
        self.xdm = xdm
        self.verbosity = verbosity
        self.load_store = load_store
        self.requester = requester
        self.responder = responder
        self.net_exit = net_exit
        self.nodeid = conn.init.uuid
        super().__init__()

    def startFactory(self):
        self.peers = {}

    def buildProtocol(self, addr):
        return MyProtocol(self, 'GETHELLO', 'FROM')

    def setup(self, port, nodes):
        #log.startLogging(sys.stdout)  # Revisit: twisted debug
        endpoint = TCP4ServerEndpoint(reactor, port)
        endpoint.listen(self)

        for node in nodes:
            point = TCP4ClientEndpoint(reactor, node, port)
            d = connectProtocol(point,
                                MyProtocol(self, 'SENDHELLO', 'TO'))
            d.addCallback(gotProtocol)

