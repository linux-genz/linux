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

import contextlib
import mmap
import argparse
import os
import hashlib
from ctypes import *
from pdb import set_trace
import time
import wildcat
from wildcat import MR, UU, zuuid
import signal

class ModuleParams():
    def __init__(self, mod='wildcat'):
        self.mod = mod
        self._path = '/sys/module/' + mod + '/parameters/'
        self._files = os.listdir(self._path)
        self.params = {}
        for f in self._files:
            with open(self._path + f, 'r') as fp:
                val = fp.read().rstrip()
                try:
                    self.params[f] = int(val)
                except ValueError:
                    self.params[f] = val
        self.__dict__.update(self.params)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--devfile', default='/dev/wildcat-rdma',
                        help='the wildcat-rdma character device file')
    parser.add_argument('-H', '--hugefile', default='/dev/hugepages/test2',
                        help='a 1G hugepage test file')
    parser.add_argument('-l', '--loopback', action='store_true',
                        help='enable loopback mode')
    parser.add_argument('-A', '--anonymous', action='store_true',
                        help='use an anonymous mmap instead of hugefile')
    parser.add_argument('-S', '--size', default='1', type=int,
                        help='set the anonymous mmap size')
    parser.add_argument('-k', '--keyboard', action='store_true',
                        help='invoke interactive keyboard')
    parser.add_argument('-v', '--verbosity', action='count', default=0,
                        help='increase output verbosity')
    return parser.parse_args()

def main():
    '''summary of MR_REG regions:
    name       | access   | args     | mmap  | v         | sz    |
    -----------+----------+----------+-------+-----------+-------+
    rsp1G      |GRPRIC    |always    | mm1G  | v1G       | sz*1G |
    '''
    global args
    args = parse_args()
    if args.verbosity:
        print('pid={}'.format(os.getpid()))
    gz_modp = ModuleParams('genz')
    wc_modp = ModuleParams('wildcat')
    with open(args.devfile, 'rb+', buffering=0) as f:
        conn = wildcat.Connection(f, args.verbosity)
        init = conn.do_INIT()
        gcid = init.uuid.gcid
        print('do_INIT: uuid={}, gcid={}'.format(init.uuid, init.uuid.gcid_str))

        if args.loopback and wc_modp.wildcat_loopback == 0:
            print('Configuration error - loopback requested but driver has wildcat_loopback=0')

        if args.loopback and wc_modp.wildcat_loopback:
            zuu = zuuid(gcid=gcid)
            #conn.do_UUID_IMPORT(zuu, 0, None)
            conn.do_UUID_IMPORT(zuu, UU.IS_FAM, None) # Revisit: debug

        sz = sz1G = 1<<30

        if args.anonymous:
            if args.size:
                sz = sz1G * args.size
            if args.verbosity:
                print('mmapping anonymous region, sz={}'.format(sz))
            mm1G = mmap.mmap(-1, sz, access=mmap.ACCESS_WRITE)
        else:
            sz = os.path.getsize(args.hugefile)
            if args.verbosity:
                print('opening hugefile "{}", sz={}'.format(args.hugefile, sz))
            f1G = open(args.hugefile, 'rb+')
            if args.verbosity:
                print('mmapping hugefile')
            mm1G = mmap.mmap(f1G.fileno(), 0, access=mmap.ACCESS_WRITE)
        #print('initializing hugefile with random data')
        #mm1G[0:sz//2] = os.urandom(sz//2)
        v1G, l1G = wildcat.mmap_vaddr_len(mm1G)

        # individual, cpu-visible, 1G mapping allowing
        # GET_REMOTE/PUT_REMOTE
        #rsp1G = conn.do_MR_REG(v1G, sz, MR.GRPRIC) # huge: REMOTE, szG
        # Revisit: non-cpu-visible for now
        rsp1G = conn.do_MR_REG(v1G, sz, MR.GRPRI) # huge: REMOTE, szG
        print('do_MR_REG: rsp_zaddr={:#x}, len={}'.format(
            rsp1G.rsp_zaddr, sz))
        print('user_send3 --blk --uuid {} --gcid {} --start {:#x} --length {:#x}'.format(
            init.uuid, init.uuid.gcid_str, rsp1G.rsp_zaddr, sz))
        if args.keyboard:
            set_trace()
        try:
            signal.pause()
        except KeyboardInterrupt:
            if args.verbosity:
                print('\nexiting on keyboard interrupt')
        conn.do_MR_FREE(v1G, l1G, MR.GRPRI, rsp1G.rsp_zaddr)
        conn.do_UUID_FREE(init.uuid)
    # end with

if __name__ == '__main__':
    main()
