#!/usr/bin/env python3

# Copyright (C) 2019 Hewlett Packard Enterprise Development LP.
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
from pdb import post_mortem
import time
import wildcat
from wildcat import MR, UU
from wildcat import zuuid, XDMcompletionError
from tests import Tests

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

def runtime_err(*arg):
    raise RuntimeError(*arg)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--devfile', default='/dev/wildcat',
                        help='the wildcat character device file')
    parser.add_argument('-k', '--keyboard', action='store_true',
                        help='invoke interactive keyboard')
    parser.add_argument('-P', '--post_mortem', action='store_true',
                        help='enter debugger on uncaught exception')
    parser.add_argument('-v', '--verbosity', action='count', default=0,
                        help='increase output verbosity')
    return parser.parse_args()

def main():
    global args
    args = parse_args()
    if args.verbosity:
        print('pid={}'.format(os.getpid()))
    modp = ModuleParams()
    with open(args.devfile, 'rb+', buffering=0) as f:
        conn = wildcat.Connection(f, args.verbosity)
        init = conn.do_INIT()
        gcid = init.uuid.gcid
        if args.verbosity:
            print('do_INIT: uuid={}, gcid={}'.format(
                init.uuid, init.uuid.gcid_str))
        zuu = zuuid(gcid=gcid)
        conn.do_UUID_IMPORT(zuu, 0, None)

        sz4K = 4096

        mm = mmap.mmap(-1, sz4K)
        v, l = wildcat.mmap_vaddr_len(mm)
        rsp = conn.do_MR_REG(v, l, MR.GPGRPRI)  # req: GET/PUT/GETREM/PUTREM, 4K
        rsp_rmr = conn.do_RMR_IMPORT(zuu, rsp.rsp_zaddr, sz4K, MR.GPGRPRIC)
        rmm = mmap.mmap(f.fileno(), sz4K, offset=rsp_rmr.offset)
        v_rmm, l_rmm = wildcat.mmap_vaddr_len(rmm)

        str1 = b'12345678'
        len1 = len(str1)
        off1 = 0x9A0
        str2 = b'abcdefgh'
        len2 = len(str2)
        off2 = off1 + len2
        len1_2 = len1 + len2

        mm[off1:off1+len1] = str1
        if args.verbosity:
            print('mm (initial)="{}"'.format(mm[off1:off1+len1]))
        if args.keyboard:
            set_trace()
        # invalidate rmm to read fresh data
        wildcat.invalidate(v_rmm+off1, len1, True)
        if args.verbosity:
            print('rmm (remote)="{}"'.format(rmm[off1:off1+len1]))
        if mm[off1:off1+len1] != rmm[off1:off1+len1]:
            runtime_err('Error: mm "{}" != rmm "{}"'.format(
                mm[off1:off1+len1], rmm[off1:off1+len1]))
        rmm[off2:off2+len2] = str2
        # commit rmm writes, so mm reads will see new data
        wildcat.commit(v_rmm+off2, len2, True)
        # invalidate mm reads to see new data.
        wildcat.invalidate(v+off1, len1_2, True)
        if args.verbosity:
            print('mm after remote update="{}"'.format(
                mm[off1:off1+len1_2]))
        if mm[off1:off1+len1_2] != rmm[off1:off1+len1_2]:
            runtime_err('Error: mm "{}" != rmm "{}"'.format(
                mm[off1:off1+len1_2], rmm[off1:off1+len1_2]))

        rmm.close()
        conn.do_RMR_FREE(zuu, rsp.rsp_zaddr, sz4K, MR.GPGRPRIC,
                         rsp_rmr.req_addr)
        conn.do_MR_FREE(v, l, MR.GPGRPRI, rsp.rsp_zaddr)
        mm.close()
        f.close()
    # end with

if __name__ == '__main__':
    try:
        main()
    except Exception as post_err:
        if args.post_mortem:
            post_mortem()
        else:
            raise
