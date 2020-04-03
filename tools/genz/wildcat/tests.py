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

import wildcat
from wildcat import XDMcompletionError
import hashlib
from ctypes import *
import time

class Tests():
    str1 = b'J/B/S '
    str2 = b'making Gen-Z awesome!'
    str3 = b'PF Slice is awesome too!'
    len1 = len(str1)
    len2 = len(str2)
    len3 = len(str3)
    len1_2 = len1 + len2
    sz1G = 1<<30

    sync = wildcat.xdm_cmd()
    sync.opcode = wildcat.XDM_CMD.SYNC|wildcat.XDM_CMD.FENCE

    def __init__(self, lmr, lmm, rmr, rmr_sz, rmm, xdm, verbosity=0,
                 load_store=True, pagesize=4096):
        self.lmr = lmr
        self.lmm = lmm
        self.rmr = rmr
        self.rmm = rmm
        self.xdm = xdm
        self.verbosity = verbosity
        self.load_store = load_store
        self.lmm_v, self.lmm_l = wildcat.mmap_vaddr_len(lmm)
        self.maxsz = min(self.lmm_l, rmr_sz)
        if rmm is not None:
            self.rmm_v, self.rmm_l = wildcat.mmap_vaddr_len(rmm)
        self.pagesize = pagesize
        mask = (-self.pagesize) & ((1 << 64) - 1)
        self.pg_off = rmr.req_addr & ~mask

    def test_load_store(self, offset=0):
        if self.rmm is None:
            if self.verbosity:
                print('test_load_store: skipping - no load/store rmm')
            return
        # Revisit: this assumes rmm is mapped writable
        rmm_off = self.pg_off + offset
        if self.verbosity:
            print('test_load_store: offset={}, rmm_off={}, rmm_v={:#x}'
                  .format(offset, rmm_off, self.rmm_v))
        self.rmm[rmm_off:rmm_off+Tests.len1] = Tests.str1
        self.rmm[rmm_off+Tests.len1:rmm_off+Tests.len1_2] = Tests.str2
        # invalidate rmm writes, so rmm reads will generate new Gen-Z packets
        wildcat.invalidate(self.rmm_v+rmm_off, Tests.len1_2, True)
        expected = Tests.str1 + Tests.str2
        if self.verbosity:
            print('rmm[{}:{}] after load/store="{}"'.format(
                rmm_off, rmm_off+Tests.len1_2,
                self.rmm[rmm_off:rmm_off+Tests.len1_2].decode()))
        if self.rmm[rmm_off:rmm_off+Tests.len1_2] != expected:
            raise IOError
        # invalidate rmm after reads, so cache is empty for next test
        wildcat.invalidate(self.rmm_v+rmm_off, Tests.len1_2, True)

    def test_PUT_IMM(self, data=str3, offset=len1_2+64):
        sz = len(data)
        if sz < 1 or sz > 32:
            raise ValueError
        rem_addr = self.rmr.req_addr + offset
        put_imm = wildcat.xdm_cmd()
        put_imm.opcode = wildcat.XDM_CMD.PUT_IMM
        put_imm.getput_imm.size = sz
        put_imm.getput_imm.rem_addr = rem_addr
        put_imm.getput_imm.payload[0:sz] = data
        if self.verbosity:
            print('test_PUT_IMM: data={}, sz={}, offset={}, rem_addr={:#x}'
                  .format(data, sz, offset, rem_addr))
        self.xdm.queue_cmd(put_imm)
        try:
            cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('PUT_IMM cmpl: {}'.format(cmpl))
        except XDMcompletionError as e:
            print('PUT_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        # Revisit: need fence/sync to ensure visibility?
        if self.rmm is not None:
            rmm_off = self.pg_off + offset
            if self.verbosity:
                print('rmm[{}:{}] after PUT_IMM="{}"'.format(
                    rmm_off, rmm_off+sz, self.rmm[rmm_off:rmm_off+sz].decode()))
            if self.rmm[rmm_off:rmm_off+sz] != data:
                raise IOError
            # invalidate rmm after reads, so cache is empty for next test
            wildcat.invalidate(self.rmm_v+rmm_off, sz, True)

    def test_GET_IMM(self, offset=0, sz=len1_2):
        if sz < 1 or sz > 32:
            raise ValueError
        rem_addr = self.rmr.req_addr + offset
        get_imm = wildcat.xdm_cmd()
        get_imm.opcode = wildcat.XDM_CMD.GET_IMM
        get_imm.getput_imm.size = sz
        get_imm.getput_imm.rem_addr = rem_addr
        if self.verbosity:
            print('test_GET_IMM: sz={}, offset={}, rem_addr={:#x}'
                  .format(sz, offset, rem_addr))
        self.xdm.queue_cmd(get_imm)
        try:
            cmpl = self.xdm.get_cmpl()
            if self.verbosity:
                print('GET_IMM cmpl: {}'.format(cmpl.getimm))
        except XDMcompletionError as e:
            print('GET_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        if self.rmm is not None:
            rmm_off = self.pg_off + offset
            if bytes(cmpl.getimm.payload[0:sz]) != self.rmm[rmm_off:rmm_off+sz]:
                raise IOError
            # Revisit: check that payload bytes beyond sz are 0
            # invalidate rmm after reads, so cache is empty for next test
            wildcat.invalidate(self.rmm_v+rmm_off, sz, True)

    def test_PUT(self, loc_offset=0, rem_offset=0, sz=None):
        if sz is None:
            sz = self.maxsz // 2
        local_addr = self.lmm_v
        local_addr += loc_offset
        rem_addr = self.rmr.req_addr + rem_offset
        put = wildcat.xdm_cmd()
        put.opcode = wildcat.XDM_CMD.PUT|wildcat.XDM_CMD.FENCE
        put.getput.size = sz
        put.getput.read_addr = local_addr
        put.getput.write_addr = rem_addr
        if self.verbosity:
            print('test_PUT: local_addr={:#x}, sz={}, rem_addr={:#x}'
                  .format(local_addr, sz, rem_addr))
        if self.rmm is not None:
            rmm_off = self.pg_off + rem_offset
            # invalidate rmm before PUT, so cache is empty for later reads
            wildcat.invalidate(self.rmm_v+rmm_off, sz, True)
        start = time.monotonic()
        self.xdm.queue_cmd(put)
        try:
            cmpl = self.xdm.get_cmpl()
            end = time.monotonic()
            if self.verbosity:
                print('PUT cmpl: {}'.format(cmpl))
        except XDMcompletionError as e:
            print('PUT cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        # Revisit: need fence/sync/flush to ensure visibility?
        lmm_sha256 = hashlib.sha256(
            self.lmm[loc_offset:loc_offset+sz]).hexdigest()
        if self.verbosity:
            print('lmm sha256="{}"'.format(lmm_sha256))
        if self.rmm is not None:
            rmm_sha256 = hashlib.sha256(
                self.rmm[rmm_off:rmm_off+sz]).hexdigest()
            if self.verbosity:
                print('rmm[{}:{}] sha256 after PUT="{}"'.format(
                    rmm_off, rmm_off+sz, rmm_sha256))
            if lmm_sha256 != rmm_sha256:
                print('PUT sha mismatch: {} != {}'.format(
                    lmm_sha256, rmm_sha256))
                # Revisit: temporary debug
                print('lmm[{}:{}]="{}"'.format(
                    loc_offset, loc_offset+100,
                    self.lmm[loc_offset:loc_offset+100]))
                print('rmm[{}:{}]="{}"'.format(
                    rmm_off, rmm_off+100,
                    self.rmm[rmm_off:rmm_off+100]))
            if lmm_sha256 != rmm_sha256:
                raise IOError
            # invalidate rmm after reads, so cache is empty for next test
            wildcat.invalidate(self.rmm_v+rmm_off, sz, True)
        # end if self.rmm
        secs = end - start
        if self.verbosity:
            print('PUT of {} bytes in {} seconds = {} GiB/s'.format(
                put.getput.size, secs, put.getput.size / (secs * self.sz1G)))

    def test_GET(self, loc_offset=0, rem_offset=0, sz=None):
        if sz is None:
            sz = self.maxsz // 2
        local_addr = self.lmm_v
        local_addr += loc_offset
        rem_addr = self.rmr.req_addr + rem_offset
        get = wildcat.xdm_cmd()
        get.opcode = wildcat.XDM_CMD.GET|wildcat.XDM_CMD.FENCE
        get.getput.size = sz
        get.getput.read_addr = rem_addr
        get.getput.write_addr = local_addr
        if self.verbosity:
            print('test_GET: local_addr={:#x}, sz={}, rem_addr={:#x}'
                  .format(local_addr, sz, rem_addr))
        start = time.monotonic()
        self.xdm.queue_cmd(get)
        try:
            cmpl = self.xdm.get_cmpl()
            end = time.monotonic()
            if self.verbosity:
                print('GET cmpl: {}'.format(cmpl))
        except XDMcompletionError as e:
            print('GET cmpl error: {} {:#x} request_id {:#x}'.format(
                e, e.status, e.request_id))
        # Revisit: need fence/sync/flush to ensure visibility?
        if self.rmm is not None:
            rmm_off = self.pg_off + rem_offset
            lmm_sha256 = hashlib.sha256(
                self.lmm[loc_offset:loc_offset+sz]).hexdigest()
            if self.verbosity:
                print('lmm sha256 after GET="{}"'.format(lmm_sha256))
                rmm_sha256 = hashlib.sha256(
                    self.rmm[rmm_off:rmm_off+sz]).hexdigest()
            if self.verbosity:
                print('rmm[{}:{}] sha256="{}"'.format(
                    rmm_off, rmm_off+sz, rmm_sha256))
            if lmm_sha256 != rmm_sha256:
                print('GET sha mismatch: {} != {}'.format(
                    lmm_sha256, rmm_sha256))
                # Revisit: temporary debug
                print('lmm[{}:{}]="{}"'.format(
                    loc_offset, loc_offset+100,
                    self.lmm[loc_offset:loc_offset+100]))
                print('rmm[{}:{}]="{}"'.format(
                    rmm_off, rmm_off+100,
                    self.rmm[rmm_off:rmm_off+100]))
            if lmm_sha256 != rmm_sha256:
                raise IOError
            # invalidate rmm after reads, so cache is empty for next test
            wildcat.invalidate(self.rmm_v+rmm_off, sz, True)
        # end if self.rmm
        secs = end - start
        if self.verbosity:
            print('GET of {} bytes in {} seconds = {} GiB/s'.format(
                get.getput.size, secs, get.getput.size / (secs * self.sz1G)))

    def all_tests(self):
        for off in range(0, 64, 7):
            self.test_load_store(offset=off)
        self.test_PUT_IMM()
        self.test_GET_IMM()
        self.test_PUT()
        self.test_GET()
