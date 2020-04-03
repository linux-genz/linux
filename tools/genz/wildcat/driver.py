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

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--devfile', default='/dev/wildcat-rdma',
                        help='the wildcat-rdma character device file')
    parser.add_argument('-b', '--bigfile', default='/dev/hugepages/test1',
                        help='a hugepage test file')
    parser.add_argument('-H', '--hugefile', default='/dev/hugepages/test2',
                        help='a huger hugepage test file')
    parser.add_argument('--huge', action='store_true',
                        help='enable huge PUT test')
    parser.add_argument('-D', '--datafile', default='./driver.py',
                        help='a data test file')
    parser.add_argument('-N', '--net', action='store_true',
                        help='make/accept network connections')
    parser.add_argument('-n', '--nodes', type=str, default=None,
                        help='list of remote node IPs')
    parser.add_argument('-p', '--port', type=int, default=42042,
                        help='network port')
    parser.add_argument('-q', '--requester', action='store_true',
                        help='enable requester')
    parser.add_argument('-r', '--responder', action='store_true',
                        help='enable responder')
    parser.add_argument('-l', '--loopback', action='store_true',
                        help='enable loopback mode')
    parser.add_argument('-k', '--keyboard', action='store_true',
                        help='invoke interactive keyboard')
    parser.add_argument('-v', '--verbosity', action='count', default=0,
                        help='increase output verbosity')
    parser.add_argument('-f', '--fam', action='store_true',
                        help='test FAM at GCID 0x40')
    parser.add_argument('-L', '--load_store', action='store_false',
                        default=True, help='disable load/store tests')
    parser.add_argument('-X', '--exit', action='store_true',
                        help='exit immediately after network requester tests')
    return parser.parse_args()

def main():
    '''summary of MR_REG regions:
    name       | access   | args     | mmap  | v         | sz  |
    -----------+----------+----------+-------+-----------+-----+
    rsp        |GPI       |requester | mm    | v         | 4K
    rsp2       |GRPRI     |responder | mm2   | v2        | 4K
    rsp2M      |GRPRI     |always    | mm2M  | v2M+0x1242| 2M-0x5000
    rsp2M_l    |GP        |always    | mm2M  | v2M       | 2M
    rsp2M_b    |GRPRI     |responder | mm2M  | v2M       | 2M
    rsp2M_r    |GPGRPRI   |loopback  | mm2M  | v2M       | 2M

    summary of RMR_IMPORT regions:
    name       | access   | args     |memreg | mmap  | rmr sz | mmap sz |
    -----------+----------+----------+-------+-------+--------+---------+
    rsp_rmr    |GRPRI     |loopback  |rsp2M_b|---    | 4K     | --      |
    rsp_rmr_c  |GRPRIC    |load_store|rsp2M_b|rmm    | 2M     | 4K      |
    rsp_rmr2   |GRPRIC    |load_store|rsp2   |rmm2   | 4K     | 4K      |
    rsp_rmr2   |GRPRI     |else      |rsp2   |---    | 4K     | --      |
    rsp_rmr_ro |GRIC      |load_store|rsp2   |rmm2_ro| 4K     | 4K      |
    rsp_rmr2M  |GRPRIC    |load_store|rsp2M_r|rmm2M  | 2M     | 2M      |
    rsp_rmr2M  |GRPRI     |else      |rsp2M_r|---    | 2M     | --      |
    fam_rmr    |GRPRIC    |fam+ld_st | ---   |fam_rmm| 2M     | 2M      |
    '''
    global args
    args = parse_args()
    if args.verbosity:
        print('pid={}'.format(os.getpid()))
    nodes = [item for item in args.nodes.split(',')] if args.nodes else []
    datasize = os.path.getsize(args.datafile)
    bigsize = os.path.getsize(args.bigfile)
    if 3*datasize > bigsize:
        print('3*datafile size (3*{}) > bigfile size ({})'.format(
              datasize, bigsize))
        sys.exit(1)
    gz_modp = ModuleParams('genz')
    wc_modp = ModuleParams('wildcat')
    with open(args.devfile, 'rb+', buffering=0) as f:
        conn = wildcat.Connection(f, args.verbosity)
        init = conn.do_INIT()
        gcid = init.uuid.gcid
        print('do_INIT: uuid={}, gcid={}'.format(init.uuid, init.uuid.gcid_str))
        # doing a 2nd INIT should fail
        exc = False
        try:
            bad = conn.do_INIT()
        except OSError:
            exc = True
        if exc:
            if args.verbosity:
                print('do_INIT: got expected error on 2nd INIT')
        else:
            print('fail: no error on 2nd INIT')

        if args.loopback and wc_modp.wildcat_loopback == 0:
            print('Configuration error - loopback test requested but driver has wildcat_loopback=0')

        if args.loopback and wc_modp.wildcat_loopback:
            zuu = zuuid(gcid=gcid)
            #conn.do_UUID_IMPORT(zuu, 0, None)
            conn.do_UUID_IMPORT(zuu, UU.IS_FAM, None) # Revisit: debug

        sz4K = 4096
        sz2M = 2<<20
        sz1G = 1<<30

        if args.requester:
            mm = mmap.mmap(-1, sz4K)
            v, l = wildcat.mmap_vaddr_len(mm)
            rsp = conn.do_MR_REG(v, l, MR.GPI)  # req: GET/PUT, 4K

        if args.responder or args.loopback:
            mm2 = mmap.mmap(-1, sz4K)
            mm2[0:sz4K] = os.urandom(sz4K)  # fill with random bytes
            v2, l2 = wildcat.mmap_vaddr_len(mm2)
            rsp2 = conn.do_MR_REG(v2, l2, MR.GRPRI)  # rsp: GET_REM/PUT_REM, 4K

        data = open(args.datafile, 'rb')
        mmdata = mmap.mmap(data.fileno(), 0, access=mmap.ACCESS_READ)
        datasha256 = hashlib.sha256(mmdata[0:datasize]).hexdigest()
        if args.verbosity:
            print('datafile sha256={}'.format(datasha256))
        # Revisit: using a hugepage file to guarantee a physically contiguous
        # region until the IOMMU works in the sim
        f2M = open(args.bigfile, 'rb+')
        mm2M = mmap.mmap(f2M.fileno(), 0, access=mmap.ACCESS_WRITE)
        mm2M[0:datasize] = mmdata[0:datasize]
        if args.huge:
            hugesize = os.path.getsize(args.hugefile)
            print('opening hugefile "{}"'.format(args.hugefile))
            f1G = open(args.hugefile, 'rb+')
            print('mmapping hugefile')
            mm1G = mmap.mmap(f1G.fileno(), 0, access=mmap.ACCESS_WRITE)
            print('initializing hugefile with random data')
            mm1G[0:hugesize//2] = os.urandom(hugesize//2)
            v1G, l1G = wildcat.mmap_vaddr_len(mm1G)
        mmdata.close()
        data.close()
        v2M, l2M = wildcat.mmap_vaddr_len(mm2M)
        rsp2M = conn.do_MR_REG(v2M + 0x1242, l2M - 0x5000, MR.GRPRI) # GET_REM/PUT_REM, 2M-0x5000

        rsp2M_l = conn.do_MR_REG(v2M, l2M, MR.GP)  # GET/PUT, 2M
        lmr = rsp2M_l
        lmm = mm2M

        if args.responder or args.loopback:
            rsp2M_b = conn.do_MR_REG(v2M, l2M, MR.GRPRI) # rsp: GET_REM/PUT_REM, 2M

        if args.loopback and wc_modp.wildcat_loopback:
            rsp_rmr = conn.do_RMR_IMPORT(zuu, rsp2M_b.rsp_zaddr, sz4K,
                                         MR.GRPRI)
            # individual, cpu-visible, 2M mapping allowing
            # GET/PUT/GET_REMOTE/PUT_REMOTE
            rsp2M_r = conn.do_MR_REG(v2M, sz2M, MR.GPGRPRI) # loop: ALL, 2M

            if args.load_store:
                rsp_rmr_c = conn.do_RMR_IMPORT(zuu, rsp2M_b.rsp_zaddr, sz4K,
                                               MR.GRPRIC)
                rmm = mmap.mmap(f.fileno(), sz4K, offset=rsp_rmr_c.offset)

                rsp_rmr2 = conn.do_RMR_IMPORT(zuu, rsp2.rsp_zaddr, sz4K,
                                              MR.GRPRIC)
                rmm2 = mmap.mmap(f.fileno(), sz4K, offset=rsp_rmr2.offset)
                v_rmm2, l_rmm2 = wildcat.mmap_vaddr_len(rmm2)

                rsp_rmr_ro = conn.do_RMR_IMPORT(zuu, rsp2.rsp_zaddr, sz4K,
                                                MR.GRIC)
                rmm2_ro = mmap.mmap(f.fileno(), sz4K, offset=rsp_rmr_ro.offset)
                v_rmm2_ro, l_rmm2_ro = wildcat.mmap_vaddr_len(rmm2_ro)
                # Revisit: why does trying to write rmm2_ro (to test that it's
                # really RO) cause a python3 segfault?
                # rmm2_ro[0:3] = b'Joe'

                rsp_rmr2M = conn.do_RMR_IMPORT(zuu, rsp2M_r.rsp_zaddr, sz2M,
                                               MR.GRPRIC)
                rmm2M = mmap.mmap(f.fileno(), sz2M, offset=rsp_rmr2M.offset)
            else:
                rsp_rmr2 = conn.do_RMR_IMPORT(zuu, rsp2.rsp_zaddr, sz4K,
                                              MR.GRPRI)
                rsp_rmr2M = conn.do_RMR_IMPORT(zuu, rsp2M_r.rsp_zaddr, sz2M,
                                               MR.GRPRI)

        xdm = wildcat.XDM(conn, 256, 256, slice_mask=0x1)
        rdm = wildcat.RDM(conn, 1024, slice_mask=0x1)  # Revisit: PFS has only slice 0

        nop = wildcat.xdm_cmd()
        nop.opcode = wildcat.XDM_CMD.NOP|wildcat.XDM_CMD.FENCE

        if args.huge:
            # individual, 1G mapping allowing
            # GET/PUT/GET_REMOTE/PUT_REMOTE (not cpu-visible)
            mm1Gsha256h = hashlib.sha256(mm1G[0:hugesize//2]).hexdigest()
            rsp1G = conn.do_MR_REG(v1G, sz1G, MR.GPGRPRI) # huge: ALL, 1G
            lmr = rsp1G
            lmm = mm1G

        if args.net:
            if args.verbosity:
                print('Starting networking - this is very slow in sim')
            import network as net
            factory = net.MyFactory(conn, lmr, lmm, xdm,
                                    args.verbosity, args.load_store,
                                    args.requester, args.responder, args.exit)
            try:
                factory.setup(args.port, nodes)
            except net.CannotListenError:
                print('Error: Address in use')

        # str1+str2 & str3 must fit in a 32-byte GET_IMM/PUT_IMM
        str1 = b'J/B/Z '
        str2 = b'making Gen-Z awesome!'
        str3 = b'PF Slice is awesome too!'
        # str4 & str5 must fit in a 52-byte ENQA
        str4 = b'But sometimes, madness is the only path forward.'
        str5 = b'Interrupts are distractions.'
        len1 = len(str1)
        len2 = len(str2)
        len3 = len(str3)
        len4 = len(str4)
        len5 = len(str5)
        len1_2 = len1 + len2
        if args.responder or args.loopback:
            mm2[0:len1] = str1
            if args.verbosity:
                print('mm2 (initial)="{}"'.format(mm2[0:len1].decode()))
        if args.loopback and wc_modp.wildcat_loopback:
            if args.load_store:
                if args.keyboard:
                    set_trace()  # Revisit: temporary debug
                # invalidate rmm2 to read fresh data
                wildcat.invalidate(v_rmm2, len1, True)
                if args.verbosity:
                    print('rmm2 (remote)="{}"'.format(rmm2[0:len1].decode()))
                if mm2[0:len1] != rmm2[0:len1]:
                    print('Error: mm2 "{}" != rmm2 "{}"'.format(
                        mm2[0:len1].decode(), rmm2[0:len1].decode()))
                rmm2[len1:len1_2] = str2
                # commit rmm2 writes, so mm2 reads will see new data
                wildcat.commit(v_rmm2+len1, len2, True)
                # invalidate mm2 to read fresh data
                wildcat.invalidate(v2, len1_2, False)
                if args.verbosity:
                    print('mm2 after remote update="{}"'.format(
                        mm2[0:len1_2].decode()))
                if mm2[0:len1_2] != rmm2[0:len1_2]:
                    print('Error: mm2 "{}" != rmm2 "{}"'.format(
                        mm2[0:len1_2].decode(), rmm2[0:len1_2].decode()))
            else:
                # just write mm2 directly, so it has the right stuff
                mm2[len1:len1_2] = str2

        sync = wildcat.xdm_cmd()
        sync.opcode = wildcat.XDM_CMD.SYNC|wildcat.XDM_CMD.FENCE

        xdm.buffer_cmd(nop)
        nop_cmpl = xdm.get_cmpl()
        if args.verbosity:
            print('NOP cmpl: {}'.format(nop_cmpl))
        if args.keyboard:
            set_trace()

        if args.loopback and wc_modp.wildcat_loopback:
            # test PUT_IMM
            put_imm_offset = len1_2 + 1
            rem_addr = rsp_rmr2.req_addr + put_imm_offset
            put_imm = wildcat.xdm_cmd()
            put_imm.opcode = wildcat.XDM_CMD.PUT_IMM
            put_imm.getput_imm.size = len3
            put_imm.getput_imm.rem_addr = rem_addr
            put_imm.getput_imm.payload[0:len3] = str3
            if args.keyboard:
                set_trace()
            xdm.queue_cmd(put_imm)
            try:
                put_imm_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('PUT_IMM cmpl: {}'.format(put_imm_cmpl))
            except XDMcompletionError as e:
                print('PUT_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.keyboard:
                set_trace()
            # Revisit: need fence/sync to ensure visibility
            if args.verbosity:
                print('mm2 after PUT_IMM="{}"'.format(
                    mm2[put_imm_offset:put_imm_offset+len3].decode()))
            # Revisit: check that mm2 got str3
            # test GET_IMM
            get_imm = wildcat.xdm_cmd()
            get_imm.opcode = wildcat.XDM_CMD.GET_IMM
            get_imm.getput_imm.size = len1_2
            get_imm.getput_imm.rem_addr = rsp_rmr2.req_addr
            xdm.queue_cmd(get_imm)
            try:
                get_imm_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('GET_IMM cmpl: {}'.format(get_imm_cmpl.getimm))
            except XDMcompletionError as e:
                print('GET_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            # Revisit: check that we got str1+str2

            if args.keyboard:
                set_trace()
            # test PUT
            put_offset = datasize
            local_addr = v2M
            rem_addr = rsp_rmr2M.req_addr + put_offset
            put = wildcat.xdm_cmd()
            put.opcode = wildcat.XDM_CMD.PUT|wildcat.XDM_CMD.FENCE
            put.getput.size = datasize
            put.getput.read_addr = local_addr
            put.getput.write_addr = rem_addr
            xdm.queue_cmd(put)
            try:
                put_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('PUT cmpl: {}'.format(put_cmpl))
            except XDMcompletionError as e:
                print('PUT cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            # Revisit: need fence/sync to ensure visibility
            mm2Msha256p = hashlib.sha256(
                mm2M[put_offset:put_offset+datasize]).hexdigest()
            if args.verbosity:
                print('mm2M sha256 after PUT="{}"'.format(mm2Msha256p))
            if mm2Msha256p != datasha256:
                print('PUT sha mismatch: {} != {}'.format(datasha256, mm2Msha256p))

            if args.keyboard:
                set_trace()
            # test GET+SYNC
            get_offset = 2 * datasize
            local_addr = v2M + get_offset
            rem_addr = rsp_rmr2M.req_addr + put_offset
            get = wildcat.xdm_cmd()
            get.opcode = wildcat.XDM_CMD.GET|wildcat.XDM_CMD.FENCE
            get.getput.size = datasize
            get.getput.read_addr = rem_addr
            get.getput.write_addr = local_addr
            xdm.queue_cmds([get, sync])
            try:
                get_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('GET cmpl: {}'.format(get_cmpl))
            except XDMcompletionError as e:
                print('GET cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            try:
                sync_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SYNC cmpl: {}'.format(sync_cmpl))
            except XDMcompletionError as e:
                print('SYNC cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            mm2Msha256g = hashlib.sha256(
                mm2M[get_offset:get_offset+datasize]).hexdigest()
            if args.verbosity:
                print('mm2M sha256 after GET="{}"'.format(mm2Msha256g))
            if mm2Msha256g != datasha256:
                print('GET sha mismatch: {} != {}'.format(
                    datasha256, mm2Msha256g))

            # Do the atomic tests at the 1M point in the 2M region
            atomic_offset = rsp_rmr2M.req_addr + 1048576

            # test atomic 32 bit SWAP
            swap32 = wildcat.xdm_cmd()
            swap32.opcode = wildcat.XDM_CMD.ATM_SWAP
            swap32.atomic_one_op32.r = 1  # return a value
            swap32.atomic_one_op32.size = wildcat.ATOMIC_SIZE.SIZE_32BIT
            swap32.atomic_one_op32.rem_addr = atomic_offset
            swap32.atomic_one_op32.operand = 0x12345678
            xdm.queue_cmd(swap32)
            try:
                swap32_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SWAP32 cmpl: {}'.format(swap32_cmpl))
            except XDMcompletionError as e:
                print('SWAP32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('SWAP32 return value: {}'.format(
                      swap32_cmpl.atomic32))
            if args.keyboard:
                set_trace()

            # test the same atomic 32 bit SWAP to see if the prev val is now 0x12345678
            swap32 = wildcat.xdm_cmd()
            swap32.opcode = wildcat.XDM_CMD.ATM_SWAP
            swap32.atomic_one_op32.r = 1  # return a value
            swap32.atomic_one_op32.size = wildcat.ATOMIC_SIZE.SIZE_32BIT
            swap32.atomic_one_op32.rem_addr = atomic_offset
            swap32.atomic_one_op32.operand = 0xDEADBEEF
            xdm.queue_cmd(swap32)
            try:
                swap32_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SWAP32 cmpl: {}'.format(swap32_cmpl))
            except XDMcompletionError as e:
                print('SWAP32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('SWAP32 return value: {}'.format(
                      swap32_cmpl.atomic32))
            if swap32_cmpl.atomic32.retval != 0x12345678:
                print('FAIL: SWAP32: retval is {:#x} and should be 0x12345678'.format(
                      swap32_cmpl.atomic32.retval))
            if args.keyboard:
                set_trace()

            # test atomic 32 bit COMPARE AND SWAP - val is now 0xDEADBEEF
            cas32 = wildcat.xdm_cmd()
            cas32.opcode = wildcat.XDM_CMD.ATM_CAS
            cas32.atomic_two_op32.r = 1  # return a value
            cas32.atomic_two_op32.size = wildcat.ATOMIC_SIZE.SIZE_32BIT
            cas32.atomic_two_op32.rem_addr = atomic_offset
            cas32.atomic_two_op32.operand1 = 0xDEADBEEF
            cas32.atomic_two_op32.operand2 = 0xBDA11FED
            xdm.queue_cmd(cas32)
            try:
                cas32_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('CAS32 cmpl: {}'.format(cas32_cmpl))
            except XDMcompletionError as e:
                print('CAS32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('CAS32 return value: {}'.format(
                      cas32_cmpl.atomic32))
            if cas32_cmpl.atomic32.retval != 0xDEADBEEF:
                print('FAIL: CAS32: retval is {:#x} and should be 0xDEADBEEF'.format(
                      cas32_cmpl.atomic32.retval))
            if args.keyboard:
                set_trace()

            # test atomic 32 bit FETCH AND ADD - val is now 0xBDA11FED
            add32 = wildcat.xdm_cmd()
            add32.opcode = wildcat.XDM_CMD.ATM_ADD
            add32.atomic_one_op32.r = 1  # return a value
            add32.atomic_one_op32.size = wildcat.ATOMIC_SIZE.SIZE_32BIT
            add32.atomic_one_op32.rem_addr = atomic_offset
            add32.atomic_one_op32.operand = 0x12345678
            xdm.queue_cmd(add32)
            try:
                add32_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('ADD32 cmpl: {}'.format(add32_cmpl))
            except XDMcompletionError as e:
                print('ADD32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('ADD32 return value: {}'.format(
                      add32_cmpl.atomic32))
            if add32_cmpl.atomic32.retval != 0xBDA11FED:
                print('FAIL: ADD32: retval is {:#x} and should be 0xBDA11FED'.format(
                      add32_cmpl.atomic32.retval))
            if args.keyboard:
                set_trace()

            # use SWAP to get the sum from the previous ADD32
            swap32 = wildcat.xdm_cmd()
            swap32.opcode = wildcat.XDM_CMD.ATM_SWAP
            swap32.atomic_one_op32.r = 1  # return a value
            swap32.atomic_one_op32.size = wildcat.ATOMIC_SIZE.SIZE_32BIT
            swap32.atomic_one_op32.rem_addr = atomic_offset
            swap32.atomic_one_op32.operand = 0x0
            xdm.queue_cmd(swap32)
            try:
                swap32_cmpl = xdm.get_cmpl()
            except XDMcompletionError as e:
                print('SWAP32 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if swap32_cmpl.atomic32.retval != 0xCFD57665:
                print('FAIL: ADD32: retval is {:#x} and should be 0xCFD57665'.format(
                      swap32_cmpl.atomic32.retval))
            else:
                print('ADD32: PASS: sum is {:#x}'.format(swap32_cmpl.atomic32.retval))

            # test atomic 64 bit SWAP 
            swap64 = wildcat.xdm_cmd()
            swap64.opcode = wildcat.XDM_CMD.ATM_SWAP
            swap64.atomic_one_op64.r = 1  # return a value
            swap64.atomic_one_op64.size = wildcat.ATOMIC_SIZE.SIZE_64BIT
            swap64.atomic_one_op64.rem_addr = atomic_offset
            swap64.atomic_one_op64.operand = 0xDEADBEEFEDA11AB
            xdm.queue_cmd(swap64)
            try:
                swap64_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SWAP64 cmpl: {}'.format(swap64_cmpl))
            except XDMcompletionError as e:
                print('SWAP64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('SWAP64 return value: {}'.format(
                      swap64_cmpl.atomic64))
            if args.keyboard:
                set_trace()
            # second test atomic 64 bit SWAP - val is now 0xDEADBEEFEDA11AB
            swap64 = wildcat.xdm_cmd()
            swap64.opcode = wildcat.XDM_CMD.ATM_SWAP
            swap64.atomic_one_op64.r = 1  # return a value
            swap64.atomic_one_op64.size = wildcat.ATOMIC_SIZE.SIZE_64BIT
            swap64.atomic_one_op64.rem_addr = atomic_offset
            swap64.atomic_one_op64.operand = 0x123456789ABCDEF1
            xdm.queue_cmd(swap64)
            try:
                swap64_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('SWAP64 cmpl: {}'.format(swap64_cmpl))
            except XDMcompletionError as e:
                print('SWAP64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('SWAP64 return value: {}'.format(
                      swap64_cmpl.atomic64))
            if swap64_cmpl.atomic64.retval != 0xDEADBEEFEDA11AB:
                print('FAIL: SWAP64: retval is {:#x} and should be 0xDEADBEEFEDA11AB'.format(
                      swap64_cmpl.atomic64.retval))
            if args.keyboard:
                set_trace()
               
            # test atomic 64 bit COMPARE AND SWAP - val is now 0x12356789ABCDEF1
            cas64 = wildcat.xdm_cmd()
            cas64.opcode = wildcat.XDM_CMD.ATM_CAS
            cas64.atomic_two_op64.r = 1  # return a value
            cas64.atomic_two_op64.size = wildcat.ATOMIC_SIZE.SIZE_64BIT
            cas64.atomic_two_op64.rem_addr = atomic_offset
            cas64.atomic_two_op64.operand1 = 0x12356789ABCDEF1
            cas64.atomic_two_op64.operand2 = 0xBADDECAFBADDECAF
            xdm.queue_cmd(cas64)
            try:
                cas64_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('CAS64 cmpl: {}'.format(cas64_cmpl))
            except XDMcompletionError as e:
                print('CAS64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('CAS64 return value: {}'.format(
                      cas64_cmpl.atomic64))
            if cas64_cmpl.atomic64.retval != 0x123456789ABCDEF1:
                print('FAIL: CAS64: retval is {:#x} and should be 0x123456789ABCDEF1'.format(
                      cas64_cmpl.atomic64.retval))
            if args.keyboard:
                set_trace()

            # test atomic 64 bit FETCH AND ADD - val is now 0x123456789ABCDEF1
            add64 = wildcat.xdm_cmd()
            add64.opcode = wildcat.XDM_CMD.ATM_ADD
            add64.atomic_one_op64.r = 1  # return a value
            add64.atomic_one_op64.size = wildcat.ATOMIC_SIZE.SIZE_64BIT
            add64.atomic_one_op64.rem_addr = atomic_offset
            add64.atomic_one_op64.operand = 0x1111111111111111
            xdm.queue_cmd(add64)
            try:
                add64_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('ADD64 cmpl: {}'.format(add64_cmpl))
            except XDMcompletionError as e:
                print('ADD64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if args.verbosity:
                print('ADD64 return value: {}'.format(
                      add64_cmpl.atomic64))
            if add64_cmpl.atomic64.retval != 0x123456789abcdef1:
                print('FAIL: ADD64: retval is {:#x} and should be 0x0x123456789abcdef1'.format(
                      add64_cmpl.atomic64.retval))
            # use atomic 64 bit SWAP to get the sum from previous ADD
            swap64 = wildcat.xdm_cmd()
            swap64.opcode = wildcat.XDM_CMD.ATM_SWAP
            swap64.atomic_one_op64.r = 1  # return a value
            swap64.atomic_one_op64.size = wildcat.ATOMIC_SIZE.SIZE_64BIT
            swap64.atomic_one_op64.rem_addr = atomic_offset
            swap64.atomic_one_op64.operand = 0x0
            xdm.queue_cmd(swap64)
            try:
                swap64_cmpl = xdm.get_cmpl()
            except XDMcompletionError as e:
                print('SWAP64 cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            if swap64_cmpl.atomic64.retval != 0x23456789ABCDF002:
                print('FAIL: ADD64: retval is {:#x} and should be 0x23456789ABCDF002'.format(
                      swap64_cmpl.atomic64.retval))
            else:
                print('ADD64: PASS: sum is {:#x}'.format(swap64_cmpl.atomic64.retval))
            if args.keyboard:
                set_trace()

            # test EnqA/RDM
            enqa = wildcat.xdm_cmd()
            enqa.opcode = wildcat.XDM_CMD.ENQA
            enqa.enqa.dgcid = zuu.gcid
            enqa.enqa.rspctxid = rdm.rsp_rqa.info.rspctxid
            enqa.enqa.payload[0:len4] = str4
            xdm.queue_cmd(enqa)
            try:
                enqa_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('ENQA cmpl: {}'.format(enqa_cmpl))
            except XDMcompletionError as e:
                print('ENQA cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            rdm_cmpl = rdm.get_cmpl()
            if args.verbosity:
                print('RDM cmpl: {}'.format(rdm_cmpl.enqa))
            if enqa.enqa.payload[0:52] != rdm_cmpl.enqa.payload[0:52]:
                print('FAIL: RDM: payload is {} and should be {}'.format(
                      rdm_cmpl.enqa.payload[0:52], enqa.enqa.payload[0:52]))
            # Revisit: check other cmpl fields
            if args.keyboard:
                set_trace()

            # test EnqA/RDM with poll
            enqa = wildcat.xdm_cmd()
            enqa.opcode = wildcat.XDM_CMD.ENQA
            enqa.enqa.dgcid = zuu.gcid
            enqa.enqa.rspctxid = rdm.rsp_rqa.info.rspctxid
            enqa.enqa.payload[0:len4] = str4
            xdm.queue_cmd(enqa)
            try:
                enqa_cmpl = xdm.get_cmpl()
                if args.verbosity:
                    print('ENQA cmpl: {}'.format(enqa_cmpl))
            except XDMcompletionError as e:
                print('ENQA cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            rdm_cmpls = rdm.get_poll()
            if args.verbosity:
                for c in range(len(rdm_cmpls)):
                    if c != None:
                         print('RDM cmpl: {}'.format(rdm_cmpls[c].enqa))
            for c in range(len(rdm_cmpls)):
                if enqa.enqa.payload[0:52] != rdm_cmpls[c].enqa.payload[0:52]:
                    print('FAIL: RDM: payload is {} and should be {}'.format(
                      rdm_cmpls[c].enqa.payload[0:52], enqa.enqa.payload[0:52]))
            if args.keyboard:
                set_trace()

            # second test EnqA/RDM with poll
            print('SECOND EnqA/RDM poll test')
            enqa2 = wildcat.xdm_cmd()
            enqa2.opcode = wildcat.XDM_CMD.ENQA
            enqa2.enqa.dgcid = zuu.gcid
            enqa2.enqa.rspctxid = rdm.rsp_rqa.info.rspctxid
            enqa2.enqa.payload[0:len5] = str5
            xdm.queue_cmd(enqa2)
            try:
                enqa_cmpl2 = xdm.get_cmpl()
                if args.verbosity:
                    print('ENQA cmpl: {}'.format(enqa_cmpl2))
            except XDMcompletionError as e:
                print('ENQA cmpl error: {} {:#x} request_id {:#x}'.format(
                      e, e.status, e.request_id))
            rdm_cmpls2 = rdm.get_poll()
            if args.verbosity:
                for c in range(len(rdm_cmpls2)):
                    if c != None:
                         print('RDM cmpl: {}'.format(rdm_cmpls2[c].enqa))
            for c in range(len(rdm_cmpls2)):
                if enqa2.enqa.payload[0:52] != rdm_cmpls2[c].enqa.payload[0:52]:
                    print('FAIL: RDM: payload is {} and should be {}'.format(
                      rdm_cmpls[c].enqa.payload[0:52], enqa.enqa.payload[0:52]))
            if args.keyboard:
                set_trace()
            # test FAM
            if args.fam:
                # Assume CID is 0x40 and create a ZUUID
                fam_zuu = zuuid(gcid=0x1) # Revisit: fpga test for bringup
                if args.verbosity:
                    print('FAM zuuid={}'.format(fam_zuu))
                # Do a UUID_IMPORT with the IS_FAM flag set
                conn.do_UUID_IMPORT(fam_zuu, UU.IS_FAM, None)
                # RMR_IMPORT the FAM at address 0 and size 2M
                if args.load_store:
                    fam_rmr = conn.do_RMR_IMPORT(fam_zuu, 0, sz2M, MR.GRPRIC)
                    # Do load/store to FAM
                    fam_rmm = mmap.mmap(f.fileno(), sz2M,
                                    offset=fam_rmr.offset)
                    fam_v, fam_l = wildcat.mmap_vaddr_len(fam_rmm)
                    fam_rmm[0:len1] = str1
                    fam_rmm[len1:len1_2] = str2
                    # commit writes, so reads will see new data
                    wildcat.commit(fam_v, len1_2, True)
                else:
                    fam_rmr = conn.do_RMR_IMPORT(fam_zuu, 0, sz2M, MR.GRPRI)
                # do an XDM command to get the data back and check it
                get_imm = wildcat.xdm_cmd()
                get_imm.opcode = wildcat.XDM_CMD.GET_IMM
                get_imm.getput_imm.size = len1_2
                get_imm.getput_imm.rem_addr = fam_rmr.req_addr
                if args.keyboard:
                    set_trace()
                xdm.queue_cmd(get_imm)
                try:
                    get_imm_cmpl = xdm.get_cmpl()
                    if args.verbosity:
                        print('GET_IMM cmpl: {}'.format(get_imm_cmpl.getimm))
                except XDMcompletionError as e:
                    print('GET_IMM cmpl error: {} {:#x} request_id {:#x}'.format(
                          e, e.status, e.request_id))
                # Revisit: check that we got str1+str2
                if args.keyboard:
                    set_trace()
            # end if FAM

            # Test a huge PUT
            if args.huge:
                rsp_rmr1G = conn.do_RMR_IMPORT(zuu, rsp1G.rsp_zaddr, sz1G,
                                               MR.GRPRI)
                put_offset = hugesize // 2
                local_addr = v1G
                rem_addr = rsp_rmr1G.req_addr + put_offset
                put = wildcat.xdm_cmd()
                put.opcode = wildcat.XDM_CMD.PUT|wildcat.XDM_CMD.FENCE
                put.getput.size = hugesize // 2
                put.getput.read_addr = local_addr
                put.getput.write_addr = rem_addr
                if args.keyboard:
                    set_trace()
                start = time.monotonic()
                xdm.queue_cmd(put)
                try:
                    put_cmpl = xdm.get_cmpl()
                    end = time.monotonic()
                    if args.verbosity:
                        print('huge PUT cmpl: {}'.format(put_cmpl))
                except XDMcompletionError as e:
                    print('huge PUT cmpl error: {} {:#x} request_id {:#x}'.format(
                        e, e.status, e.request_id))
                # Revisit: need fence/sync to ensure visibility
                mm1Gsha256p = hashlib.sha256(
                    mm1G[put_offset:put_offset+hugesize//2]).hexdigest()
                if args.verbosity:
                    print('mm1G sha256 after PUT="{}"'.format(mm1Gsha256p))
                if mm1Gsha256p != mm1Gsha256h:
                    print('huge PUT sha mismatch: {} != {}'.format(
                        mm1Gsha256h, mm1Gsha256h))
                secs = end - start
                if args.verbosity:
                    print('huge PUT of {} bytes in {} seconds = {} GiB/s'.format(
                        put.getput.size, secs, put.getput.size / (secs * sz1G)))
            # end if huge
        # end if loopback

        if args.net:
            if args.verbosity:
                print('Waiting for network connections')
            net.reactor.run()
        if args.keyboard:
            set_trace()
        conn.do_XQUEUE_FREE(xdm.rsp_xqa.info)
        conn.do_RQUEUE_FREE(rdm.rsp_rqa.info)
        if args.requester:
            conn.do_MR_FREE(v, l, MR.GPI, rsp.rsp_zaddr)
        conn.do_MR_FREE(v2M, l2M, MR.GP, rsp2M_l.rsp_zaddr)
        conn.do_MR_FREE(v2M + 0x1242, l2M - 0x5000, MR.GRPRI, rsp2M.rsp_zaddr)

        # we do not MR_FREE rsp2M_b, to see if it is cleaned up at close
        # same for RMR_FREE of rsp_rmr
        if args.loopback and wc_modp.wildcat_loopback:
            if args.load_store:
                conn.do_RMR_FREE(zuu, rsp2M_b.rsp_zaddr, sz4K, MR.GRPRIC,
                                 rsp_rmr_c.req_addr)
            exc = False
            try:
                conn.do_UUID_FREE(zuu)
            except OSError:
                exc = True
            if exc:
                if args.verbosity:
                    print('do_UUID_FREE of zuu: got expected error')
            else:
                print('fail: no error on UUID_FREE of zuu')
        exc = False
        try:
            conn.do_UUID_FREE(init.uuid)
        except OSError:
            exc = True
        if exc:
            if args.verbosity:
                print('do_UUID_FREE of init.uuid: got expected error')
        else:
            print('fail: no error on UUID_FREE of init.uuid')
    # end with

if __name__ == '__main__':
    main()
