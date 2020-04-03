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

import os
import uuid
import mmap
import select
from ctypes import *
from enum import Enum, IntEnum
from collections import defaultdict

mcommit = cdll.LoadLibrary(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'libmcommit.so'))

c_u8  = c_ubyte
c_u16 = c_ushort
c_u32 = c_uint
c_u64 = c_ulonglong

_bytes = bytes    # to avoid bytes name conflict in zuuid.__init__


def gcid_to_str(gcid):
    '''Return a string representation of a GCID in the format ssss:ccc,
    where ssss is the 16-bit SID and ccc is the 12-bit CID (both in hex)'''
    return '{:04x}:{:03x}'.format(gcid >> 12, gcid & 0xfff)

class zuuid(uuid.UUID):
    '''An ordinary version 4 (random) UUID with the Gen-Z GCID encoded in
    the top 28 bits.'''
    def __init__(self, string=None, gcid=None, bytes=None):
        '''Create a UUID containing the 28-bit gcid (if specified) and
        initial string/bytes (if specified).

        If string/bytes is not specified, then random bytes are used.

        The other constructor forms supported by UUID (bytes_le, fields,
        hex, int, urn) are not supported.'''
        if bytes is not None:
            ba = bytearray(bytes)
        elif string is not None:
            ba = uuid.UUID(string).bytes
        else:
            ba = bytearray(os.urandom(16))
        if gcid is not None:
            ba[0:4] = ((gcid<<4)|(ba[3]&0xf)).to_bytes(4, byteorder='big')
        super().__init__(bytes=_bytes(ba), version=4)

    @property
    def gcid(self):
        '''Return the 28-bit Gen-Z GCID portion of the uuid (as an int).'''
        return ((self.bytes[0] << 20) | (self.bytes[1] << 12) |
                (self.bytes[2] <<  4) | (self.bytes[3] >> 4))

    @property
    def gcid_str(self):
        return gcid_to_str(self.gcid)

class MR(IntEnum):
    '''MR_REG access flags'''
    GET         = 1 << 0
    PUT         = 1 << 1
    SEND        = PUT
    RECV        = GET
    GET_REMOTE  = 1 << 2
    PUT_REMOTE  = 1 << 3
    KEY_ONESHOT = 1 << 7  # Revisit
    REQ_CPU     = 1 << 27
    REQ_CPU_WB  = 0 << 28
    REQ_CPU_WC  = 1 << 28
    REQ_CPU_WT  = 2 << 28
    REQ_CPU_UC  = 3 << 28
    INDIVIDUAL  = 1 << 30
    INDIV_RKEYS = 1 << 31
    G           = GET
    P           = PUT
    GR          = GET_REMOTE
    PR          = PUT_REMOTE
    I           = INDIVIDUAL
    C           = REQ_CPU
    GP          = G|P
    GPI         = G|P|I
    GRPR        = GR|PR
    GRPRI       = GR|PR|I
    GRPRIC      = GR|PR|I|C
    GRIC        = GR|I|C
    PGRI        = P|GR|I
    GPGRPRI     = G|P|GR|PR|I
    GPGRPRIC    = G|P|GR|PR|I|C

class UU(IntEnum):
    '''UUID_IMPORT uu_flags'''
    IS_FAM      = 0x1

class OP(Enum):
    INIT        = 0
    MR_REG      = 1
    MR_FREE     = 2
    NOP         = 3
    RMR_IMPORT  = 6
    RMR_FREE    = 7
    UUID_IMPORT = 10
    UUID_FREE   = 11
    XQUEUE_ALLOC= 12
    XQUEUE_FREE = 13
    RQUEUE_ALLOC= 14
    RQUEUE_FREE = 15
    RESPONSE    = 0x80
    VERSION     = 1
    INDEX_MASK  = 0xffff

class XDM_CMD(IntEnum):
    NOP           = 0x0
    ENQA          = 0x1
    PUT           = 0x2
    GET           = 0x3
    PUT_IMM       = 0x4
    GET_IMM       = 0x5
    SYNC          = 0x1f
    ATM_SWAP      = 0x20
    ATM_ADD       = 0x22
    ATM_AND       = 0x24
    ATM_OR        = 0x25
    ATM_XOR       = 0x26
    ATM_SMIN      = 0x28
    ATM_SMAX      = 0x29
    ATM_UMIN      = 0x2a
    ATM_UMAX      = 0x2b
    ATM_CAS       = 0x2c
    OP_MASK       = 0xff
    FENCE         = 0x100
    ATM_RETURN    = 0x01
    ATM_SIZE_MASK = 0x0E
    ATM_SIZE_32   = 0x04
    ATM_SIZE_64   = 0x06

class ATOMIC_SIZE(IntEnum):
    SIZE_32BIT    = 2
    SIZE_64BIT    = 3

class hdr(Structure):
    _fields_ = [('version',        c_u8),
                ('opcode',         c_u8),
                ('_index',         c_u16),
                ('status',         c_int)
                ]

    def __init__(self, opcode=OP.NOP, index=0, rsp=False):
        super().__init__(OP.VERSION.value,
                         opcode.value|OP.RESPONSE.value if rsp
                         else opcode.value,
                         index & OP.INDEX_MASK.value, 0)

    @property
    def index(self):
        return self._index

    @index.setter
    def index(self, val):
        self._index = val & OP.INDEX_MASK.value

class uuidStructure(Structure):
    @property
    def uuid(self):
        if (not hasattr(self, '_uuid') or
            self._uuid.bytes != bytes(self.uuid_bytes)):
            self._uuid = zuuid(bytes=bytes(self.uuid_bytes))
        return self._uuid

class qcm(Structure):
    _fields_ = [('size',      c_u32),
                ('off',       c_u64)
                ]

class queue(Structure):
    _fields_ = [('ent',       c_u32),
                ('size',      c_u32),
                ('off',       c_u64)
                ]

class xqinfo(Structure):
    _fields_ = [('qcm',        qcm),
                ('cmdq',       queue),
                ('cmplq',      queue),
                ('slice',      c_u8),
                ('queue',      c_u8)
                ]

class rqinfo(Structure):
    _fields_ = [('qcm',        qcm),
                ('cmplq',      queue),
                ('slice',      c_u8),
                ('queue',      c_u8),
                ('rspctxid',   c_u32),
                ('irq_vector', c_u32)
                ]

class wildcat_rdma_attr(Structure):
    _fields_ = [('backend',        c_u32),
                ('max_tx_queues',  c_u32),
                ('max_rx_queues',  c_u32),
                ('max_hw_qlen',    c_u32),
                ('max_sw_qlen',    c_u32),
                ('max_dma_len',    c_u64)
               ]

class global_shared_data(Structure):
    _fields_ = [('magic',             c_u32),
                ('version',           c_u32),
                ('debug_flags',       c_u32),
                ('default_attr',      wildcat_rdma_attr),
                ('triggered_counter', c_u32 * 128)
               ]

class local_shared_data(Structure):
    _fields_ = [('magic',             c_u32),
                ('version',           c_u32),
                ('handled_counter',   c_u32 * 128)
               ]

class req_INIT(Structure):
    _fields_ = [('hdr',            hdr)
                ]

class rsp_INIT(uuidStructure):
    _fields_ = [('hdr',                  hdr),
                ('uuid_bytes',           c_byte * 16),
                ('global_shared_offset', c_u64),
                ('global_shared_size',   c_u32),
                ('local_shared_offset',  c_u64),
                ('local_shared_size',    c_u32),
                ]

class req_NOP(Structure):
    _fields_ = [('hdr',            hdr),
                ('seq',            c_u64),
                ]

class rsp_NOP(Structure):
    _fields_ = [('hdr',            hdr),
                ('seq',            c_u64),
                ]

class req_MR_REG(Structure):
    _fields_ = [('hdr',            hdr),
                ('vaddr',          c_u64),
                ('len',            c_u64),
                ('access',         c_u64),
                ]

    def to_json(self):
        return {'__class__': type(self).__name__,
                '__value__': {'vaddr':self.vaddr,
                              'len':self.len,
                              'access':self.access}}

    def __repr__(self):
        r = type(self).__name__ + '('
        r += 'vaddr={:#x}, len={:#x}, access={:#x}'.format(
            self.vaddr, self.len, self.access)
        r += ')'
        return r

class rsp_MR_REG(Structure):
    _fields_ = [('hdr',            hdr),
                ('rsp_zaddr',      c_u64),
                ('pg_ps',          c_u32),
                ('physaddr',       c_u64),  # no longer used
                ]

    def to_json(self):
        return {'__class__': type(self).__name__,
                '__value__': {'rsp_zaddr':self.rsp_zaddr,
                              'pg_ps':self.pg_ps}}

    def __repr__(self):
        r = type(self).__name__ + '('
        r += 'rsp_zaddr={:#x}, pg_ps={}'.format(
            self.rsp_zaddr, self.pg_ps)
        r += ')'
        return r

class req_MR_FREE(Structure):
    _fields_ = [('hdr',            hdr),
                ('vaddr',          c_u64),
                ('len',            c_u64),
                ('access',         c_u64),
                ('rsp_zaddr',      c_u64),
                ]

class rsp_MR_FREE(Structure):
    _fields_ = [('hdr',            hdr),
                ]

class req_RMR_IMPORT(uuidStructure):
    _fields_ = [('hdr',            hdr),
                ('uuid_bytes',     c_byte * 16),
                ('rsp_zaddr',      c_u64),
                ('len',            c_u64),
                ('access',         c_u64),
                ]

class rsp_RMR_IMPORT(Structure):
    _fields_ = [('hdr',            hdr),
                ('req_addr',       c_u64),
                ('offset',         c_u64),
                ('pg_ps',          c_u32),
                ]

class req_RMR_FREE(uuidStructure):
    _fields_ = [('hdr',            hdr),
                ('uuid_bytes',     c_byte * 16),
                ('rsp_zaddr',      c_u64),
                ('len',            c_u64),
                ('access',         c_u64),
                ('req_addr',       c_u64),
                ]

class rsp_RMR_FREE(Structure):
    _fields_ = [('hdr',            hdr),
                ]

class req_UUID_IMPORT(uuidStructure):
    _fields_ = [('hdr',            hdr),
                ('uuid_bytes',     c_byte * 16),
                ('mgr_uuid_bytes', c_byte * 16),
                ('uu_flags',       c_u32),
                ]

class rsp_UUID_IMPORT(Structure):
    _fields_ = [('hdr',            hdr),
                ]

class req_UUID_FREE(uuidStructure):
    _fields_ = [('hdr',            hdr),
                ('uuid_bytes',     c_byte * 16)
                ]

class rsp_UUID_FREE(Structure):
    _fields_ = [('hdr',            hdr),
                ]

class req_XQUEUE_ALLOC(Structure):
    _fields_ = [('hdr',                     hdr),
                ('cmdq_ent',                c_u32),
                ('cmplq_ent',               c_u32),
                ('EnqA_traffic_class',      c_u8),
                ('priority',                c_u8),
                ('slice_mask',              c_u8)
                ]

class rsp_XQUEUE_ALLOC(Structure):
    _fields_ = [('hdr',            hdr),
                ('info',           xqinfo),
                ]

class req_XQUEUE_FREE(Structure):
    _fields_ = [('hdr',            hdr),
                ('info',           xqinfo),
                ]

class rsp_XQUEUE_FREE(Structure):
    _fields_ = [('hdr',            hdr),
                ]

class req_RQUEUE_ALLOC(Structure):
    _fields_ = [('hdr',                     hdr),
                ('cmplq_ent',               c_u32),
                ('slice_mask',              c_u8),
                ]

class rsp_RQUEUE_ALLOC(Structure):
    _fields_ = [('hdr',            hdr),
                ('info',           rqinfo),
                ]

class req_RQUEUE_FREE(Structure):
    _fields_ = [('hdr',            hdr),
                ('info',           rqinfo),
                ]

class rsp_RQUEUE_FREE(Structure):
    _fields_ = [('hdr',            hdr),
                ]

class xdm_cmd_hdr(Structure):
    _fields_ = [('opcode',          c_u16),
                ('request_id',      c_u16)
                ]

class xdm_getput(Structure):
    _fields_ = [('hdr',             xdm_cmd_hdr),
                ('size',            c_u32),
                ('read_addr',       c_u64),
                ('write_addr',      c_u64),
                ('rv1',             c_u8 * 40)
                ]

class xdm_getput_imm(Structure):
    _fields_ = [('hdr',             xdm_cmd_hdr),
                ('size',            c_u32),
                ('rem_addr',        c_u64),
                ('rv1',             c_u64 * 2),
                ('payload',         c_byte * 32)  # Revisit: put_imm only
                ]

class xdm_atomic_one_op32(Structure):
    _fields_ = [('hdr',             xdm_cmd_hdr),
                ('r',               c_u8, 1),
                ('size',            c_u8, 3),
                ('rv1',             c_u8 * 3),
                ('rem_addr',        c_u64),
                ('rv2',             c_u64 * 2),
                ('operand',         c_u32),
                ('rv3',             c_u32),
                ('rv4',             c_u64 * 3)
                ]

class xdm_atomic_one_op64(Structure):
    _fields_ = [('hdr',             xdm_cmd_hdr),
                ('r',               c_u8, 1),
                ('size',            c_u8, 3),
                ('rv1',             c_u8 * 3),
                ('rem_addr',        c_u64),
                ('rv2',             c_u64 * 2),
                ('operand',         c_u64),
                ('rv3',             c_u64 * 3)
                ]

class xdm_atomic_two_op32(Structure):
    _fields_ = [('hdr',             xdm_cmd_hdr),
                ('r',               c_u8, 1),
                ('size',            c_u8, 3),
                ('rv1',             c_u8 * 3),
                ('rem_addr',        c_u64),
                ('rv2',             c_u64 * 2),
                ('operand1',        c_u32),
                ('operand2',        c_u32),
                ('rv3',             c_u64 * 3)
                ]

class xdm_atomic_two_op64(Structure):
    _fields_ = [('hdr',             xdm_cmd_hdr),
                ('r',               c_u8, 1),
                ('size',            c_u8, 3),
                ('rv1',             c_u8 * 3),
                ('rem_addr',        c_u64),
                ('rv2',             c_u64 * 2),
                ('operand1',        c_u64),
                ('operand2',        c_u64),
                ('rv3',             c_u64 * 2)
                ]

class xdm_enqa(Structure):
    _fields_ = [('hdr',             xdm_cmd_hdr),
                ('rv1',             c_u32, 3),
                ('t',               c_u32, 1),  # format - must be 0
                ('dgcid',           c_u32, 28),
                ('rspctxid',        c_u32, 24),
                ('rv2',             c_u32, 8),
                ('payload',         c_byte * 52)
                ]

class xdm_cmd_by_bytes(Structure):
    _fields_ = [('u64',             c_u64 * 8)]

class xdm_cmd(Union):
    _fields_ = [('hdr',             xdm_cmd_hdr),
                ('getput',          xdm_getput),
                ('getput_imm',      xdm_getput_imm),
                ('atomic_one_op32', xdm_atomic_one_op32),
                ('atomic_one_op64', xdm_atomic_one_op64),
                ('atomic_two_op32', xdm_atomic_two_op32),
                ('atomic_two_op64', xdm_atomic_two_op64),
                ('enqa',            xdm_enqa),
                ('cmd_by_bytes',    xdm_cmd_by_bytes)
                ]

    cmd_names = ['NOP', 'ENQA', 'PUT', 'GET', 'PUT_IMM', 'GET_IMM', 'SYNC',
                 'ATM_SWAP', 'ATM_ADD',  'ATM_AND',  'ATM_OR',   'ATM_XOR',
                 'ATM_SMIN', 'ATM_SMAX', 'ATM_UMIN', 'ATM_UMAX', 'ATM_CAS']

    cmd_to_name = {k.value : v for (k, v) in zip(XDM_CMD, cmd_names)}

    @property
    def fence(self):
        return self.hdr.opcode & XDM_CMD.FENCE.value

    @property
    def opcode(self):
        return self.hdr.opcode & XDM_CMD.OP_MASK.value

    @opcode.setter
    def opcode(self, cmd):
        self.hdr.opcode = cmd.value if isinstance(cmd, XDM_CMD) else cmd

    def __repr__(self):
        cmd_name = xdm_cmd.cmd_to_name[self.opcode]
        r = type(self).__name__ + '(' + cmd_name
        if self.fence:
            r += ':fence'
        r += ', {:#x}'.format(self.hdr.request_id)
        r += ')'
        return r

class xdm_cmpl_hdr(Structure):
    _fields_ = [('v',               c_u8, 1),
                ('rv1',             c_u8, 4),
                ('qd',              c_u8, 3),  # EnqA only
                ('status',          c_u8),
                ('request_id',      c_u16)
                ]

class xdm_cmpl_generic(Structure):
    _fields_ = [('hdr',             xdm_cmpl_hdr),
                ('rv1',             c_u32 * 15)
                ]

class xdm_cmpl_enqa(Structure):
    _fields_ = [('hdr',             xdm_cmpl_hdr),
                ('rv1',             c_u32 * 15)
                ]

    def __repr__(self):
        r = type(self).__name__ + '({:#x}'.format(self.hdr.request_id)
        r += ', v={}'.format(self.hdr.v)
        r += ', status={:#x}'.format(self.hdr.status)
        r += ', qd={}'.format(self.hdr.qd)
        r += ')'
        return r

class xdm_cmpl_getimm(Structure):
    _fields_ = [('hdr',             xdm_cmpl_hdr),
                ('rv1',             c_u32 * 7),
                ('payload',         c_byte * 32)
                ]

    def __repr__(self):
        r = type(self).__name__ + '({:#x}'.format(self.hdr.request_id)
        r += ', v={}'.format(self.hdr.v)
        r += ', status={:#x}'.format(self.hdr.status)
        r += ', payload="{}"'.format(bytearray(self.payload))
        r += ')'
        return r

class xdm_cmpl_atomic32(Structure):
    _fields_ = [('hdr',             xdm_cmpl_hdr),
                ('rv1',             c_u32 * 7),
                ('retval',          c_u32),
                ('rv2',             c_u32 * 7)
                ]

    def __repr__(self):
        r = type(self).__name__ + '({:#x}'.format(self.hdr.request_id)
        r += ', v={}'.format(self.hdr.v)
        r += ', status={:#x}'.format(self.hdr.status)
        r += ', retval={:#x}'.format(self.retval)
        r += ')'
        return r

class xdm_cmpl_atomic64(Structure):
    _fields_ = [('hdr',             xdm_cmpl_hdr),
                ('rv1',             c_u32 * 7),
                ('retval',          c_u64),
                ('rv2',             c_u32 * 6)
                ]

    def __repr__(self):
        r = type(self).__name__ + '({:#x}'.format(self.hdr.request_id)
        r += ', v={}'.format(self.hdr.v)
        r += ', status={:#x}'.format(self.hdr.status)
        r += ', retval={:#x}'.format(self.retval)
        r += ')'
        return r

class xdm_cmpl(Union):
    _fields_ = [('hdr',             xdm_cmpl_hdr),
                ('generic',         xdm_cmpl_generic),
                ('enqa',            xdm_cmpl_enqa),
                ('getimm',          xdm_cmpl_getimm),
                ('atomic32',        xdm_cmpl_atomic32),
                ('atomic64',        xdm_cmpl_atomic64)
                ]

    def __repr__(self):
        r = type(self).__name__ + '({:#x}'.format(self.hdr.request_id)
        r += ', v={}'.format(self.hdr.v)
        r += ', status={:#x}'.format(self.hdr.status)
        r += ')'
        return r

class XDMcompletionError(ValueError):
    '''XDM completion error'''
    def __init__(self, message, request_id, status):
        super().__init__(message)
        self.request_id = request_id
        self.status = status

class XDMqcm(Structure):
    _fields_ = [('cmd_q_base_addr',    c_u64, 64),  # byte 0x00
                ('cmpl_q_base_addr',   c_u64, 64),  # byte 0x08
                ('cmd_q_size',         c_u64, 16),  # byte 0x10
                ('rv2',                c_u64, 16),
                ('cmpl_q_size',        c_u64, 16),
                ('rv3',                c_u64, 16),
                ('local_pasid',        c_u64, 20),  # byte 0x18
                ('traffic_class',      c_u64,  4),
                ('priority',           c_u64,  1),
                ('rv4',                c_u64,  5),
                ('virt',               c_u64,  1),
                ('q_virt',             c_u64,  1),
                ('fabric_pasid',       c_u64, 20),
                ('rv5',                c_u64, 12),
                ('master_stop',        c_u64,  1),  # byte 0x20
                ('rv6',                c_u64, 63),
                ('active_cmd_cnt',     c_u64, 11),  # byte 0x28
                ('rv7',                c_u64,  4),
                ('active',             c_u64,  1),
                ('status',             c_u64,  3),
                ('rv8',                c_u64, 12),
                ('error',              c_u64,  1),
                ('rv9',                c_u64, 32),
                ('rv10',               c_u64 * 2),
                ('_stop',              c_u64, 64),  # byte 0x40
                ('rv12',               c_u64 * 7),
                ('_cmd_q_tail_idx',    c_u64, 64),  # byte 0x80
                ('rv14',               c_u64 * 7),
                ('_cmd_q_head_idx',    c_u64, 64),  # byte 0xc0
                ('rv16',               c_u64 * 7),
                ('_t_cmpl_q_tail_idx', c_u64, 64),  # byte 0x100
                ('rv17',               c_u64 * 223),
                ('xdm_cmd_buf',        xdm_cmd * 16), # byte 0x800
                ]

    @property
    def cmd_q_head_idx(self):
        mask = (1<<16) - 1
        return self._cmd_q_head_idx & mask

    @cmd_q_head_idx.setter
    def cmd_q_head_idx(self, value):
        # Revisit: not atomic
        mask64 = (1<<64) - 1
        mask = (1<<16) - 1
        cur = self._cmd_q_head_idx
        new = (cur & ~mask & mask64) | (value & mask)
        self._cmd_q_head_idx = new

    @property
    def cmd_q_tail_idx(self):
        mask = (1<<16) - 1
        return self._cmd_q_tail_idx & mask

    @cmd_q_tail_idx.setter
    def cmd_q_tail_idx(self, value):
        # Revisit: not atomic
        mask64 = (1<<64) - 1
        mask = (1<<16) - 1
        cur = self._cmd_q_tail_idx
        new = (cur & ~mask & mask64) | (value & mask)
        self._cmd_q_tail_idx = new

    @property
    def toggle_valid(self):
        return self._t_cmpl_q_tail_idx >> 31

    @toggle_valid.setter
    def toggle_valid(self, value):
        # Revisit: not atomic
        mask64 = (1<<64) - 1
        mask = 1<<31
        cur = self._t_cmpl_q_tail_idx
        new = (cur & ~mask & mask64) | ((value << 31) & mask)
        self._t_cmpl_q_tail_idx = new

    @property
    def cmpl_q_tail_idx(self):
        mask = (1<<16) - 1
        return self._t_cmpl_q_tail_idx & mask

    @cmpl_q_tail_idx.setter
    def cmpl_q_tail_idx(self, value):
        # Revisit: not atomic
        mask64 = (1<<64) - 1
        mask = (1<<16) - 1
        cur = self._t_cmpl_q_tail_idx
        new = (cur & ~mask & mask64) | (value & mask)
        self._t_cmpl_q_tail_idx = new

class XDM():
    def __init__(self, conn, cmd_ent, cmpl_ent,
                 priority=0, traffic_class=0, slice_mask=0):
        fno = conn.fno
        self.rsp_xqa = conn.do_XQUEUE_ALLOC(cmd_ent, cmpl_ent,
                                            priority, traffic_class, slice_mask)
        self.qcm_mm = mmap.mmap(fno, self.rsp_xqa.info.qcm.size,
                                offset=self.rsp_xqa.info.qcm.off)
        self.cmd_mm = mmap.mmap(fno, self.rsp_xqa.info.cmdq.size,
                                offset=self.rsp_xqa.info.cmdq.off)
        self.cmpl_mm = mmap.mmap(fno, self.rsp_xqa.info.cmplq.size,
                                 offset=self.rsp_xqa.info.cmplq.off)
        self.qcm = XDMqcm.from_buffer(self.qcm_mm, 0)
        cmd_array = xdm_cmd * self.rsp_xqa.info.cmdq.ent
        self.cmd = cmd_array.from_buffer(self.cmd_mm, 0)
        cmpl_array = xdm_cmpl * self.rsp_xqa.info.cmplq.ent
        self.cmpl = cmpl_array.from_buffer(self.cmpl_mm, 0)
        self.cur_valid = 1
        self.qcm.toggle_valid = self.cur_valid
        self.qcm._stop = 0  # Revisit: use stop, not _stop
        self.cmd_q_tail_shadow = self.qcm.cmd_q_tail_idx
        self.cmd_q_head_shadow = self.qcm.cmd_q_head_idx
        self.cmpl_q_tail_shadow = self.qcm.cmpl_q_tail_idx
        self.cmd_buf_state = [0] * 16  # a list of 16 zeros
        self.cur_buf = 0

    def buffer_cmd(self, cmd):
        # find a free buffer
        found = None
        while found is None:
            for b in range(16):
                if (self.cmd_buf_state[b] == 0):
                    found = True
                    break

        b = self.cur_buf
        self.cur_buf = b+1
        if self.cur_buf >=16:
            self.cur_buf = 0
        # mark this buffer busy
        self.cmd_buf_state[b] = 1
        # Request id greater than the number of entries indicates buffer cmd
        cmd.hdr.request_id = self.rsp_xqa.info.cmdq.ent + b

        # Copy the command into the buffer 
        # Writing byte 0 triggers the command
        cmds_64byte = [XDM_CMD.ENQA, XDM_CMD.PUT_IMM, XDM_CMD.ATM_SWAP, XDM_CMD.ATM_ADD, XDM_CMD.ATM_AND, XDM_CMD.ATM_OR, XDM_CMD.ATM_XOR, XDM_CMD.ATM_SMIN, XDM_CMD.ATM_UMIN, XDM_CMD.ATM_UMAX, XDM_CMD.ATM_CAS]
        cmds_32byte = [XDM_CMD.PUT, XDM_CMD.GET]
        cmds_16byte = [XDM_CMD.GET_IMM]
        cmds_8byte =  [XDM_CMD.NOP, XDM_CMD.SYNC]

        if cmd.opcode in cmds_64byte:
            # optimally use two 32B stores
            for n in range(7, -1, -1):
                self.qcm.xdm_cmd_buf[b].cmd_by_bytes.u64[n] = cmd.cmd_by_bytes.u64[n]
        elif cmd.opcode in cmds_32byte:
            # optimally use one 32B store
            for n in range(3, -1, -1):
                self.qcm.xdm_cmd_buf[b].cmd_by_bytes.u64[n] = cmd.cmd_by_bytes.u64[n]
        elif cmd.opcode in cmds_16byte:
            # optimally use one 16B store
            for n in range(1, -1, -1):
                self.qcm.xdm_cmd_buf[b].cmd_by_bytes.u64[n] = cmd.cmd_by_bytes.u64[n]
        elif cmd.opcode in cmds_8byte:
            # optimally use one 8B store
            self.qcm.xdm_cmd_buf[b].cmd_by_bytes.u64[0] = cmd.cmd_by_bytes.u64[0]
        else:
            print('buffer_cmd: ERROR: invalid opcode {}'.format(cmd.opcode))


    def queue_cmd(self, cmd):
        # Revisit: check for cmdq full
        t = self.cmd_q_tail_shadow
        cmd.hdr.request_id = t
        self.cmd[t] = cmd
        self.cmd_q_tail_shadow = ((self.cmd_q_tail_shadow + 1) %
                                  self.rsp_xqa.info.cmdq.ent)
        self.qcm.cmd_q_tail_idx = self.cmd_q_tail_shadow

    def queue_cmds(self, cmds):
        cnt = len(cmds)
        # Revisit: check for cmdq full
        for cmd in cmds:
            t = self.cmd_q_tail_shadow
            cmd.hdr.request_id = t
            self.cmd[t] = cmd
            self.cmd_q_tail_shadow = ((self.cmd_q_tail_shadow + 1) %
                                      self.rsp_xqa.info.cmdq.ent)
        self.qcm.cmd_q_tail_idx = self.cmd_q_tail_shadow

    def get_cmpl(self, wait=True):
        t = self.cmpl_q_tail_shadow
        try:  # Revisit: debug
            while True:  # Spin until cmpl[t] becomes valid if wait is True
                if self.cmpl[t].hdr.v == self.cur_valid:
                    break
                elif wait == False:
                    return None
        except KeyboardInterrupt:
            print('get_cmpl(t={}: KeyboardInterrupt'.format(t))
            return None
        self.cmpl_q_tail_shadow = ((self.cmpl_q_tail_shadow + 1) %
                                   self.rsp_xqa.info.cmplq.ent)
        if self.cmpl_q_tail_shadow < t:  # toggle expected valid on wrap
            self.cur_valid = self.cur_valid ^ 1
        if self.cmpl[t].hdr.status != 0:
            raise XDMcompletionError('bad status',
                                     self.cmpl[t].hdr.request_id,
                                     self.cmpl[t].hdr.status)
        return self.cmpl[t]

class rdm_cmpl_hdr(Structure):
    _fields_ = [('v',               c_u64,  1),
                ('rv1',             c_u64,  3),
                ('sgcid',           c_u64, 28),
                ('reqctxid',        c_u64, 24),
                ('rv2',             c_u64,  8)
                ]

class rdm_cmpl_enqa(Structure):
    _fields_ = [('hdr',             rdm_cmpl_hdr),
                ('rv1',             c_u32),
                ('payload',         c_byte * 52)
                ]

    def __repr__(self):
        r = type(self).__name__ + '({}'.format(gcid_to_str(self.hdr.sgcid))
        r += ', v={}'.format(self.hdr.v)
        r += ', reqctxid={:#x}'.format(self.hdr.reqctxid)
        r += ', payload="{}"'.format(bytearray(self.payload))
        r += ')'
        return r

class rdm_cmpl(Union):
    _fields_ = [('hdr',             rdm_cmpl_hdr),
                ('enqa',            rdm_cmpl_enqa)
                ]

    def __repr__(self):
        r = type(self).__name__ + '({}'.format(gcid_to_str(self.hdr.sgcid))
        r += ', v={}'.format(self.hdr.v)
        r += ', reqctxid={:#x}'.format(self.hdr.reqctxid)
        r += ')'
        return r

class RDMqcm(Structure):
    _fields_ = [('cmpl_q_base_addr',   c_u64, 64),  # byte 0x00
                ('cmpl_q_size',        c_u64, 20),  # byte 0x08
                ('rv1',                c_u64, 12),
                ('pasid',              c_u64, 20),
                ('rv2',                c_u64, 10),
                ('intr_en',            c_u64,  1),
                ('virt',               c_u64,  1),
                ('master_stop',        c_u64,  1),  # byte 0x10
                ('rv3',                c_u64, 63),
                ('active',             c_u64,  1),  # byte 0x18
                ('rv4',                c_u64, 63),
                ('rv5',                c_u64 * 4),
                ('_stop',              c_u64, 64),  # byte 0x40
                ('rv6',                c_u64 * 7),
                ('_t_cmpl_q_tail_idx', c_u64, 64),  # byte 0x80
                ('rv7',                c_u64 * 7),
                ('_cmpl_q_head_idx',   c_u64, 64),  # byte 0xc0
                ]

    @property
    def toggle_valid(self):
        return self._t_cmpl_q_tail_idx >> 31

    @toggle_valid.setter
    def toggle_valid(self, value):
        # Revisit: not atomic
        mask64 = (1<<64) - 1
        mask = 1<<31
        cur = self._t_cmpl_q_tail_idx
        new = (cur & ~mask & mask64) | ((value << 31) & mask)
        self._t_cmpl_q_tail_idx = new

    @property
    def cmpl_q_tail_idx(self):
        mask = (1<<20) - 1
        return self._t_cmpl_q_tail_idx & mask

    @cmpl_q_tail_idx.setter
    def cmpl_q_tail_idx(self, value):
        # Revisit: not atomic
        mask64 = (1<<64) - 1
        mask = (1<<20) - 1
        cur = self._t_cmpl_q_tail_idx
        new = (cur & ~mask & mask64) | (value & mask)
        self._t_cmpl_q_tail_idx = new

    @property
    def cmpl_q_head_idx(self):
        mask = (1<<20) - 1
        return self._cmpl_q_head_idx & mask

    @cmpl_q_head_idx.setter
    def cmpl_q_head_idx(self, value):
        # Revisit: not atomic
        mask64 = (1<<64) - 1
        mask = (1<<20) - 1
        cur = self._cmpl_q_head_idx
        new = (cur & ~mask & mask64) | (value & mask)
        self._cmpl_q_head_idx = new

class RDM():
    def __init__(self, conn, cmpl_ent, slice_mask=0):
        fno = conn.fno
        self.rsp_rqa = conn.do_RQUEUE_ALLOC(cmpl_ent, slice_mask)
        self.qcm_mm = mmap.mmap(fno, self.rsp_rqa.info.qcm.size,
                                offset=self.rsp_rqa.info.qcm.off)
        self.cmpl_mm = mmap.mmap(fno, self.rsp_rqa.info.cmplq.size,
                                 offset=self.rsp_rqa.info.cmplq.off)
        self.qcm = RDMqcm.from_buffer(self.qcm_mm, 0)
        cmpl_array = rdm_cmpl * self.rsp_rqa.info.cmplq.ent
        self.cmpl = cmpl_array.from_buffer(self.cmpl_mm, 0)
        self.cur_valid = 1
        self.qcm.toggle_valid = self.cur_valid
        self.qcm._stop = 0  # Revisit: use stop, not _stop
        self.cmpl_q_tail_shadow = self.qcm.cmpl_q_tail_idx
        self.cmpl_q_head_shadow = self.qcm.cmpl_q_head_idx
        self.conn = conn
        try:
            conn.poll_open(self.rsp_rqa.info.irq_vector)
            conn.epoll_start(self.rsp_rqa.info.irq_vector, select.EPOLLIN)
            # Add this RDM to the dictionary per irq_vector
            conn.rdm_per_irq_index[self.rsp_rqa.info.irq_vector].append(self)
        except FileNotFoundError:
            print('Unable to open RDM poll device\n')

    def get_cmpl(self, wait=True):
        h = self.cmpl_q_head_shadow
        try:  # Revisit: debug
            while True:  # Spin until cmpl[h] becomes valid if wait is True
                if self.cmpl[h].hdr.v == self.cur_valid:
                    break
                elif wait == False:
                    return None
        except KeyboardInterrupt:
            print('get_cmpl(h={}: KeyboardInterrupt'.format(h))
            return None
        self.cmpl_q_head_shadow = ((self.cmpl_q_head_shadow + 1) %
                                   self.rsp_rqa.info.cmplq.ent)
        if self.cmpl_q_head_shadow < h:  # toggle expected valid on wrap
            self.cur_valid = self.cur_valid ^ 1
        self.qcm.cmpl_q_head_idx = self.cmpl_q_head_shadow
        # Revisit: deal with race against HW writing new completions
        return self.cmpl[h]

    def get_poll(self):
        cmpls = list()
        handled = False
        try:
              irq_vector = self.rsp_rqa.info.irq_vector
              triggered = self.conn.triggered[irq_vector]
              print('get_poll: irq_vector is {} triggered is {}'.format(irq_vector, triggered))
              while handled == False:
                  if (self.conn.epoll[irq_vector] == None):
                      print("ERROR: epoll is None")
                      break
                  print('get_poll: calling poll')
                  events = self.conn.epoll[irq_vector].poll(1)
                  for fd, event_type in events:
                      print('event_type is {}'.format(event_type))
                      if event_type & select.EPOLLIN:
                          # Get triggered count
                          triggered = self.conn.triggered[irq_vector]
                          print('triggered is {}'.format(triggered))
                          # Loop through all RDM that have this irq_vector
                          for rdm in self.conn.rdm_per_irq_index[irq_vector]:
                              cmpls.append(rdm.get_cmpl(wait=False))
                              print('got cmpl')
                              print('poll RDM cmpl: {}'.format(cmpls))
                          handled = True
                  break
        finally:
               print('finally statement in get_poll')
#              self.conn.epoll_stop(irq_vector)
        # Write handled count
        self.conn.handled[irq_vector] = triggered
        print('handled set to {}'.format(self.conn.handled[irq_vector]))
        return cmpls

class Connection():
    def __init__(self, file, verbosity=0, index=0):
        self._file = file
        self.verbosity = verbosity
        self._index = index
        self.nop_seq = 0
        self.init = None
        self.mrreg = {}
        self.global_shared = None
        self.local_shared = None
        self.handled = None
        self.triggered = None
        self.poll_file = [None]*128
        self.epoll = [None]*128
        self.rdm_per_irq_index = defaultdict(list)

    @property
    def fno(self):
        return self._file.fileno()

    def write(self, req):
        self._index += 1  # Revisit: this isn't atomic
        req.hdr.index = self._index
        return self._file.write(req)

    def read(self, rsp):
        self._file.readinto(rsp)
        err = rsp.hdr.status
        if rsp.hdr.status < 0:
            err = abs(rsp.hdr.status)
            raise OSError(err, os.strerror(err))

    def do_handled_print(self):
        print('Handled array:')
        if (self.handled != None):
            for h in range(0, 128):
                 print('handled[{:#}]: {:#}'.format(h, self.handled[h]))
                 if (self.handled[h] != 0):
                     print('handled[{:#}]: {:#}'.format(h, self.handled[h]))

    def do_triggered_print(self):
        print('Triggered array')
        if (self.triggered != None):
            for t in range(0, 128):
                 if (self.triggered[t] != 0):
                     print('triggered[{:#}]: {:#}'.format(t, self.triggered[t]))

    def do_INIT(self):
        req = req_INIT(hdr(OP.INIT))
        self.write(req)
        rsp = rsp_INIT(hdr(OP.INIT, index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('INIT: uuid={}, local_shared_size={}, local_shared_offset={:#x}, global_shared_size={}, global_shared_offset={:#x}'.format(rsp.uuid, rsp.local_shared_size, rsp.local_shared_offset, rsp.global_shared_size, rsp.global_shared_offset))
        self.init = rsp
        self.local_shared = mmap.mmap(self.fno, rsp.local_shared_size,
                                 offset=rsp.local_shared_offset)
        self.global_shared = mmap.mmap(self.fno, rsp.global_shared_size,
                                 offset=rsp.global_shared_offset)
        self.handled = local_shared_data.from_buffer(self.local_shared, 0).handled_counter
        self.triggered = global_shared_data.from_buffer(self.global_shared, 0).triggered_counter
        return rsp

    def do_NOP(self):
        self.nop_seq += 1
        req = req_NOP(hdr(OP.NOP), self.nop_seq)
        self.write(req)
        rsp = rsp_NOP(hdr(OP.NOP, index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('NOP: seq={}'.format(rsp.seq))
        return rsp

    def do_MR_REG(self, vaddr, len, access):
        if self.verbosity:
            print('MR_REG: vaddr={:#x}, len={}, access={:#x}'.format(
                vaddr, len, access))
        req = req_MR_REG(hdr(OP.MR_REG), vaddr, len, access)
        self.write(req)
        rsp = rsp_MR_REG(hdr(OP.MR_REG, index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('MR_REG: rsp_zaddr={:#x}, pg_ps={}'.format(
                rsp.rsp_zaddr, rsp.pg_ps))
        if rsp.rsp_zaddr != ((1 << 64) - 1):
            self.mrreg[rsp.rsp_zaddr] = (req, rsp)
        return rsp

    def do_MR_FREE(self, vaddr, len, access, rsp_zaddr):
        if self.verbosity:
            print('MR_FREE vaddr={:#x}, len={}, access={:#x}, rsp_zaddr={:#x}'.format(
                vaddr, len, access, rsp_zaddr))
        req = req_MR_FREE(hdr(OP.MR_FREE), vaddr, len, access, rsp_zaddr)
        self.write(req)
        rsp = rsp_MR_FREE(hdr(OP.MR_FREE, index=req.hdr.index, rsp=True))
        self.read(rsp)
        if rsp_zaddr != ((1 << 64) - 1):
            self.mrreg.pop(rsp_zaddr)
        return rsp

    def do_RMR_IMPORT(self, uuid, rsp_zaddr, len, access):
        if self.verbosity:
            print('RMR_IMPORT: uuid={}, rsp_zaddr={:#x}, len={}, access={:#x}'.format(
                uuid, rsp_zaddr, len, access))
        req = req_RMR_IMPORT(hdr(OP.RMR_IMPORT),
                             create_uuid_bytes(uuid),
                             rsp_zaddr, len, access)
        self.write(req)
        rsp = rsp_RMR_IMPORT(hdr(OP.RMR_IMPORT, index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('RMR_IMPORT: req_addr={:#x}, offset={:#x}, pg_ps={}'.format(
                rsp.req_addr, rsp.offset, rsp.pg_ps))
        return rsp

    def do_RMR_FREE(self, uuid, rsp_zaddr, len, access, req_addr):
        if self.verbosity:
            print('RMR_FREE uuid={}, rsp_zaddr={:#x}, len={}, access={:#x}, req_addr={:#x}'.format(
                uuid, rsp_zaddr, len, access, req_addr))
        req = req_RMR_FREE(hdr(OP.RMR_FREE),
                           create_uuid_bytes(uuid),
                           rsp_zaddr, len, access, req_addr)
        self.write(req)
        rsp = rsp_RMR_FREE(hdr(OP.RMR_FREE, index=req.hdr.index, rsp=True))
        self.read(rsp)
        return rsp

    def do_UUID_IMPORT(self, uuid, uu_flags, sock):
        # Revisit: finish this - do something with sock
        req = req_UUID_IMPORT(hdr(OP.UUID_IMPORT), create_uuid_bytes(uuid), create_uuid_bytes(uuid),  uu_flags)
        self.write(req)
        rsp = rsp_UUID_IMPORT(hdr(OP.UUID_IMPORT,
                                  index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('UUID_IMPORT: uuid={}'.format(uuid))
        return rsp

    def do_UUID_FREE(self, uuid):
        req = req_UUID_FREE(hdr(OP.UUID_FREE), create_uuid_bytes(uuid))
        self.write(req)
        rsp = rsp_UUID_FREE(hdr(OP.UUID_FREE, index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('UUID_FREE: uuid={}'.format(uuid))
        return rsp

    def do_XQUEUE_ALLOC(self, cmdq_ent, cmplq_ent, EnqA_traffic_class,
                        priority, slice_mask):
        req = req_XQUEUE_ALLOC(hdr(OP.XQUEUE_ALLOC),
                               cmdq_ent, cmplq_ent, EnqA_traffic_class,
                               priority, slice_mask)
        self.write(req)
        rsp = rsp_XQUEUE_ALLOC(hdr(OP.XQUEUE_ALLOC,
                                   index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('XQUEUE_ALLOC: qcm.size={}, qcm.off={:#x}, cmdq.ent={}, cmdq.size={}, cmdq.off={:#x}, cmplq.ent={}, cmplq.size={}, cmplq.off={:#x}, slice={}, queue={}'.format(rsp.info.qcm.size, rsp.info.qcm.off, rsp.info.cmdq.ent, rsp.info.cmdq.size, rsp.info.cmdq.off, rsp.info.cmplq.ent, rsp.info.cmplq.size, rsp.info.cmplq.off, rsp.info.slice, rsp.info.queue))
        return rsp

    def do_XQUEUE_FREE(self, info):
        req = req_XQUEUE_FREE(hdr(OP.XQUEUE_FREE), info)
        self.write(req)
        rsp = rsp_XQUEUE_FREE(hdr(OP.XQUEUE_FREE,
                                  index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('XQUEUE_FREE: status={}'.format(rsp.hdr.status))

    def do_RQUEUE_ALLOC(self, cmplq_ent, slice_mask):
        req = req_RQUEUE_ALLOC(hdr(OP.RQUEUE_ALLOC), cmplq_ent, slice_mask)
        self.write(req)
        rsp = rsp_RQUEUE_ALLOC(hdr(OP.RQUEUE_ALLOC,
                                   index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('RQUEUE_ALLOC: qcm.size={}, qcm.off={:#x}, cmplq.ent={}, cmplq.size={}, cmplq.off={:#x}, slice={}, queue={}, rspctxid={} irq_vector={}'.format(rsp.info.qcm.size, rsp.info.qcm.off, rsp.info.cmplq.ent, rsp.info.cmplq.size, rsp.info.cmplq.off, rsp.info.slice, rsp.info.queue, rsp.info.rspctxid, rsp.info.irq_vector))
        return rsp

    def do_RQUEUE_FREE(self, info):
        req = req_RQUEUE_FREE(hdr(OP.RQUEUE_FREE), info)
        self.write(req)
        rsp = rsp_RQUEUE_FREE(hdr(OP.RQUEUE_FREE,
                                  index=req.hdr.index, rsp=True))
        self.read(rsp)
        if self.verbosity:
            print('RQUEUE_FREE: status={}'.format(rsp.hdr.status))

    def poll_open(self, irq_index):
        if self.poll_file[irq_index] == None:
            self.poll_file[irq_index] = open('/dev/wildcat_rdma_poll_' +
                                             str(irq_index), 'rb+',
                                             buffering=0);

    def poll_close(self, irq_index):
        if self.poll_file[irq_index] != None:
            close(self.poll_file[irq_index])

    def epoll_start(self, irq_index, event):
        print('epoll_start for index={}'.format(irq_index))
        if self.epoll[irq_index] == None:
            self.epoll[irq_index] = select.epoll()
            self.epoll[irq_index].register(self.poll_file[irq_index], event)

    def epoll_stop(self, irq_index):
        print('epoll_stop for index={}'.format(irq_index))
        if self.epoll[irq_index] != None:
            self.epoll[irq_index].unregister(self.poll_file[irq_index])
            self.epoll[irq_index].close()
            self.epoll[irq_index] = None

def create_uuid_bytes(uuid):
    # Revisit: there must be a better way to do this
    return (c_byte * len(uuid.bytes))(*list(uuid.bytes))

def mmap_vaddr_len(mm):
    # based on code here:
    # https://stackoverflow.com/questions/33977369/get-address-of-read-only-mmap-object?lq=1
    obj = py_object(mm)
    vaddr = c_void_p()
    length = c_ssize_t()
    # Revisit: this uses the deprecated "old buffer protocol"
    pythonapi.PyObject_AsReadBuffer(obj, byref(vaddr), byref(length))
    return (vaddr.value, length.value)

def invalidate(vaddr, length, fence):
    mcommit.invalidate(c_void_p(vaddr), c_size_t(length), c_bool(fence))

def flush(vaddr, length, fence):
    mcommit.flush(c_void_p(vaddr), c_size_t(length), c_bool(fence))

def commit(vaddr, length, fence):
    mcommit.commit(c_void_p(vaddr), c_size_t(length), c_bool(fence))
