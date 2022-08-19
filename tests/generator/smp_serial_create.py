#!/usr/bin/env python3
#

import sys

from enum import Enum
import copy
import struct

import cbor
import base64
from crc import CrcCalculator, Crc16

from argparse import ArgumentParser


class MgmtOp(Enum):
    READ      = 0
    READ_RSP  = 1
    WRITE     = 2
    WRITE_RSP = 3


class MgmtGroup(Enum):
    OS     = 0
    IMAGE  = 1
    STAT   = 2
    CONFIG = 3
    LOG    = 4
    CRASH  = 5
    SPLIT  = 6
    RUN    = 7
    FS     = 8
    PERUSER = 64



class MgmtHeader:

    # op:3, flags, len, group, seq, id
    fmt = '!BBHHBB'
    size = 8

    @staticmethod
    def decode(b):
        t = struct.unpack_from(MgmtHeader.fmt, b)
        return MgmtHeader(t[0], t[3], t[5], length=t[2], seq=t[4], flags=t[1])

    def __init__(self, op, group, nh_id, length=0, seq=0, flags=0, strict=False):
        if not strict:
            try:
                self.op = MgmtOp(op)
            except ValueError:
                self.op = int(op) & 0xff
        else:
            self.op = MgmtOp(op)
        self.flags = flags
        self.length = length
        if not strict:
            try:
                self.group = MgmtGroup(group)
            except ValueError:
                self.group = int(group) & 0xffff
        else:
            self.group = MgmtGroup(group)
        self.seq = seq
        self.id = nh_id

        if self.id is None:
            try:
                self.id = nh_id.value
            except AttributeError:
                self.id = int(nh_id)


    def encode(self):
        try:
            id = self.id.value
        except AttributeError:
            id = self.id

        try:
            op = self.op.value
        except AttributeError:
            op = self.op

        try:
            grp = self.group.value
        except AttributeError:
            grp = self.group

        return struct.pack(MgmtHeader.fmt,
            op,
            self.flags,
            self.length,
            grp,
            self.seq,
            id
        )

    def __str__(self):
        return '{}(op:{} group:{} id:{} len:{} seq:{} flags:{})'.format(self.__class__.__name__,
            self.op, self.group, self.id, self.length, self.seq, self.flags)

    def __copy__(self):
        return self.__class__(self.op, self.group, self.id, self.length, self.seq, self.flags)


class SMPPacket:

    def __init__(self, hdr, payload):
        self.hdr = copy.copy(hdr)
        self.payload = payload


    def encode(self, seq=0):

        payload_encoded = cbor.dumps(self.payload)

        self.hdr.length = len(payload_encoded)

        if self.hdr.seq != 0:
            self.hdr.seq = seq
        hdr_encoded = self.hdr.encode()

        return hdr_encoded + payload_encoded

    def encode_frag(self, frag_size, seq=0):
        enc = self.encode(seq=seq)
        frags = []
        # prevent endless loop, mtu should be higher than that in reality
        if frag_size < 8:
            raise ValueError("frag_size should be at least 8")

        while enc:
            frags.append(enc[:frag_size])
            enc = enc[frag_size:]
        return frags

    def __str__(self):
        return f"hdr:{self.hdr} pl:{self.payload}"



def sixteen(data):
    """\
    yield tuples of hex and ASCII display in multiples of 16. Includes a
    space after 8 bytes and (None, None) after 16 bytes and at the end.
    """
    n = 0
    for bi in data:
        b = bytes(bytearray([bi]))

        yield ('{:02x} '.format(ord(b)), b.decode('ascii') if b' ' <= b < b'\x7f' else '.')
        n += 1
        if n == 8:
            yield (' ', '')
        elif n >= 16:
            yield (None, None)
            n = 0
    if n > 0:
        while n < 16:
            n += 1
            if n == 8:
                yield (' ', '')
            yield ('   ', ' ')
        yield (None, None)


def hexdump_lines(data):
    """yield lines with hexdump of data"""
    values = []
    ascii = []
    offset = 0
    for h, a in sixteen(data):
        if h is None:
            yield (offset, ''.join(values), ''.join(ascii))
            del values[:]
            del ascii[:]
            offset += 0x10
        else:
            values.append(h)
            ascii.append(a)


def hexdump(data):

    for addr, h, a in hexdump_lines(data):
        print(f"{addr:08x}:  {h} |{a}|", file=sys.stderr)


def output(*data):
    print(*data)

def cdump(data: bytes, output="hex", pre=None, indent="\t", end=';'):

    if pre:
        lines = [indent + pre]
    else:
        lines = []

    for addr, h, a, in hexdump_lines(data):
        if output == "hex":
            s = '\\x' + '\\x'.join(h.split())
        elif output == "ascii":
            # need to properly encode ascii vs escapes
            # always do full line due to c hex escape rules (cannot mix escaped + ascii)
            bs = h.split()
            l = len(bs)
            dohex = False
            extra_newline = ""
            for idx, c in enumerate(a):
                if c == '.' and bs[idx] != "2e": # 2e is literal .
                    if idx == (l - 1) and bs[idx] == '0a':
                    # if idx == (l - 1):
                        # print("foo: ", c, type(c), bs[idx], file=sys.stderr)
                        # make exception for single newline at end of line
                        extra_newline = '" "\\x0a'
                    else:
                        dohex = True
                        break
            if dohex:
                s = '\\x' + '\\x'.join(bs)

            else:
                if extra_newline:
                    s = a[:len(bs)-1] + extra_newline
                else:
                    s = a[:len(bs)]

        else: # do 'hex'
            s = '\\x'.join(h.split())

        lines.append(f'{indent}"{s}"')

    text = '\n'.join(lines) + end
    return text


def cdump2(data: bytes, var="data", split_first_hex=0):

    l = len(data)
    ind = f"{INDENT}\t"
    pre = f"{INDENT}const uint8_t {var}[{l}] = "
    if split_first_hex > 0:
        if l > split_first_hex:
            endh = ""
        else:
            endh = ";"
        text = cdump(data[:split_first_hex], "hex", indent=ind, end=endh) + "\n"
        if l > split_first_hex:
            text += cdump(data[split_first_hex:], "ascii", indent=ind)

    else:
        text = cdump(data, "ascii", indent=ind)

    output(pre)
    output(text)


MCUMGR_SHELL_HDR_PKT = b'\x06\x09'
MCUMGR_SHELL_HDR_DATA = b'\x04\x14'
MCUMGR_SHELL_MAX_FRAME = 127

# can set to 0 to generate data with crc len not included (older zephyr bug)
# for testing workaround
MCUMGR_SHELL_CRC_LEN = 2

CRC_INIT = 0


def smp_serial_chunk(smp_frag_data):

    # crc and len are calculated over plain data
    # crc and len are then also base64 encoded, adding 2 bytes each to len

    l = len(smp_frag_data) + MCUMGR_SHELL_CRC_LEN
    len_bin = struct.pack("!H", l)

    crc_calculator = CrcCalculator(Crc16.CCITT)

    crc = struct.pack("!H", crc_calculator.calculate_checksum(smp_frag_data))

    data = len_bin + smp_frag_data + crc
    benc = base64.b64encode(data)

    hexdump(data)
    hexdump(benc)
    # length of base 64 encoded data
    s_pkt_len = len(benc)

    # maximum chunk data length
    datalen = MCUMGR_SHELL_MAX_FRAME - 3 # 2 SOF, 1 newline

    # need to split one less for newline
    chunks = []
    while benc:
        sof = MCUMGR_SHELL_HDR_PKT if not chunks else MCUMGR_SHELL_HDR_DATA

        chunks.append(sof + benc[:datalen] + b'\n')
        benc = benc[datalen:]
        assert len(chunks[-1]) <= MCUMGR_SHELL_MAX_FRAME

    return chunks



#SMP_CBOR_PAYLOAD = {"r": "1234567890" * 5}
#SMP_HDR = MgmtHeader(3, 0, 0, strict=True)
#SMP_FRAG_SIZE = 250


SMP_CBOR_PAYLOAD = {"r": "1234567890" * 17 + "123456789"}
# SMP_CBOR_PAYLOAD = {"r": "1234567890" * 7 + "1234567"}
SMP_HDR = MgmtHeader(MgmtOp.WRITE_RSP, MgmtGroup.OS, 0, strict=True)
SMP_FRAG_SIZE = 256



VERBOSE = False
INDENT = '\t'
INCLUDE_FRAGMENT = False

def main():

    smp_hdr = copy.copy(SMP_HDR)
    smp_pl = copy.deepcopy(SMP_CBOR_PAYLOAD)
    frag_size = SMP_FRAG_SIZE
    incl_frag = INCLUDE_FRAGMENT

    if VERBOSE:
        print("hdr    :", smp_hdr, file=sys.stderr)
        print("payload:", smp_pl, file=sys.stderr)

    output(f"{INDENT}/* {smp_hdr}")
    output(f"{INDENT}   payload")
    output(f"{INDENT}   {SMP_CBOR_PAYLOAD}")
    output(f"{INDENT}   max fragment size: {frag_size} */")

    smp_pkt = SMPPacket(smp_hdr, smp_pl)
    if VERBOSE:
        print("pkt:", smp_pkt, file=sys.stderr)

    enc = smp_pkt.encode()

    if VERBOSE:
        print("enc:", enc, file=sys.stderr)

        hexdump(enc)

    output(f"{INDENT}/* Full SMP packet */")

    cdump2(enc, "exp_rx_data", 8)

    frags = smp_pkt.encode_frag(frag_size=frag_size)

    num_frags = 0
    num_chunks = 0
    for idx, frag in enumerate(frags):

        num_frags += 1
        if VERBOSE:
            hexdump(frag)

        if incl_frag:
            output(f"{INDENT}/* SMP fragment", idx, " */")

            if idx == 0: # split of hex header on first fragment
                cdump2(frag, f"frag{idx}", 8)
            else:
                cdump2(frag, f"frag{idx}", 0)

        chunks = smp_serial_chunk(frag)
        for cidx, chunk in enumerate(chunks):
            num_chunks += 1
            output(f"{INDENT}/* SMP serial fragment {idx} chunk: {cidx} */")
            if VERBOSE:
                hexdump(chunk)
            # split of chunk SOF (bytes) as hex
            cdump2(chunk, f"chunk_{idx}_{cidx}", 2)




if __name__ == "__main__":
    main()
