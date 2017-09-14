#! /usr/bin/python

import rlcompleter
import readline
readline.parse_and_bind('tab:complete')

import struct
import os
import sys
from collections import namedtuple

from pprint import pprint

pcap_header_struct = 'IHHIIII'
pcap_header_tup = namedtuple('PCAP_HEADER_LINE', ['magic_number',
                                                  'major_version_number',
                                                  'minor_version_number',
                                                  'GMT_to_location',
                                                  'accuracy_of_timestamps',
                                                  'max_length_captured_packets',
                                                  'data_link_type'])
pkt_struct = 'IIII'
pkt_tup = namedtuple('PKT', ['timestamp_seconds',
                             'timestamp_microseconds',
                             'number_octets_saved',
                             'actual_length_of_packet'])

########## Basic functions ##########


def byTime(elem):
    return elem.pkt_tup.timestamp_seconds


def fileHeader(file_handle):
    assert file_handle.tell() == 0, "Not at beginning of file"
    header = file_handle.read(24)
    return header, pcap_header_tup(*struct.unpack(pcap_header_struct, header))


class Parser:

    @staticmethod
    def form(result):
        return str(bytearray(result))

    @staticmethod
    def ipaddr(result):
        x = [str(i) for i in result]
        return ".".join(x)

    @staticmethod
    def _process_icmp(self):
        self.L4 = 'ICMP'

    @staticmethod
    def _process_tcp(self):
        self.L4 = 'TCP'
        self.L4_TCP_Spt = struct.unpack_from(
            endian + 'H', self.raw, offset=self.L4_start + 0)[0]
        self.L4_TCP_Dpt = struct.unpack_from(
            endian + 'H', self.raw, offset=self.L4_start + 2)[0]
        self.L4_TCP_Seq = struct.unpack_from(
            endian + 'I', self.raw, offset=self.L4_start + 4)[0]
        self.L4_TCP_Ack = struct.unpack_from(
            endian + 'I', self.raw, offset=self.L4_start + 8)[0]
        self.L4_TCP_Length = struct.unpack_from(
            'B', self.raw, offset=self.L4_start + 12)[0] / 16 * 4
        self.L5_start = self.L4_start + self.L4_TCP_Length

    @staticmethod
    def _process_udp(self):
        self.L4 = 'UDP'
        self.L4_UDP_Spt = struct.unpack_from(
            endian + 'H', self.raw, offset=self.L4_start + 0)[0]
        self.L4_UDP_Dpt = struct.unpack_from(
            endian + 'H', self.raw, offset=self.L4_start + 2)[0]
        self.L4_UDP_Length = struct.unpack_from(
            endian + 'H', self.raw, offset=self.L4_start + 4)[0]
        self.L4_UDP_Checksum = Parser.form(
            struct.unpack_from('2B', self.raw, offset=self.L4_start + 6))
        self.L5_start = self.L4_start + 8

    @staticmethod
    def _data(self):
        if not hasattr(self, 'L5_start'):
            return
        return self.raw[self.L5_start:]

########## PKT Class ##########


class PKT:

    def __init__(self, file_handle):
        self.header = file_handle.read(16)
        self.pkt_tup = pkt_tup(
            *struct.unpack(pkt_struct, self.header))
        self.raw = file_handle.read(self.pkt_tup.number_octets_saved)
        self.process_l2()
        self.process_l3()
        self.process_l4()

    def process_l2(self):
        self.MAC_dst = Parser.form(
            struct.unpack_from('6B', self.raw, offset=0))
        self.MAC_src = Parser.form(
            struct.unpack_from('6B', self.raw, offset=6))
        self.L2test = Parser.form(
            struct.unpack_from('2B', self.raw, offset=12))

        if self.L2test.startswith('\x88\xa8'):
            self.L3_start = 20
        elif self.L2test.startswith('\x81\x00'):
            self.L3_start = 16
        elif self.L2test == '\x08\x00':
            self.L3_start = 14
        else:
            # If not IP, just return
            return
        del self.L2test

    def process_l3(self):
        if not hasattr(self, 'L3_start'):
            return
        l3_off = self.L3_start
        self.L3_type_size = struct.unpack_from('B', self.raw, offset=l3_off)[0]
        self.L3_type = self.L3_type_size / 16
        self.L3_header_size = self.L3_type_size % 16

        self.IPsrc = Parser.ipaddr(struct.unpack_from(
            '4B', self.raw, offset=l3_off + 12))
        self.IPdst = Parser.ipaddr(struct.unpack_from(
            '4B', self.raw, offset=l3_off + 16))
        self.IP_TTL = struct.unpack_from('B', self.raw, offset=l3_off + 8)[0]
        self.IPprotocol = struct.unpack_from(
            'B', self.raw, offset=l3_off + 9)[0]

        self.L4_start = l3_off + (self.L3_header_size * 4)

    def process_l4(self):
        if not hasattr(self, 'IPprotocol'):
            return
        if self.IPprotocol == 6:
            Parser._process_tcp(self)
        if self.IPprotocol == 1:
            Parser._process_icmp(self)
        if self.IPprotocol == 17:
            Parser._process_udp(self)

    def data(self):
        return Parser._data(self)

########## PKT Class Ends ##########

########## Helper Generators ##########


def read_pkts(file_handle, end):
    file_handle.seek(24)  # Place at the start of the file
    while file_handle.tell() != end:
        yield PKT(file_handle)
    file_handle.seek(24)  # Return back to the start


def ip_pkts(file_handle, end):
    return (x for x in read_pkts(file_handle, end) if hasattr(x, 'L3_start'))


def udp_pkts(file_handle, end):
    return (x for x in ip_pkts(f, end) if hasattr(x, 'L4') and x.L4 == 'UDP')


def tcp_pkts(file_handle, end):
    return (x for x in ip_pkts(f, end) if hasattr(x, 'L4') and x.L4 == 'TCP')


def icmp_pkts(file_handle, end):
    return (x for x in ip_pkts(f, end) if hasattr(x, 'L4') and x.L4 == 'ICMP')


def ip_sets(gen):
    SRC = set()
    DST = set()
    for i in gen:
        SRC.add(i.IPsrc)
        DST.add(i.IPdst)
    return (sorted(list(SRC)), sorted(list(DST)))


def write_pcap(gen, filename='test'):
    with open(filename + '.pcap', 'wb') as g:
        g.write(pcap_header_raw)
        for i in gen:
            g.write(i.header)
            g.write(i.raw)

########## Helper Generators End ##########

########## Main function ##########

if len(sys.argv) == 2:
    filename = sys.argv[1]

# filename = './'
file_list = []

if filename[-2:] == "/*":
    file_list = next(os.walk(filename[0:-2]))[2]
else:
    file_list.append(filename)

# Clean filename list
for f in file_list:
    if not f.endswith('.pcap'):
        file_list.remove(f)

f = open(file_list[0], 'rb')
f.seek(0, 2)
end = f.tell()
f.seek(0)

total = []
pcap_header_raw, PCAP_Header = fileHeader(f)
if struct.unpack('<I', pcap_header_raw[0:4])[0] < \
   struct.unpack('>I', pcap_header_raw[0:4])[0]:
    endian = '<'
else:
    endian = '>'

print("File opened = f")
print("pcap_header_raw = Raw header")
print('')
print("Options to query:  Creates Generators")
print("ip_pkts(file_handle, end)")
print("udp_pkts(file_handle, end)")
print("tcp_pkts(file_handle, end)")
print("icmp_pkts(file_handle, end)")
print("--------------------------")
print("Create ip_sets:")
print("ip_sets(gen) -> (SRC, DST)")
print("To write out pcaps: (will be appended with .pcap)")
print("write_pcap(gen, filename='test'")
print('')


# for pcap_file in file_list:
#    with open(pcap_file, 'rb') as f:
