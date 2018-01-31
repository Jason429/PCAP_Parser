#! /usr/bin/python

import rlcompleter
import readline
import struct
import os
import sys

from collections import namedtuple
from pprint import pprint

readline.parse_and_bind('tab:complete')

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

filename = sys.argv[1]
