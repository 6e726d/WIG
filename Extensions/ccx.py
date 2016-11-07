#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
#
# BSD 3-Clause License
#
# Copyright (c) 2016, Andrés Blanco (6e726d@gmail.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of WIG nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import struct
import socket


CISCO_CCX_IE_DEVICE_NAME_ID = 0x85
CISCO_CCX_IE_IP_ADDRESS_ID = 0x95


class InvalidCCXInformationElement(Exception):
    """Invalid CCX Information Element Exception."""
    pass


class CiscoCCX85InformationElement(object):

    TLV_HEADER_SIZE = 2
    DEVICE_NAME_OFFSET = 10 + TLV_HEADER_SIZE
    DEVICE_NAME_VALUE_SIZE = 16
    ASSOCIATED_CLIENTS_OFFSET = 26 + TLV_HEADER_SIZE

    def __init__(self, buff):
        self.buffer = buff
        self.buffer_length = len(buff)
        self.__device_name__ = str()
        self.__associated_clients__ = int()
        self.__do_basic_verification__()
        self.__process_buffer__()

    def get_device_name(self):
        """Return the device name value in the information element."""
        return self.__device_name__

    def get_associated_clients(self):
        """Return the associated clients value in the information element."""
        return self.__associated_clients__

    def __do_basic_verification__(self):
        """Verify if the buffer has the minimal length necessary."""
        tlv_id = struct.unpack("B", self.buffer[0])[0]
        tlv_size = struct.unpack("B", self.buffer[1])[0]
        if not tlv_id == CISCO_CCX_IE_DEVICE_NAME_ID:
            raise InvalidCCXInformationElement()
        if tlv_size < self.ASSOCIATED_CLIENTS_OFFSET or self.buffer_length < self.ASSOCIATED_CLIENTS_OFFSET:
            raise InvalidCCXInformationElement()

    def __process_buffer__(self):
        """Process data buffer and get device name and associated clients."""
        aux_buff = self.buffer[self.DEVICE_NAME_OFFSET:self.DEVICE_NAME_OFFSET+self.DEVICE_NAME_VALUE_SIZE]
        self.__device_name__ = struct.unpack("16s", aux_buff)[0].replace("\x00", "")
        self.__associated_clients__ = struct.unpack("B", self.buffer[self.ASSOCIATED_CLIENTS_OFFSET])[0]


class CiscoCCX95InformationElement(object):

    TLV_HEADER_SIZE = 2
    TLV_MIN_SIZE = 10
    IP_ADDRESS_OFFSET = 4 + TLV_HEADER_SIZE
    IP_ADDRESS_SIZE = 4

    def __init__(self, buff):
        self.buffer = buff
        self.buffer_length = len(buff)
        self.__ip_address__ = str()
        self.__do_basic_verification__()
        self.__process_buffer__()

    def get_ip_address(self):
        """Return the IP address value in the information element."""
        return self.__ip_address__

    def __do_basic_verification__(self):
        """Verify if the buffer has the minimal length necessary."""
        tlv_id = struct.unpack("B", self.buffer[0])[0]
        tlv_size = struct.unpack("B", self.buffer[1])[0]
        if not tlv_id == CISCO_CCX_IE_IP_ADDRESS_ID:
            raise InvalidCCXInformationElement()
        if tlv_size < self.TLV_MIN_SIZE:
            raise InvalidCCXInformationElement()

    def __process_buffer__(self):
        """Process data buffer and get ip address."""
        buff = self.buffer[self.IP_ADDRESS_OFFSET:self.IP_ADDRESS_OFFSET+self.IP_ADDRESS_SIZE]
        self.__ip_address__ = socket.inet_ntoa(buff)


if __name__ == "__main__":
    ccx_85_ie = str()
    ccx_85_ie += "\x85\x1e\x00\x00\x8f\x0a\x0f\x00\xff\x03\x40\x00\x46\x41\x46\x41"
    ccx_85_ie += "\x46\x41\x46\x41\x46\x41\x46\x41\x2d\x41\x50\x00\x00\x00\x00\x3c"
    ccx85 = CiscoCCX85InformationElement(ccx_85_ie)
    print "Device Name: %s" % ccx85.get_device_name()
    print "Associated Clients: %d" % ccx85.get_associated_clients()

    ccx_95_ie = str()
    ccx_95_ie += "\x95\x0a\x00\x40\x96\x00\xc0\xa8\x03\x01\x00\x00"
    ccx95 = CiscoCCX95InformationElement(ccx_95_ie)
    print "IP Address: %s" % ccx95.get_ip_address()
