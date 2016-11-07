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


import os
import fcntl
import struct
import socket


SYS_NET_PATH = "/sys/class/net/"
PHY_80211_FILENAME = "phy80211"


# linux/if.h
IFNAMSIZ = 16
# linux/wireless.h
SIOCSIWFREQ = 0x8B04  # Set Channel Frequency (Hz)
SIOCGIWFREQ = 0x8B05  # Get Channel Frequency (Hz)

# 802.11 Frequency MHz
FREQUENCY_DELTA = 5
BG_BASE_FREQUENCY = 2407
BG_LOWER_FREQUENCY = 2412
BG_UPPER_FREQUENCY = 2472
BG_CH14_FREQUENCY = 2484
A_BASE_FREQUENCY = 5000
A_LOWER_FREQUENCY = 5170
A_UPPER_FREQUENCY = 5825


class InvalidIEE80211Channel(Exception):
    pass


def get_network_interfaces():
    """Returns a list with network interfaces."""
    return os.listdir(SYS_NET_PATH)


def get_wireless_interfaces():
    """Returns a list with wireless network interfaces."""
    ifaces = list()
    for iface in get_network_interfaces():
        iface_sys_path = "%s%s" % (SYS_NET_PATH, iface)
        if PHY_80211_FILENAME in os.listdir(iface_sys_path):
            ifaces.append(iface)
    return ifaces


def get_interface_channel(iface):
    """Returns channel for a wireless network interface."""
    sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_data = fcntl.ioctl(sd.fileno(), SIOCGIWFREQ, struct.pack('256s', iface[:IFNAMSIZ-1]))[IFNAMSIZ:]
    freq = struct.unpack("I", raw_data[0:4])[0]
    return get_channel_from_frequency(freq)


def get_channel_from_frequency(freq):
    """Returns channel for a specific frequency."""
    if (freq >= BG_LOWER_FREQUENCY) and (freq <= BG_UPPER_FREQUENCY):
        return (freq - BG_BASE_FREQUENCY) / FREQUENCY_DELTA
    elif freq == BG_CH14_FREQUENCY:
        return 14
    elif (freq >= A_LOWER_FREQUENCY) and (freq <= A_UPPER_FREQUENCY):
        return (freq - A_BASE_FREQUENCY) / FREQUENCY_DELTA
    raise InvalidIEE80211Channel()
