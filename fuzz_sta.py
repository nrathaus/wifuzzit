#!/usr/bin/env python

import socket
import time
import logging

import boofuzz

from ap_requests import STA_MAC, list_ies, mac2str, ouis
from ap_settings import FNAME, IFACE
from sta_settings import LISTEN_TIME

ETH_P_ALL = 3

# Assume that wireless card is in monitor mode on appropriate channel
# Saves from lot of dependencies (lorcon, pylorcon...)


def listen(s):
    """
    Returns whenever STA active scanning is detected.
    """

    def isscan(pkt):
        """isscan"""
        if len(pkt) >= 24:
            if pkt[0] == "\x40" and pkt[10:16] == mac2str(STA_MAC):
                return True
        return False

    logging.info(f"waiting for active scanning from {STA_MAC}")
    while True:
        ans = s.recv(1024)
        answered = isscan(ans)
        if answered:
            logging.info(f"active scanning detected from {STA_MAC}")
            return True


def is_alive():
    """is_alive"""

    def isscan(pkt):
        """isscan"""
        if len(pkt) >= 24:
            if pkt[0] == "\x40" and pkt[10:16] == mac2str(STA_MAC):
                return True
        return False

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((IFACE, ETH_P_ALL))

    alive = False
    logging.info(f"waiting for active scanning from {STA_MAC}")
    start_time = time.time()

    while time.time() - start_time < LISTEN_TIME:
        ans = s.recv(1024)
        if isscan(ans):
            alive = True
            break

    return alive


# Defining the transport protocol
sess = boofuzz.Session(
    session_filename=FNAME,
    # proto="wifi",
    # repeat_time=REPEAT_TIME,
    # timeout=5.0,
    sleep_time=0,
    # skip=SKIP,
)

connection = boofuzz.SocketConnection(
    host="wlan0",
    proto="raw-l2",
    ethernet_proto=socket.htons(ETH_P_ALL),
    send_timeout=5.0,
    recv_timeout=5.0,
)

connection.wifi_dev = "wlan0"
# Defining the target
target = boofuzz.Target(connection=connection)

# Defining the instrumentation
# target.procmon = instrumentation.external(post=is_alive)

# Adding the listen() function for target monitoring
sess.pre_send = listen

# Adding the IFACE for socket binding
sess.wifi_iface = IFACE

# Adding the target to the fuzzing session
sess.add_target(target)

# Adding tests
sess.connect(boofuzz.s_get("ProbeResp: Most Used IEs"))

for ie in list_ies:
    sess.connect(boofuzz.s_get(f"ProbeResp: IE {ie}"))

sess.connect(boofuzz.s_get("ProbeResp: Malformed"))

for type_subtype in range(256):
    sess.connect(boofuzz.s_get(f"Fuzzy: Malformed {type_subtype}"))

for oui in ouis:
    sess.connect(boofuzz.s_get(f"ProbeResp: Vendor Specific {oui}"))

for method in ["WPA-PSK", "RSN-PSK", "WPA-EAP", "RSN-EAP"]:
    sess.connect(boofuzz.s_get(f"ProbeResp: {method} Fuzzing"))

# Launching the fuzzing campaign
sess.fuzz()
