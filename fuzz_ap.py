#!/usr/bin/env python

import socket
import time

import logging

import boofuzz

from ap_requests import AUTH_REQ_OPEN, DEAUTH, list_ies, mac2str, ouis
from ap_settings import (
    AP_CONFIG,
    AP_MAC,
    CRASH_RETRIES,
    DELAY_REBOOT,
    FNAME,
    IFACE,
    STA_MAC,
    STATE_WAIT_TIME,
)

# Assume that wireless card is in monitor mode on appropriate channel
# Saves from lot of dependencies (lorcon, pylorcon...)

ETH_P_ALL = 3


def is_alive():
    def isresp(pkt):
        resp = False
        if (
            len(pkt) >= 30
            and pkt[0] == "\xB0"
            and pkt[4:10] == mac2str(STA_MAC)
            and pkt[28:30] == "\x00\x00"
        ):
            resp = True
        return resp

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((IFACE, ETH_P_ALL))

    logging.info("checking aliveness of fuzzed access point %s" % AP_MAC)

    retries = CRASH_RETRIES
    alive = False

    while retries:
        s.send(AUTH_REQ_OPEN)

        start_time = time.time()
        while (time.time() - start_time) < 1:
            ans = s.recv(1024)
            alive = isresp(ans)
            if alive:
                s.send(DEAUTH)
                s.close()
                if retries != CRASH_RETRIES:
                    logging.info(
                        "retried authentication %d times" % (CRASH_RETRIES - retries),
                    )
                return alive

        retries -= 1

    s.close()

    return alive


def check_alive(s):
    def isresp(pkt):
        resp = False
        if (
            len(pkt) >= 30
            and pkt[0] == "\xB0"
            and pkt[4:10] == mac2str(STA_MAC)
            and pkt[28:30] == "\x00\x00"
        ):
            resp = True
        return resp

    logging.info("checking aliveness of fuzzed access point %s" % AP_MAC)

    while True:
        s.send(AUTH_REQ_OPEN)
        start_time = time.time()
        while (time.time() - start_time) < 1:
            alive = isresp(s.recv(1024))
            if alive:
                return alive
        logging.info("waiting for the access point to be up")
        time.sleep(DELAY_REBOOT)


def pass_state(s):
    """ """
    return True


def clean_state(s):
    s.send(DEAUTH)
    logging.info("sending deauthentication to come back to initial state")


# shameless ripped from scapy
# def hexdump(x):
#     x = str(x)
#     l = len(x)
#     i = 0
#     while i < l:
#         print("%04x  " % i)
#         for j in range(16):
#             if i + j < l:
#                 print("%02X" % ord(x[i + j]))
#             else:
#                 print("  ")
#             if j % 16 == 7:
#                 print("")
#         print(" ")
#         print(x[i : i + 16])
#         i += 16


def check_auth(session, node, edge, sock):
    def isresp(pkt):
        resp = False
        if (
            len(pkt) >= 30
            and pkt[0] == "\xB0"
            and pkt[4:10] == mac2str(STA_MAC)
            and pkt[28:30] == "\x00\x00"
        ):
            resp = True
        return resp

    start_time = time.time()
    while (time.time() - start_time) < STATE_WAIT_TIME:
        pkt = sock.recv(1024)
        ans = isresp(pkt)
        if ans:
            logging.info("authentication successfull with %s" % AP_MAC)
            return

    logging.info("authentication not successfull with %s" % AP_MAC)

    if session.fuzz_node.mutant != None:
        # print "XXXXX : session.fuzz_node.name %s" % session.fuzz_node.name
        # print "XXXXX : session.fuzz_node.mutant_index %d" % session.fuzz_node.mutant_index
        # print "XXXXX : session.fuzz_node.mutant.mutant_index %d" % session.fuzz_node.mutant.mutant_index
        # print "XXXXX : session.fuzz_node.num_mutations() %d" % session.fuzz_node.num_mutations()
        # print "XXXXX : session.total_mutant_index %d" % session.total_mutant_index
        logging.info("re-trying the current test case")
        session.fuzz_node.mutant_index -= 1
        session.fuzz_node.mutant.mutant_index -= 1
        session.total_mutant_index -= 1


def check_asso(session, node, edge, sock):
    def isresp(pkt):
        resp = False
        if (
            len(pkt) >= 30
            and pkt[0] == "\x10"
            and pkt[4:10] == mac2str(STA_MAC)
            and pkt[26:28] == "\x00\x00"
        ):
            resp = True
        return resp

    start_time = time.time()
    while (time.time() - start_time) < STATE_WAIT_TIME:
        pkt = sock.recv(1024)
        ans = isresp(pkt)
        if ans:
            logging.info("association successfull with %s" % AP_MAC)
            return

    logging.info("association not successfull with %s" % AP_MAC)
    if session.fuzz_node.mutant != None:
        # print "XXXXX : session.fuzz_node.name %s" % session.fuzz_node.name
        # print "XXXXX : session.fuzz_node.mutant_index %d" % session.fuzz_node.mutant_index
        # print "XXXXX : session.fuzz_node.mutant.mutant_index %d" % session.fuzz_node.mutant.mutant_index
        # print "XXXXX : session.fuzz_node.num_mutations() %d" % session.fuzz_node.num_mutations()
        # print "XXXXX : session.total_mutant_index %d" % session.total_mutant_index
        logging.info("re-trying the current test case")
        session.fuzz_node.mutant_index -= 1
        session.fuzz_node.mutant.mutant_index -= 1
        session.total_mutant_index -= 1


###############

# Defining the transport protocol
sess = boofuzz.Session(
    session_filename=FNAME,
    sleep_time=0.1,
)

# Defining the target
connection = boofuzz.SocketConnection(
    host="wlan0",
    proto="wifi",
    ethernet_proto=socket.htons(ETH_P_ALL),
    send_timeout=5.0,
    recv_timeout=5.0,
)

connection.wifi_dev = "wlan0"
target = boofuzz.Target(connection=connection)

# Adding the detect_crash function for target monitoring
# target.procmon = instrumentation.external(post=is_alive)

# Adding a check for alive of access point
sess.pre_send = check_alive

# Adding a deauth send to come back to initial state
sess.post_send = clean_state

# Adding the IFACE for socket binding
sess.wifi_iface = IFACE

# Adding the target to the fuzzing session
sess.add_target(target)

# Fuzzing State "Not Authenticated, Not Associated"

sess.connect(boofuzz.s_get("AuthReq: Open"))

for type_subtype in range(256):  # 256
    sess.connect(boofuzz.s_get("Fuzzy 1: Malformed %d" % type_subtype))

# Fuzzing State "Authenticated, Not Associated"
sess.connect(
    boofuzz.s_get("AuthReq: Open"),
    boofuzz.s_get("AssoReq: Garbage"),
    callback=check_auth,
)  # Checking Authentication
sess.connect(
    boofuzz.s_get("AuthReq: Open"), boofuzz.s_get("AssoReq: Open"), callback=check_auth
)  # Checking Authentication
sess.connect(
    boofuzz.s_get("AuthReq: Open"),
    boofuzz.s_get("AssoReq: %s" % AP_CONFIG),
    callback=check_auth,
)  # Checking Authentication
if AP_CONFIG not in ["Open"]:
    sess.connect(
        boofuzz.s_get("AuthReq: Open"),
        boofuzz.s_get("AssoReq: %s Fuzzing" % AP_CONFIG),
        callback=check_auth,
    )  # Checking Authentication

for oui in ouis:
    sess.connect(
        boofuzz.s_get("AuthReq: Open"),
        boofuzz.s_get("AssoReq: Vendor Specific %s" % oui),
        callback=check_auth,
    )

for ie in list_ies:
    sess.connect(
        boofuzz.s_get("AuthReq: Open"),
        boofuzz.s_get("AssoReq: IE %d" % ie),
        callback=check_auth,
    )

for type_subtype in range(256):
    sess.connect(
        boofuzz.s_get("AuthReq: Open"),
        boofuzz.s_get("Fuzzy 2: Malformed %d" % type_subtype),
        callback=check_auth,
    )

# Fuzzing State : "Authenticated, Associated"

for type_subtype in range(256):
    sess.connect(
        boofuzz.s_get("AssoReq: %s" % AP_CONFIG),
        boofuzz.s_get("Fuzzy 3: Malformed %d" % type_subtype),
        callback=check_asso,
    )

if AP_CONFIG in ["WPA-PSK", "RSN-PSK"]:
    sess.connect(
        boofuzz.s_get("AssoReq: %s" % AP_CONFIG),
        boofuzz.s_get("EAPoL-Key: %s" % AP_CONFIG),
        callback=check_asso,
    )

if AP_CONFIG in ["WPA-EAP", "RSN-EAP"]:
    sess.connect(
        boofuzz.s_get("AssoReq: %s" % AP_CONFIG),
        boofuzz.s_get("EAPoL-Start: %s" % AP_CONFIG),
        callback=check_asso,
    )

# Launching the fuzzing campaign
sess.fuzz()
