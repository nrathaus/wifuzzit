#!/usr/bin/env python

import logging
import re
import socket
import time
from optparse import OptionParser

import boofuzz

from ap_requests import AUTH_REQ_OPEN, DEAUTH, list_ies, mac2str, ouis
from ap_settings import IFACE

ETH_P_ALL = 3
# Assume that wireless card is in monitor mode on appropriate channel
# Saves from lot of dependencies (lorcon, pylorcon...)

###############


def fuzz_ap():
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
                            "retried authentication %d times"
                            % (CRASH_RETRIES - retries),
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

    def check_auth(target, fuzz_data_logger, session, *args, **kwargs):
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
            pkt = target.recv(1024)
            ans = isresp(pkt)
            if ans:
                logging.info("authentication successful with %s" % AP_MAC)
                return

        logging.info("authentication not successful with %s" % AP_MAC)

        if session.fuzz_node.mutant is not None:
            # print "XXXXX : session.fuzz_node.name %s" % session.fuzz_node.name
            # print "XXXXX : session.fuzz_node.mutant_index %d" % session.fuzz_node.mutant_index
            # print "XXXXX : session.fuzz_node.mutant.mutant_index %d" % session.fuzz_node.mutant.mutant_index
            # print "XXXXX : session.fuzz_node.num_mutations() %d" % session.fuzz_node.num_mutations()
            # print "XXXXX : session.total_mutant_index %d" % session.total_mutant_index
            logging.info("re-trying the current test case")
            session.fuzz_node.mutant_index -= 1
            session.fuzz_node.mutant.mutant_index -= 1
            session.total_mutant_index -= 1

    def check_asso(target, fuzz_data_logger, session, *args, **kwargs):
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
            pkt = target.recv(1024)
            ans = isresp(pkt)
            if ans:
                logging.info(f"association successful with {AP_MAC}")
                return

        logging.error(f"association not successful with {AP_MAC}")
        if session.fuzz_node.mutant is not None:
            # print "XXXXX : session.fuzz_node.name %s" % session.fuzz_node.name
            # print "XXXXX : session.fuzz_node.mutant_index %d" % session.fuzz_node.mutant_index
            # print "XXXXX : session.fuzz_node.mutant.mutant_index %d" % session.fuzz_node.mutant.mutant_index
            # print "XXXXX : session.fuzz_node.num_mutations() %d" % session.fuzz_node.num_mutations()
            # print "XXXXX : session.total_mutant_index %d" % session.total_mutant_index
            logging.info("re-trying the current test case")
            session.fuzz_node.mutant_index -= 1
            session.fuzz_node.mutant.mutant_index -= 1
            session.total_mutant_index -= 1

    # Defining the transport protocol
    sess = boofuzz.Session(
        session_filename=FNAME,
        # proto="wifi",
        # timeout=5.0,
        sleep_time=0.1,
        # log_level=LOG_LEVEL,
        # skip=SKIP,
        # crash_threshold=CRASH_THRESHOLD,
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
    # Defining the target
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
        sess.connect(boofuzz.s_get(f"Fuzzy 1: Malformed {type_subtype}"))

    # Fuzzing State "Authenticated, Not Associated"
    sess.connect(
        boofuzz.s_get("AuthReq: Open"),
        boofuzz.s_get("AssoReq: Garbage"),
        callback=check_auth,
    )  # Checking Authentication

    sess.connect(
        boofuzz.s_get("AuthReq: Open"),
        boofuzz.s_get("AssoReq: Open"),
        callback=check_auth,
    )  # Checking Authentication

    sess.connect(
        boofuzz.s_get("AuthReq: Open"),
        boofuzz.s_get(f"AssoReq: {AP_CONFIG}"),
        callback=check_auth,
    )  # Checking Authentication

    if AP_CONFIG not in ["Open"]:
        sess.connect(
            boofuzz.s_get("AuthReq: Open"),
            boofuzz.s_get(f"AssoReq: {AP_CONFIG} Fuzzing"),
            callback=check_auth,
        )  # Checking Authentication

    for oui in ouis:
        sess.connect(
            boofuzz.s_get("AuthReq: Open"),
            boofuzz.s_get(f"AssoReq: Vendor Specific {oui}"),
            callback=check_auth,
        )

    for ie in list_ies:
        sess.connect(
            boofuzz.s_get("AuthReq: Open"),
            boofuzz.s_get(f"AssoReq: IE {ie}"),
            callback=check_auth,
        )

        # for type_subtype in range(256):
        sess.connect(
            boofuzz.s_get("AuthReq: Open"),
            boofuzz.s_get(f"Fuzzy 2: Malformed {type_subtype}"),
            callback=check_auth,
        )

    # Fuzzing State : "Authenticated, Associated"

    for type_subtype in range(256):
        sess.connect(
            boofuzz.s_get(f"AssoReq: {AP_CONFIG}"),
            boofuzz.s_get(f"Fuzzy 3: Malformed {type_subtype}"),
            callback=check_asso,
        )

    if AP_CONFIG in ["WPA-PSK", "RSN-PSK"]:
        sess.connect(
            boofuzz.s_get(f"AssoReq: {AP_CONFIG}"),
            boofuzz.s_get(f"EAPoL-Key: {AP_CONFIG}"),
            callback=check_asso,
        )

    if AP_CONFIG in ["WPA-EAP", "RSN-EAP"]:
        sess.connect(
            boofuzz.s_get(f"AssoReq: {AP_CONFIG}"),
            boofuzz.s_get(f"EAPoL-Start: {AP_CONFIG}"),
            callback=check_asso,
        )

    # Launching the fuzzing campaign
    sess.fuzz()


if __name__ == "__main__":
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("--sta_mac", dest="sta_mac", help="STA MAC address (fuzzer)")
    parser.add_option("--iface", dest="iface", help="injection interface")
    parser.add_option(
        "--skip", dest="skip", help="skip tests (int)", type="int", default=0
    )
    parser.add_option("--ssid", dest="ssid", help="AP ssid (fuzzed)")
    parser.add_option("--ap_mac", dest="ap_mac", help="AP MAC address (fuzzed)")
    parser.add_option("--channel", dest="channel", help="AP channel (fuzzed)", type=int)
    parser.add_option(
        "--ap_config",
        dest="ap_config",
        help="AP config: Open, WPA-PSK, WPA-EAP, RSN-PSK, RSN-EAP",
    )
    parser.add_option(
        "--save", dest="save", help="save results", action="store_true", default=False
    )
    parser.add_option(
        "--truncate",
        dest="truncate",
        help="truncate frames option",
        action="store_true",
        default=False,
    )
    parser.add_option("--crash_retries", dest="crash_retries", type=int, default=10)
    parser.add_option("--delay", dest="delay", type=int, default=1)
    parser.add_option("--delay_reboot", dest="delay_reboot", type=int, default=10)
    parser.add_option("--state_wait_time", dest="state_wait_time", type=int, default=2)
    parser.add_option("--log_level", dest="log_level", type=int, default=3)
    parser.add_option("--crash_threshold", dest="crash_threshold", type=int, default=3)
    parser.add_option(
        "--fname",
        dest="fname",
        help="defining saved results file (conjointly with --save)",
        default=None,
    )

    (options, args) = parser.parse_args()

    if not options.sta_mac:
        parser.error("STA MAC address must be set")

    if not re.search(
        r"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", options.sta_mac, re.I
    ).group():
        parser.error("STA MAC address invalid format")

    if not options.iface:
        parser.error("injection interface must be set")

    if not options.ssid:
        parser.error("AP ssid must be set")

    if len(options.ssid) > 32:
        parser.error("AP ssid must be <= 32 characters")

    if not options.ap_mac:
        parser.error("AP MAC address must be set")

    if not re.search(
        r"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})", options.ap_mac, re.I
    ).group():
        parser.error("AP MAC address invalid format")

    if not options.channel:
        parser.error("AP channel must be set")

    if not options.ap_config:
        parser.error("AP config must be set")

    if options.ap_config not in ["Open", "WPA-PSK", "WPA-EAP", "RSN-PSK", "RSN-EAP"]:
        parser.error("AP incorrect configuration")

    if options.save:
        if options.fname:
            FNAME = options.fname
        else:
            FNAME = f"audits/ap-{options.ap_mac}-{options.ap_config}.session"

    STA_MAC = options.sta_mac
    IFACE = options.iface
    SAVE_RESULTS = options.save
    SKIP = options.skip
    SSID = options.ssid
    AP_MAC = options.ap_mac
    CHANNEL = options.channel
    AP_CONFIG = options.ap_config
    CRASH_RETRIES = options.crash_retries
    DELAY = options.delay
    STATE_WAIT_TIME = options.state_wait_time
    DELAY_REBOOT = options.delay_reboot
    LOG_LEVEL = options.log_level
    CRASH_THRESHOLD = options.crash_threshold
    TRUNCATE = options.truncate

    fuzz_ap()
