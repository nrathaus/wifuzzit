""""STA Requests"""
# from sully import *
import boofuzz

from sta_settings import AP_MAC, CHANNEL, SSID, STA_MAC, PADDING


# Ripped from scapy
def mac2str(mac):
    return "".join(map(lambda x: chr(int(x, 16)), mac.split(":")))


ouis = [
    "\x00P\xf2\x02",
    "\x00@\x96\x04",
    "\x00P\xf2\x01",
    "\x00\x90L4",
    "\x00@\x96\x03",
    "\x00@\x96\x01",
    "\x00@\x96\x0c",
    "\x00\x0b\x0e\x02",
    "\x00@\x96\x0b",
    "\x00\x90L3",
    "\x00\x03\x7f\x01",
    "\x00\x03/\x01",
    "\x00\x03\x7f\x02",
    "\x00\x03\x93\x01",
    "\x00\x10\x18\x01",
    "\x00\x10\x18\x02",
    "\x00\x03\x7f\x03",
]

RATES = "\x02\x04\x0B\x16\x0c\x18\x30\x48"
TIM = "\x00\x01\x00\x08"
ERP42 = "\x04"
ERP47 = "\x00"
XRATES = "\x32\x04\x30\x48\x60\x6c"

PROBE_RESP = "\x50"
PROBE_RESP += "\x00"
PROBE_RESP += "\x3A\x01"
PROBE_RESP += "\x00"
PROBE_RESP += mac2str(STA_MAC)  # Destination Address
PROBE_RESP += mac2str(AP_MAC)  # Source Address
PROBE_RESP += mac2str(AP_MAC)  # BSSID Address
PROBE_RESP += "\x00\x00"  # Sequence Control
PROBE_RESP += "\x00\x00\x00\x00\x01\x00\x00\x00"  # Timestamp
PROBE_RESP += "\x01\x00"  # Beacon Interval
PROBE_RESP += "\x01\x00"  # Capabilities
PROBE_RESP += "\x00" + chr(len(SSID)) + SSID  # SSID
PROBE_RESP += "\x01" + chr(len(RATES)) + RATES  # RATES
PROBE_RESP += "\x03" + "\x01" + CHANNEL  # CHANNEL


def alen(n):
    return n / 4


def h(min_len, max_len):
    l = range(min_len, min_len + 33)
    l += [63, 64, 65]
    l += [127, 128, 129]
    l += range(max_len - 5, max_len)
    return l


def information_element_header(name, iei):
    boofuzz.s_byte(iei, fuzzable=False)  # IEI
    boofuzz.s_size(name, length=1, name="%s Length" % name, fuzzable=True)  # Length
    return boofuzz.s_block_start(name)


def string_element(name, iei, content=""):
    if information_element_header(name, iei):
        boofuzz.s_string(content, 0, 255, max_len=255)
    boofuzz.s_block_end()
    boofuzz.s_repeat(name, 0, 1024, 50)


def random_element(
    name, iei, content=""
):  # FIXME: length minus content will not be elected
    if information_element_header(name, iei):
        boofuzz.s_static(content)
        # Used if heuristic patch applied to Sulley
        # boofuzz.s_random("", 0, 255 - len(content), heuristic=h)
        boofuzz.s_random("", 0, 255 - len(content))
    boofuzz.s_block_end()
    boofuzz.s_repeat(name, 0, 1024, 50)


# Fuzzing Probe Response Most Used Information Elements
boofuzz.s_initialize("ProbeResp: Most Used IEs")
if boofuzz.s_block_start("ProbeResp"):
    boofuzz.s_static("\x50")  # Type/Subtype
    boofuzz.s_static("\x00")  # Flags
    boofuzz.s_static("\x3A\x01")  # Duration ID
    boofuzz.s_static(mac2str(STA_MAC))  # Destination Address
    boofuzz.s_static(mac2str(AP_MAC))  # Source Address
    boofuzz.s_static(mac2str(AP_MAC))  # BSSID Address
    boofuzz.s_static("\x00\x00")  # Sequence Control
    boofuzz.s_qword(0x0000000010000000, fuzzable=False)  # Timestamp
    boofuzz.s_word(0x0001, fuzzable=False)  # Beacon Interval
    boofuzz.s_static("\x01\x00")  # Capabilities
    string_element("SSID", 0, content=SSID)  # Fuzzing SSID
    random_element("RATES", 1, content=RATES)  # Fuzzing RATES
    random_element("CHANNEL", 3, content=CHANNEL)  # Fuzzing CHANNEL
    random_element("TIM", 5, content=TIM)  # Fuzzing TIM
    random_element("ERP42", 42, content=ERP42)  # Fuzzing ERP42
    random_element("ERP47", 47, content=ERP47)  # Fuzzing ERP47
    random_element("XRATES", 50, content=XRATES)  # Fuzzing XRATES
boofuzz.s_block_end()

# Fuzzing Information Elements
list_ies = list(range(2, 256))
for i in [3, 5, 42, 47, 50]:
    list_ies.remove(i)

for ie in list_ies:
    boofuzz.s_initialize("ProbeResp: IE %d" % ie)
    boofuzz.s_static(PROBE_RESP)
    random_element("IE", ie)  # Fuzzing IE

# Fuzzing With Malformed Probe Responses
boofuzz.s_initialize("ProbeResp: Malformed")
if boofuzz.s_block_start("ProbeResp: Malformed"):
    boofuzz.s_static("\x50")  # Type/Subtype
    boofuzz.s_static("\x00")  # Flags
    boofuzz.s_static("\x3A\x01")  # Duration ID
    boofuzz.s_static(mac2str(STA_MAC))  # Destination Address
    boofuzz.s_static(mac2str(AP_MAC))  # Source Address
    boofuzz.s_static(mac2str(AP_MAC))  # BSSID Address
    boofuzz.s_static("\x00\x00")  # Sequence Control
    boofuzz.s_random(PADDING * 10, 0, 1024, step=25)  # Garbage
boofuzz.s_block_end()

# Fuzzing With Malformed Frames
for type_subtype in range(256):
    boofuzz.s_initialize("Fuzzy: Malformed %d" % type_subtype)
    boofuzz.s_static(type_subtype)  # Type/Subtype
    if boofuzz.s_block_start("Fuzzy: Malformed %d" % type_subtype):
        boofuzz.s_byte(0x00, fuzzable=False)  # Flags
        boofuzz.s_static("\x3A\x01")  # Duration ID
        boofuzz.s_static(mac2str(AP_MAC))  # Destination Address
        boofuzz.s_static(mac2str(STA_MAC))  # Source Address
        boofuzz.s_static(mac2str(AP_MAC))  # BSSID Address
        boofuzz.s_random(PADDING * 10, 0, 1024, step=25)  # Garbage
    boofuzz.s_block_end()

# Fuzzing Vendor Specific IE
for oui in ouis:
    boofuzz.s_initialize("ProbeResp: Vendor Specific %s" % oui)
    boofuzz.s_static(PROBE_RESP)
    random_element("IE", 221, content=oui)  # Fuzzing IE

# Fuzzing WPA-PSK, RSN-PSK, WPA-EAP, RSN-EAP IE
for method in ["WPA-PSK", "WPA-EAP", "RSN-PSK", "RSN-EAP"]:
    if method == "WPA-PSK":
        IE = "\xDD"
        HDR = "\x00\x50\xF2" + "\x01" + "\x01\x00" + "\x00\x50\xF2\x02"
        UCAST_CIPHER = "\x00\x50\xF2\x02"
        AUTH_METHOD = "\x00\x50\xF2\x02"
    elif method == "WPA-EAP":
        IE = "\xDD"
        HDR = "\x00\x50\xF2" + "\x01" + "\x01\x00" + "\x00\x50\xF2\x02"
        UCAST_CIPHER = "\x00\x50\xF2\x02"
        AUTH_METHOD = "\x00\x50\xF2\x01"
    elif method == "RSN-PSK":
        IE = "\x30"
        HDR = "\x01\x00" + "\x00\x0F\xAC\x04"
        UCAST_CIPHER = "\x00\x0F\xAC\x04"
        AUTH_METHOD = "\x00\x0F\xAC\x02"
    elif method == "RSN-EAP":
        IE = "\x30"
        HDR = "\x01\x00" + "\x00\x0F\xAC\x04"
        UCAST_CIPHER = "\x00\x0F\xAC\x04"
        AUTH_METHOD = "\x00\x0F\xAC\x01"

    boofuzz.s_initialize("ProbeResp: %s Fuzzing" % method)
    boofuzz.s_static(PROBE_RESP)
    boofuzz.s_static(IE)
    boofuzz.s_size("%s IE" % method, length=1, fuzzable=True)
    if boofuzz.s_block_start("%s IE" % method):
        boofuzz.s_static(HDR)
        boofuzz.s_size("Unicast Ciphers", length=2, fuzzable=True, math=alen)
        if boofuzz.s_block_start("Unicast Ciphers"):
            if boofuzz.s_block_start("Unicast Cipher"):
                boofuzz.s_static(UCAST_CIPHER)
            boofuzz.s_block_end()
            boofuzz.s_repeat("Unicast Cipher", 0, 1024, 50)
        boofuzz.s_block_end()
        boofuzz.s_size("Authentication Methods", length=2, fuzzable=True, math=alen)
        if boofuzz.s_block_start("Authentication Methods"):
            if boofuzz.s_block_start("Authentication Method"):
                boofuzz.s_static(AUTH_METHOD)
            boofuzz.s_block_end()
            boofuzz.s_repeat("Authentication Method", 0, 1024, 50)
        boofuzz.s_block_end()
        boofuzz.s_random("", 0, 1024)
    boofuzz.s_block_end()
