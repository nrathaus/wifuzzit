"""AP Requests"""
import boofuzz

from ap_settings import AP_MAC, SSID, STA_MAC, TRUNCATE


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

# Defining the padding value
PADDING = "\xFF"
RATES = "\x02\x04\x0B\x16\x0c\x18\x30\x48"
XRATES = "\x32\x04\x30\x48\x60\x6c"
ssid = "\x00" + chr(len(SSID)) + SSID
rates = "\x01" + chr(len(RATES)) + RATES

WPA_PSK = "\x00\x50\xF2"  # WPA OUI
WPA_PSK += "\x01"  # WPA Type
WPA_PSK += "\x01\x00"  # WPA Version
WPA_PSK += "\x00\x50\xF2\x02"  # TKIP
WPA_PSK += "\x01\x00"  # Number of unicast ciphers
WPA_PSK += "\x00\x50\xF2\x02"  # TKIP
WPA_PSK += "\x01\x00"  # Number of authentication methods
WPA_PSK += "\x00\x50\xF2\x02"  # PSK Authentication
WPA_PSK_IE = "\xDD" + chr(len(WPA_PSK)) + WPA_PSK
WPA_EAP_IE = WPA_PSK_IE[:-4] + "\x00\x50\xF2\x01"

RSN_PSK = "\x01\x00"  # RSN Version
RSN_PSK += "\x00\x0F\xAC\x04"  # CCMP
RSN_PSK += "\x01\x00"  # Number of unicast ciphers
RSN_PSK += "\x00\x0F\xAC\x04"  # CCMP
RSN_PSK += "\x01\x00"  # Number of authentication methods
RSN_PSK += "\x00\x0F\xAC\x02"  # PSK Authentication
RSN_PSK_IE = "\x30" + chr(len(RSN_PSK)) + RSN_PSK
RSN_EAP_IE = RSN_PSK_IE[:-4] + "\x00\x0F\xAC\x01"

AUTH_REQ_OPEN = "\xB0"  # Type/Subtype
AUTH_REQ_OPEN += "\x00"  # Flags
AUTH_REQ_OPEN += "\x3A\x01"  # Duration ID
AUTH_REQ_OPEN += mac2str(AP_MAC)  # Destination address
AUTH_REQ_OPEN += mac2str(STA_MAC)  # Source address
AUTH_REQ_OPEN += mac2str(AP_MAC)  # BSSID
AUTH_REQ_OPEN += "\x00\x00"  # Sequence control
AUTH_REQ_OPEN += "\x00\x00"  # Authentication algorithm (open)
AUTH_REQ_OPEN += "\x01\x00"  # Authentication sequence number
AUTH_REQ_OPEN += "\x00\x00"  # Authentication status
AUTH_REQ_HDR = AUTH_REQ_OPEN[:-6]

ASSO_REQ_OPEN = "\x00"  # Type/Subtype
ASSO_REQ_OPEN += "\x00"  # Flags
ASSO_REQ_OPEN += "\x3A\x01"  # Duration ID
ASSO_REQ_OPEN += mac2str(AP_MAC)  # Destination address
ASSO_REQ_OPEN += mac2str(STA_MAC)  # Source address
ASSO_REQ_OPEN += mac2str(AP_MAC)  # BSSID
ASSO_REQ_OPEN += "\x00\x00"  # Sequence control
ASSO_REQ_OPEN += "\x01\x00"  # Capability information (ESS) FIXME
ASSO_REQ_OPEN += "\x64\x00"  # Listen interval
ASSO_REQ_OPEN += ssid  # SSID information element
ASSO_REQ_OPEN += rates  # RATES information element
ASSO_REQ_HDR = ASSO_REQ_OPEN[: -len(ssid) - len(rates)]

DEAUTH = "\xC0"  # Type/Subtype
DEAUTH += "\x00"  # Flags
DEAUTH += "\x3A\x01"  # Duration ID
DEAUTH += mac2str(AP_MAC)  # Destination address
DEAUTH += mac2str(STA_MAC)  # Source address
DEAUTH += mac2str(AP_MAC)  # BSSID
DEAUTH += "\x00\x00"  # Sequence control
DEAUTH += "\x02\x00"  # Reason code

ASSO_REQ_WPA_PSK = ASSO_REQ_OPEN + WPA_PSK_IE
ASSO_REQ_WPA_EAP = ASSO_REQ_OPEN + WPA_EAP_IE
ASSO_REQ_RSN_PSK = ASSO_REQ_OPEN + RSN_PSK_IE
ASSO_REQ_RSN_EAP = ASSO_REQ_OPEN + RSN_EAP_IE

EAPOL_KEY_HDR = "\x08"  # Type/Subtype
EAPOL_KEY_HDR += "\x01"  # Flags
EAPOL_KEY_HDR += "\x3A\x01"  # Duration ID
EAPOL_KEY_HDR += mac2str(AP_MAC)  # Destination Address
EAPOL_KEY_HDR += mac2str(STA_MAC)  # Source Address
EAPOL_KEY_HDR += mac2str(AP_MAC)  # BSSID Address
EAPOL_KEY_HDR += "\x00\x00"  # Sequence Control
EAPOL_KEY_HDR += "\xAA\xAA"  # DSAP/SSAP
EAPOL_KEY_HDR += "\x03"  # Control Field
EAPOL_KEY_HDR += "\x00\x00\x00"  # Organization Code
EAPOL_KEY_HDR += "\x88\x8E"  # Type


def alen(n):
    return n / 4


# Used if heuristic patch applied to Sulley
def h(min_len, max_len):
    l = range(min_len, min_len + 33)
    l += [63, 64, 65]
    l += [127, 128, 129]
    l += range(max_len - 5, max_len)
    return l


def information_element_header(name, iei):
    """information_element_header"""
    boofuzz.s_byte(iei, fuzzable=False)  # IEI
    boofuzz.s_size(name, length=1, name=f"{name} Length", fuzzable=True)  # Length
    return boofuzz.s_block_start(name)


def string_element(name, iei, content=""):
    """string_element"""
    if information_element_header(name, iei):
        boofuzz.s_string(content, 0, 255, max_len=255)
    boofuzz.s_block_end()
    boofuzz.s_repeat(name, 0, 1024, 50)


def random_element(name, iei, content=""):
    """random_element"""
    if information_element_header(name, iei):
        # Used if heuristic patch applied to Sulley
        # boofuzz.s_random(content, 0, 255, heuristic=h)
        boofuzz.s_random(content, 0, 255)
    boofuzz.s_block_end()
    boofuzz.s_repeat(name, 0, 1024, 50)


def oui_element(name, iei, content=""):
    """oui_element"""
    if information_element_header(name, iei):
        boofuzz.s_static(content)
        # Used if heuristic patch applied to Sulley
        # boofuzz.s_random('', 0, 255 - len(content), heuristic=h)
        boofuzz.s_random("", 0, 255 - len(content))
    boofuzz.s_block_end()
    boofuzz.s_repeat(name, 0, 1024, 50)


#############################
# FUZZING TESTING SCENARIOS #
#############################

boofuzz.s_initialize("AssoReq: WPA-PSK")
boofuzz.s_static(ASSO_REQ_OPEN)
if boofuzz.s_block_start("AssoReq: WPA-PSK"):
    boofuzz.s_static(WPA_PSK_IE)
boofuzz.s_block_end()

boofuzz.s_initialize("AssoReq: WPA-EAP")
boofuzz.s_static(ASSO_REQ_OPEN)
if boofuzz.s_block_start("AssoReq: WPA-EAP"):
    boofuzz.s_static(WPA_EAP_IE)
boofuzz.s_block_end()

boofuzz.s_initialize("AssoReq: RSN-PSK")
boofuzz.s_static(ASSO_REQ_OPEN)
if boofuzz.s_block_start("AssoReq: RSN-PSK"):
    boofuzz.s_static(RSN_PSK_IE)
boofuzz.s_block_end()

boofuzz.s_initialize("AssoReq: RSN-EAP")
boofuzz.s_static(ASSO_REQ_OPEN)
if boofuzz.s_block_start("AssoReq: RSN-EAP"):
    boofuzz.s_static(RSN_EAP_IE)
boofuzz.s_block_end()

# AssoReq with most used IEs fuzzed
boofuzz.s_initialize("AssoReq: Open")
if boofuzz.s_block_start("AssoReq: Open"):
    boofuzz.s_static(ASSO_REQ_HDR)
    string_element("SSID", 0, content=SSID)  # Fuzzing SSID
    random_element("RATES", 1, content=RATES)  # Fuzzing RATES
    random_element("XRATES", 50, content=XRATES)  # Fuzzing XRATES
boofuzz.s_block_end()

boofuzz.s_initialize("AssoReq: Garbage")
boofuzz.s_static(ASSO_REQ_HDR)
if boofuzz.s_block_start("AssoReq: Garbage"):
    boofuzz.s_static(PADDING * 100)
boofuzz.s_block_end()

# Fuzzing With Malformed Frames
for state in ["1", "2", "3"]:
    for type_subtype in range(256):
        boofuzz.s_initialize(f"Fuzzy {state}: Malformed {type_subtype}")
        boofuzz.s_byte(type_subtype)  # Type/Subtype
        if boofuzz.s_block_start(f"Fuzzy {state}: Malformed {type_subtype}"):
            boofuzz.s_byte(0x00, fuzzable=False)  # Flags
            boofuzz.s_static("\x3A\x01")  # Duration ID
            boofuzz.s_static(mac2str(AP_MAC))  # Destination Address
            boofuzz.s_static(mac2str(STA_MAC))  # Source Address
            boofuzz.s_static(mac2str(AP_MAC))  # BSSID Address
            boofuzz.s_random(PADDING * 10, 0, 1024, step=25)  # Garbage
        boofuzz.s_block_end()

list_ies = list(range(2, 256))
for i in [50]:
    list_ies.remove(i)

# AssoReq with all IEs fuzzed
for ie in list_ies:
    boofuzz.s_initialize(f"AssoReq: IE {ie}")
    boofuzz.s_static(ASSO_REQ_OPEN)
    random_element("IE", ie)  # Fuzzing IE

# Fuzzing Vendor Specific IE
for oui in ouis:
    boofuzz.s_initialize(f"AssoReq: Vendor Specific {oui}")
    boofuzz.s_static(ASSO_REQ_OPEN)
    oui_element("IE", 221, content=oui)  # Fuzzing IE

boofuzz.s_initialize("AuthReq: Open")
boofuzz.s_static(AUTH_REQ_HDR)
boofuzz.s_word(0x0000, fuzzable=True)  # Authentication Algorithm (Open)
boofuzz.s_word(0x0001, fuzzable=True)  # Authentication Sequence Number
boofuzz.s_word(0x0000, fuzzable=True)  # Authentication Status
boofuzz.s_random("", 0, 1024)

boofuzz.s_initialize("EAPoL-Key: WPA-PSK")
boofuzz.s_static(EAPOL_KEY_HDR)
boofuzz.s_byte(0x01, fuzzable=True)  # Version 1
boofuzz.s_byte(0x03, fuzzable=True)  # Type key
boofuzz.s_size("Content", length=2, endian=">", fuzzable=True)  # Length
if boofuzz.s_block_start("Content"):
    boofuzz.s_byte(0xFE, fuzzable=False)  # Descriptor Type
    boofuzz.s_word(0x0901, fuzzable=False)  # Key Information
    boofuzz.s_word(0x2000, fuzzable=True)  # Key Length (0x0020: TKIP, 0x0010: CCMP)
    boofuzz.s_qword(0x0100000000000000, fuzzable=False)  # Replay Counter
    boofuzz.s_static("A" * 32)  # Nonce
    boofuzz.s_static("B" * 16)  # Key IV
    boofuzz.s_static("\x00" * 8)  # WPA Key RSC
    boofuzz.s_static("\x01" * 8)  # WPA Key ID
    boofuzz.s_static("\x02" * 16)  # WPA Key MIC
    boofuzz.s_size("WPA IE", length=2, endian=">", fuzzable=True)  # WPA IE Length
    if boofuzz.s_block_start("WPA IE"):
        boofuzz.s_static(WPA_PSK_IE)  # WPA IE
    boofuzz.s_block_end()
boofuzz.s_block_end()

boofuzz.s_initialize("EAPoL-Key: RSN-PSK")
boofuzz.s_static(EAPOL_KEY_HDR)
boofuzz.s_byte(0x01, fuzzable=True)  # Version 1
boofuzz.s_byte(0x03, fuzzable=True)  # Type key
boofuzz.s_size("Content", length=2, endian=">", fuzzable=True)  # Length
if boofuzz.s_block_start("Content"):
    boofuzz.s_byte(0x02, fuzzable=False)  # Descriptor Type
    boofuzz.s_word(0x0A01, fuzzable=False)  # Key Information
    boofuzz.s_word(0x1000, fuzzable=True)  # Key Length (0x0020: TKIP, 0x0010: CCMP)
    boofuzz.s_qword(0x0100000000000000, fuzzable=False)  # Replay Counter
    boofuzz.s_static("A" * 32)  # Nonce
    boofuzz.s_static("B" * 16)  # Key IV
    boofuzz.s_static("\x00" * 8)  # WPA Key RSC
    boofuzz.s_static("\x01" * 8)  # WPA Key ID
    boofuzz.s_static("\x02" * 16)  # WPA Key MIC
    boofuzz.s_size("RSN IE", length=2, endian=">", fuzzable=True)  # WPA IE Length
    if boofuzz.s_block_start("RSN IE"):
        boofuzz.s_static(RSN_PSK_IE)  # RSN IE
    boofuzz.s_block_end()
boofuzz.s_block_end()

boofuzz.s_initialize("EAPoL-Start: WPA-EAP")
boofuzz.s_static(EAPOL_KEY_HDR)
# 802.1X header
boofuzz.s_byte(0x01, fuzzable=False)  # Version 1
boofuzz.s_byte(0x01, fuzzable=False)  # Type Start
boofuzz.s_word(0x0000, fuzzable=True)  # Length

boofuzz.s_initialize("EAPoL-Start: RSN-EAP")
boofuzz.s_static(EAPOL_KEY_HDR)
# 802.1X header
boofuzz.s_byte(0x01, fuzzable=False)  # Version 1
boofuzz.s_byte(0x01, fuzzable=False)  # Type Start
boofuzz.s_word(0x0000, fuzzable=True)  # Length

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

    boofuzz.s_initialize(f"AssoReq: {method} Fuzzing")
    boofuzz.s_static(ASSO_REQ_OPEN)
    boofuzz.s_static(IE)
    boofuzz.s_size(f"{method} IE", length=1, fuzzable=True)
    if boofuzz.s_block_start(f"{method} IE"):
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

# Several testing strategies to be implemented:
# Probe requests+Authentications: state unauthenticated
# WMM Information Element Parser
# 802.11n Information Element Parser
# FIXME: data packets (flags WEP...)
# FIXME: Short AssoReq w/ WEP Flag
# Full AssoReq with filled IEs (to the MTU)
# Full AssoReq with empty IEs (to the MTU)
# Full AssoReq with 1 byte IEs (to the MTU)
