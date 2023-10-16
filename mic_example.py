import hashlib
import hmac
import os

# 1. Generate the PSK
def generate_psk(ssid, passphrase):
    return hashlib.pbkdf2_hmac('sha1', passphrase.encode(), ssid.encode(), 4096, 32)

# Pseudo-random function for PTK derivation
def PRF512(key, A, B):
    num_blocks = 4
    R = b''
    for i in range(1, num_blocks + 1):
        hmac_data = A + chr(0x00).encode() + B + chr(i).encode()
        R += hmac.new(key, hmac_data, hashlib.sha1).digest()
    return R

def generate_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    A = b"Pairwise key expansion"
    B = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(anonce, snonce) + max(anonce, snonce)
    return PRF512(pmk, A, B)

# Simplified EAPOL frame generation (either for Frame 2 or Frame 3)
def generate_eapol_frame(version, type, len, descriptor_type, key_info, key_len, replay_counter, nonce, key_iv, key_rsc, key_id, mic, data_len, data):
    return version + type + len + descriptor_type + key_info + key_len + replay_counter + nonce + key_iv + key_rsc + key_id + mic + data_len + data

# Compute the MIC over an EAPOL frame
def compute_mic(ptk, eapol_frame):
    # For this demonstration, assume the MIC field is bytes 81-97 in the EAPOL frame
    eapol_for_mic = eapol_frame[:81] + b'\x00' * 16 + eapol_frame[97:]
    return hmac.new(ptk[:16], eapol_for_mic, hashlib.sha1).digest()

# For this example:
ssid = "testSSID"
passphrase = "testPassphrase"
psk = generate_psk(ssid, passphrase)
print(f"PSK: {psk.hex()}")

# Random values for our example
anonce = os.urandom(32)
snonce = os.urandom(32)
ap_mac = os.urandom(6)
client_mac = os.urandom(6)

ptk = generate_ptk(psk, anonce, snonce, ap_mac, client_mac)
print(f"PTK: {ptk.hex()}")

# Simplified EAPOL Frame (Very basic representation. Real-world frames are more complex!)
eapol_frame = generate_eapol_frame(
    version=b'\x01',
    type=b'\x03',
    len=b'\x00\x5f',           # Length
    descriptor_type=b'\x02',  # Type: RSN Key
    key_info=b'\x01\x3a',     # Key Info
    key_len=b'\x00\x10',      # Length of the key
    replay_counter=b'\x00\x00\x00\x00\x00\x00\x00\x01',
    nonce=snonce,             # This is the SNonce for Frame 2, or ANonce for Frame 3
    key_iv=os.urandom(16),
    key_rsc=os.urandom(8),
    key_id=os.urandom(8),
    mic=b'\x00' * 16,
    data_len=b'\x00\x00',
    data=b''
)

mic = compute_mic(ptk, eapol_frame)
print(f"MIC: {mic.hex()}")

# Now you'd set the MIC field in the EAPOL frame to this computed MIC.
