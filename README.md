# WPA2 Attack Theory
This repository is meant as a basic guide of compiled information you can use to further study the intricate details of WPA2 PSK attack and recovery.

## WPA/WPA2 4-Way Handshake

The WPA/WPA2 4-way handshake is a fundamental step in the Wi-Fi authentication process. It ensures that both the client and the AP possess the correct credentials and derives a fresh session key (Pairwise Transient Key, or PTK) for encrypting the wireless traffic.

### 1. **Message 1: AP → Client**

- **Purpose**: 
  - Initiate the handshake and provide the client with the ANonce.
  
- **Values**:
  - **ANonce**: The AP generates a fresh, random number.
  - **SNonce**: Not present.
  - **MIC**: Not present.
  
- **Note**: 
  - The AP sends the ANonce to the client, awaiting its credentials in return.

### 2. **Message 2: Client → AP**

- **Purpose**: 
  - Respond with its credentials and provide the SNonce and MIC.

- **Values**:
  - **ANonce**: Used from Message 1.
  - **SNonce**: Client-generated fresh, random number.
  - **MIC**: Cryptographic function of the SNonce, ANonce, MAC addresses, and the PMK.

- **Key Derivation**: 
  - The client uses its PSK (or PMK), ANonce, SNonce, and MAC addresses to derive the PTK.

- **Note**: 
  - The client sends its credentials, including the SNonce and MIC, to the AP for verification.

### 3. **Message 3: AP → Client**

- **Purpose**: 
  - Confirm the client's credentials, provide the Group Temporal Key (GTK), and include the MIC for validation.

- **Values**:
  - **ANonce**: Resent for continuity and verification.
  - **SNonce**: Not included in this message.
  - **MIC**: Proves the AP derived the same PTK as the client.
  - **GTK**: Used to encrypt multicast and broadcast traffic on the network.

- **Note**: 
  - Ensures both parties have derived the same PTK and are using the correct PMK.

### 4. **Message 4: Client → AP**

- **Purpose**: 
  - Acknowledge receipt and understanding of the GTK.

- **Values**:
  - **ANonce & SNonce**: Neither is present.
  - **MIC**: Confirms receipt and understanding of the GTK.

- **Note**: 
  - This final message serves primarily as an acknowledgment.

---

## Values and Their Importance in Handshake Capture & Cracking:

1. **ANonce & SNonce**: 
   - Vital for PTK derivation.
   - If you capture both nonces, you can derive the PTK using a guessed PSK, leading to MIC computation.

2. **MIC**: 
   - The target of PSK cracking attempts. If a computed MIC matches the captured MIC using a guessed PSK, the guess is likely correct.

3. **PMK/PSK**: 
   - In a home network, the PSK is the "Wi-Fi password". In enterprise settings, the PMK can come from methods like EAP. The PSK is the value that cracking attempts aim to discover.

The 4-way handshake ensures mutual knowledge of the pre-shared key without direct transmission and agrees on a fresh session key for encrypted communications. The feasibility of a cracking attempt hinges on computing the correct MIC using a guessed PSK.

## Message Pair Priority

To retrieve a valid PSK using hashcat (or similar tools), you need at least a part of the 4-way handshake because the handshake contains all the necessary data (nonces, MAC addresses, MIC, etc.) to validate a guessed PSK. 

Considering the different possibilities, here's a prioritized list:

### High Priority (Best candidates for cracking):
1. **Message Pair M2-M3**: This is the most preferred because M2 contains the SNonce and MIC from the client, and M3 contains the ANonce from the AP. Having both nonces and the MIC enables you to perform an effective brute-force or dictionary attack on the PSK.

2. **Message Pair M1-M4**: While not as common as M2-M3 pairs for cracking, M1 contains the ANonce, and M4 is essentially an acknowledgment from the client, indicating that it has computed the correct MIC and PTK. Though M4 doesn't contain the SNonce, you already have it from a previous capture.

### Medium Priority (Can potentially yield a valid PSK with nonce error-correction):
3. **Message M2 Alone (from Rogue AP attack)**: With a Rogue AP attack, you can sometimes capture just the M2 message when a client is attempting to connect to what it thinks is a legitimate AP. M2 contains the SNonce and MIC. While you don't have the ANonce, hashcat has techniques that can attempt to recover the PSK using just M2 by leveraging nonce error-corrections. 

4. **Message Pair M1-M2**: Having M1 gives you the ANonce, and M2 provides the SNonce and MIC. However, without the GTK (which is in M3), there's a loss of data that's sometimes required for the attack. Still, with nonce error-correction, this could be a potential candidate for cracking.

### Low Priority (Least likely to yield a valid PSK even with nonce error-correction):
5. **Message M1 Alone**: While it provides the ANonce, without the SNonce and MIC from the client, it's very challenging to derive the PSK, even with nonce error-correction techniques.

6. **Message M3 or M4 Alone**: Without the corresponding client messages, these messages from the AP provide very little value on their own. You'd be missing either the SNonce or both nonces, making PSK retrieval highly unlikely.

### Not Viable (Will not return a valid PSK):
- Any corrupted EAPOL messages where essential data (like nonces or MIC) is not readable or has been tampered with.
- Captures without the MIC. The MIC is crucial to validate any guessed PSK, so without it, you cannot confirm the correctness of any derived PSK.

Remember, the effectiveness of PSK cracking doesn't just depend on having the right handshake messages. The complexity of the PSK, the dictionary used for attacks, and the computational power available are all factors that influence the success of the retrieval attempt.

## Hashcat 22000 Format

### PMKID Version (01):

The PMKID-based format is primarily used for PMKID attacks (targeted at roaming features in WPA2) where the 4-way handshake isn't necessarily required.

**Format**:
```
WPA*01*PMKID*MAC_AP*MAC_CLIENT*ESSID***MESSAGEPAIR
```

- `WPA*01*`: Prefix indicating it's a PMKID format.
- `PMKID`: This is the PMKID value used in PMKID attacks.
- `MAC_AP`: MAC address of the access point.
- `MAC_CLIENT`: MAC address of the client device.
- `ESSID`: The ESSID (network name).
- `MESSAGEPAIR`: Indicates the types of messages captured (e.g., M1-M2, M2-M3, etc.) for completeness and validation. It aids in understanding the context of the handshake.

### EAPOL Version (02):

The EAPOL-based format is what's typically used for capturing and cracking the 4-way handshake.

**Format**:
```
WPA*02*MIC*MAC_AP*MAC_CLIENT*ESSID*NONCE_AP*EAPOL_CLIENT*MESSAGEPAIR
```

- `WPA*02*`: Prefix indicating it's an EAPOL-based format.
- `MIC`: The Message Integrity Code from the handshake, crucial for validating PSK guesses.
- `MAC_AP`: MAC address of the access point.
- `MAC_CLIENT`: MAC address of the client device.
- `ESSID`: The ESSID (network name).
- `NONCE_AP`: The ANonce (nonce from the access point).
- `EAPOL_CLIENT`: The raw EAPOL frame data from the client, which contains the SNonce and other details.
- `MESSAGEPAIR`: As with the PMKID format, it indicates the types of messages captured, providing context to the handshake.

In the Hashcat 22000 format for WPA, the `MESSAGEPAIR` value provides insights into which messages of the 4-way handshake have been captured. Understanding this helps tools like Hashcat determine the type and viability of the attack on the captured handshake.

Each value of `MESSAGEPAIR` provides a different context for the handshake:

- **0**: `M1+M2` - This indicates that the capture includes messages M1 and M2. It's an initial phase of the 4-way handshake where the AP provides the ANonce, and the client responds with the SNonce.

- **1**: `M2+M3` - This suggests that the capture contains messages M2 and M3. It's considered the best for cracking since you have both the ANonce and SNonce, allowing the PTK to be derived and the MIC to be checked.

- **2**: `M3+M4` - The capture contains messages M3 and M4. While M3 contains the ANonce, M4 is primarily an acknowledgment. However, the presence of M4 might help verify the handshake's completeness.

- **3**: `M1+M4_ZEROED` - This indicates that the capture contains messages M1 and M4. Still, the MIC in the M4 message is zeroed, which often happens with certain client devices when the wrong passphrase is used. This pair can be useful, but it's more challenging than having the M1+M2 or M2+M3 pairs.

- **4 to 8**: These values (e.g., `M32E2`, `M32E3`, etc.) generally indicate combinations of handshake messages involving Extended EAPOL messages. They might be seen in specific network configurations and scenarios.

- **9**: `M2 (AP-LESS)` - This is an interesting case where only the M2 message is captured, typically when using a rogue AP attack to trick a client into thinking it's connecting to a legitimate AP.

These `MESSAGEPAIR` values are vital for tools like Hashcat, as they determine the kind of cryptographic operations needed to crack the handshake. Some pairs, like M2+M3, are considered better for cracking purposes than others, such as M1+M4_ZEROED.

Understanding the `MESSAGEPAIR` value is crucial for those attempting to crack WPA handshakes, as it can directly impact the likelihood of successfully retrieving the PSK.

## The MIC and Nonces

### MIC (Message Integrity Code):

MIC, or Message Integrity Code, is used to ensure the integrity and authenticity of a message. In the context of WPA/WPA2 handshakes, the MIC ensures that certain parts of the handshake (like the nonces and the derived session keys) haven't been tampered with during the exchange.

The MIC is essentially a cryptographic hash of:

- The nonces (ANonce & SNonce)
- The MAC addresses of both the client and the AP
- The Pairwise Master Key (PMK), which is derived from the pre-shared key (PSK) and other data
- Some parts of the EAPOL frames

The MIC is then attached to the EAPOL frames being exchanged. Upon receiving a message, the recipient can compute its own MIC using the received data and the known PMK. If the computed MIC matches the received MIC, the message is considered valid and untampered.

### Rogue AP Attack and MIC:

In a Rogue AP (or Evil Twin) attack, an attacker sets up a malicious access point that impersonates a legitimate one (by mimicking its SSID, MAC address, etc.). Unsuspecting clients might connect to this rogue AP, thinking it's the genuine one.

Now, here's how the MIC becomes crucial in exploiting the client to retrieve the PSK:

1. **Handshake Capture**: When a client connects to the Rogue AP, a 4-way handshake is initiated. The attacker captures this handshake, especially Message 2, which contains the client's MIC and SNonce.

2. **Offline Brute Force**: With the captured handshake, the attacker can now attempt to guess the PSK. For each guessed PSK, the attacker derives a PMK, computes the MIC, and compares it to the captured MIC. A matching MIC indicates that the guessed PSK is correct.

3. **Importance of MIC**: Without the MIC, the attacker wouldn't have a reliable way to verify if a guessed PSK is correct. The MIC, derived from the PSK and known parts of the handshake, provides a method for the attacker to confirm a correct guess without interacting further with the client or genuine AP.

##### Protecting Against Rogue AP Attacks:

It's worth noting that WPA3, which uses Simultaneous Authentication of Equals (SAE), offer protection against these types of offline dictionary attacks.

## ANonce & SNonce

The ANonce (Authenticator Nonce) and SNonce (Supplicant Nonce) play vital roles in the EAPOL process. Here's a step-by-step breakdown of how these nonce values change during the handshake:

### 1. Message 1: AP -> Client

- **ANonce:** The AP generates a fresh random number called the ANonce and sends it to the client. This nonce will remain consistent for the entire handshake process initiated by this specific Message 1.
  
- **SNonce:** No SNonce value is involved in this message since the client has yet to generate or send it.

### 2. Message 2: Client -> AP

- **ANonce:** The client receives the ANonce from Message 1 and uses it in its computations, but it doesn't send it back to the AP in Message 2.

- **SNonce:** The client generates its random nonce, the SNonce. This is then sent to the AP. This nonce, like the ANonce, remains consistent for the entire handshake process initiated by the corresponding Message 1.

In addition to the SNonce, the client also sends the MIC (Message Integrity Code) in Message 2. This MIC is a cryptographic function of several values, including the ANonce, SNonce, MAC addresses, and the chosen Pairwise Master Key (PMK). The AP can verify this MIC to ensure the client's authenticity and that it possesses the correct PMK.

### 3. Message 3: AP -> Client

- **ANonce:** The AP sends the ANonce back to the client. This ANonce remains the same as the one sent in Message 1.

- **SNonce:** The AP doesn't send the SNonce back to the client in this message, but it uses it internally to compute the MIC and, subsequently, the Pairwise Transient Key (PTK).

The AP also sends the Group Temporal Key (GTK) in this message. The GTK is encrypted with a key derived from the PTK. The MIC sent in Message 3 allows the client to verify the AP's authenticity.

### 4. Message 4: Client -> AP

- **ANonce and SNonce:** The client doesn't send any nonce values in Message 4. This message serves primarily as an acknowledgment. By sending this message, the client informs the AP that the installation of keys (temporal keys) was successful.

However, both ANonce and SNonce values are essential for both the client and the AP to derive the PTK, which is used to encrypt and authenticate data frames during that session.

In summary, during a 4-way handshake:

- The ANonce is generated by the AP and remains constant.
- The SNonce is generated by the client and remains constant.
- These nonce values, along with other data (like MAC addresses), are used to derive the session keys, ensuring the security of the wireless connection.

## Hashcat Nonce-Error-Correction

Nonce-error-correction is a method used by tools like Hashcat to attempt to recover the PSK even when there might be slight discrepancies or errors in the captured nonces. The goal of nonce-error-correction is to account for common capture errors and improve the likelihood of successfully cracking the handshake.

To understand when nonce-error-correction can be applied, it's essential to grasp how the 4-way handshake and WPA encryption work. One of the key components of the 4-way handshake is the generation of the Pairwise Transient Key (PTK). The PTK is derived from:

- The pre-shared key or PMK
- The ANonce (from the Access Point)
- The SNonce (from the client)
- The MAC addresses of both the client and the AP

If any of these values change, even slightly, the PTK changes as well, leading to a different MIC. A mismatch in the MIC means the handshake capture cannot validate the PSK.

Considering this, nonce-error-correction comes into play in the following scenarios:

1. **Partial Nonce Matching**: If the majority of the nonce matches but a few bytes are off, Hashcat tries to correct these discrepancies. This error often happens due to issues in capturing packets or slight differences in nonce generation methods among different devices.

2. **Replay Counter (RC) Analysis**: The Replay Counter (RC) in the 4-way handshake ensures that old communication cannot be replayed to appear as new. If an attacker captures multiple handshakes from the same device, they might observe slight discrepancies in the nonces across these handshakes. By analyzing the RC, Hashcat can guess which nonces are likely to be correct. If the RC values are sequential or near-sequential, it's a good indication that the nonces are part of the same handshake sequence, increasing the chances that nonce-error-correction can recover the correct nonce.

Where nonce-error-correction **might not be effective**:

1. **Significant Nonce Mismatch**: If there's a considerable mismatch in the captured nonce compared to the actual nonce used during the handshake, nonce-error-correction might not be able to recover the correct nonce. The derived PTK would be significantly different, making it challenging to get the correct MIC and thus validate the PSK.

2. **Discrepancies in RC Values**: If there's a significant gap or irregularities in the RC values across captured handshakes, it makes it challenging to determine which nonce is the correct one. It's harder to apply nonce-error-correction effectively in such cases.

It's essential to note that nonce-error-correction is an advanced technique that tries to account for imperfections in handshake captures. While it can significantly improve the chances of cracking a WPA handshake, it's not guaranteed to work in all scenarios. The more accurate and complete the captured handshake data, the higher the likelihood of successfully deriving the PSK without needing such corrections.

## PMKID Overview:

1. **What is PMKID?**  
The PMKID is derived from the PMK (Pairwise Master Key). In a typical WPA2 authentication, the PMK is derived from the pre-shared key (the Wi-Fi password) and the SSID of the network. The PMKID, in turn, is a function of the PMK, the AP's MAC address, and the client's MAC address.

2. **Where is PMKID used?**  
The PMKID is used in RSN IE (Robust Security Network Information Element) of the EAPOL frame during the association process.

### PMKID vs. 4-way Handshake:

1. **Capture Requirement**:  
   - **4-way Handshake**: You need to capture the entire 4-way handshake between the client and the AP, which means you must wait for a device to connect (or force a reconnection) to capture this handshake.
   - **PMKID**: You only need to capture the RSN IE from the first EAPOL frame during the association. No need for the client to fully authenticate.

2. **Vulnerability Exploited**:  
   - **4-way Handshake**: Relies on capturing both nonces (ANonce and SNonce) and then attempting to compute the MIC to verify a guessed password.
   - **PMKID**: The vulnerability discovered involves the fact that the PMKID is a function of the PMK, AP's MAC address, and the client's MAC address. By capturing the PMKID and knowing the other elements (like MAC addresses), you can attempt to reverse the computation with a guessed password.

3. **Attack Complexity**:  
   - **4-way Handshake**: Requires waiting for a device to connect or reconnect, making it more time-consuming, especially if there are no clients currently connecting to the target network.
   - **PMKID**: Makes the process faster as it doesn't need a full connection. Simply requesting the association is enough, which is much more common.

4. **Applicability**:  
   - **4-way Handshake**: Applicable to all WPA/WPA2 networks.
   - **PMKID**: Not all routers or devices are vulnerable to this method. However, a significant number of modern devices are.

### Why is PMKID Important?

The discovery of the PMKID method made it faster and more efficient to crack Wi-Fi passwords. Instead of waiting for a device to connect, attackers can now capture the required information more quickly. For defenders or those interested in network security, this underlines the importance of using a strong, unique password for Wi-Fi networks.

In conclusion, while the 4-way handshake remains a cornerstone of WPA2 security, the PMKID offers an alternative route for potential attackers, making it a significant concern in the world of Wi-Fi security.
