 # 🕵️‍♂️ Orca - CTF Challenge Writeup

**Challenge**: Orca
**Category**: Cryptography
**Status**: ✅ Solved
**Flag**: `uoftctf{l37_17_b3_kn0wn_th4t_th3_0r4c13_h45_5p0k3N_ac9ae43a889d2461fa7039201b6a1a75}`

---

## 1. Scenario Overview

We were presented with a crypto challenge named "Orca". The challenge provided a source code file (`server.py`) and a remote endpoint (`nc 34.186.247.84 5000`). The service implements a custom encryption oracle where user input is combined with a flag, encrypted, and returned. Our goal was to exploit the logic to extract the hidden flag.

## 2. Investigation & Analysis

### 2.1 Source Code Review
Analyzing `server.py` revealed the following key behaviors:
-   **Encryption Algorithm**: AES in **ECB mode** (`AES.MODE_ECB`).
-   **Key Generation**: A random 16-byte key `k` is generated on startup.
-   **Shuffling Mechanism**: The ciphertext blocks are **shuffled** based on a random permutation `q`.
    ```python
    # Shuffling logic
    b=[c[i:i+BS] for i in range(0,len(c),BS)]
    out=[b[i] for i in self.q]
    return out[idx]
    ```
-   **Plaintext Construction**: The plaintext `m` is constructed as:
    `m = p + u + FLAG + padding`
    where `p` is a random prefix (fixed for the session) and `u` is user input.

### 2.2 Vulnerability Identification
While the shuffling attempts to hide the ECBs inherent weakness (identical plaintext blocks -> identical ciphertext blocks), the vulnerability persists because:
1.  **Fixed Permutation**: The shuffle order `q` is constant for the session.
2.  **ECB Proeprties**: If we inject recognizable patterns (e.g., blocks of null bytes), we can identify which shuffled output index corresponds to which logical input block.
3.  **Oracle**: We can query the server repeatedly with chosen plaintexts.

This setup allows for a **Byte-by-Byte ECB Decryption Attack** (chosen-plaintext attack), adapted to account for the shuffled blocks.

## 3. Solution Development

To recover the flag, we implemented a solver script (`solver.py`) that automates the following steps:

### 3.1 Prefix Length Detection
We need to know the length of the unknown prefix `p` to align our input. 
-   **Method**: We sent increasing lengths of `0x00` bytes.
-   **Observation**: When `len(p) + len(u)` is a multiple of 16, and our input `u` contains at least two full blocks of zeros, we observe two identical ciphertext blocks in the output (regardless of their position effectively proving alignment).
-   **Result**: We calculated `len(p) % 16`.

### 3.2 Block Mapping
We needed to map the "logical" block index (where our input lands) to the "shuffled" output index.
-   **Technique**: We found the ciphertext block corresponding to `16 * 0x00` (`C_zero`). We then crafted an input that turns *only specific blocks* into zeros. By observing where `C_zero` appeared in the shuffled output, we built a mapping `logical_index -> shuffled_index`.

### 3.3 Byte-by-Byte Exploitation
With the alignment and mapping known, we performed the standard ECB attack:
1.  **Target**: We want to decrypt the byte at `FLAG[i]`.
2.  **Align**: Pad the input `u` so that `p + u + FLAG[:i]` fills the block exactly up to the last byte. The target byte `FLAG[i]` becomes the last byte of the block.
3.  **Capture**: Retrieve the ciphertext block for this target state.
4.  **Brute-Force**: Locally construct `p + u + FLAG[:i] + guess` for all 256 possible bytes. Query the oracle to see which `guess` produces the same ciphertext block.

## 4. Results & Flag Recovery

We ran the `solver.py` script against the remote server.

### Execution Log
```
[+] Opening connection to 34.186.247.84 on port 5000: Done
Finding pl % 16...
Candidate pl % 16: 15 (shift 1)
Flag so far: u
Flag so far: uo
...
Flag so far: uoftctf{l37_17_b3_kn0wn_th4t_th3_0r4c13_h45_5p0k3N_ac9ae43a889d2461fa7039201b6a1a75}
```

The attack successfully recovered the entire flag string.

## 5. Conclusion

-   **Attacker Method**: Adapted ECB Byte-by-Byte Chosen-Plaintext Attack.
-   **Key Insight**: Even with shuffled blocks, AES-ECB leaks equality patterns. By correlating input patterns with output blocks, the shuffle can be bypassed.
-   **Flag**: `uoftctf{l37_17_b3_kn0wn_th4t_th3_0r4c13_h45_5p0k3N_ac9ae43a889d2461fa7039201b6a1a75}`

---
