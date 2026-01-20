# E4sy_P3asy CTF Challenge

## Challenge Info
- **Type**: Reverse Engineering
- **File**: `E4sy_P3asy.ks` (64-bit ELF)
- **Problem**: The binary validates a flag character-by-character using MD5 hashes of a salt + index + char.

## Files
- `E4sy_P3asy.zip`: Original challenge archive.
- `E4sy_P3asy.ks`: Extracted executable.
- `solve.py`: Python solver script.
- `overlay.bin`: Large overlay extracted from the binary (mostly nulls).

## Solution
The solution is implemented in `solve.py`. It works by:
1. Reading the binary to find the stored target MD5 hashes.
2. Brute-forcing each character position to find the matching hash.

### Usage
```bash
python solve.py
```

## Flags
- Decoy Flag (Length 13): `Th1s_1s_D3c0y`
- **Real Flag (Length 23):** `KCTF{_L0TS_oF_bRuTE_foRCE_:P}`
