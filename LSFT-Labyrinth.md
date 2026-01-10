# UofT LFSR Labyrinth - UofTCTF 2025

**Ctf** | **Crypto** | **LFSR** | **Z3**

## Description
A quirky 48-bit UofT stream taps through a WG-flavoured filter, leaving 80 bits of trace and a sealed flag. The blueprint is public; the hidden state is the dance you need to unravel.

## Given Files
We are given `LFSR.zip` containing:
- `crypto.py`: Encrypts/decrypts the flag using ChaCha20Poly1305 with a key derived from the LFSR state.
- `filter_cipher.py`: Implements the LFSR and the non-linear filter function (WG-style ANF).
- `challenge.json`: Contains the LFSR taps, filter structure, 80 bits of keystream, nonce, and the encrypted flag.

## Solving
The challenge involves a 48-bit Linear Feedback Shift Register (LFSR) with a non-linear filter function. We are given 80 bits of output (keystream). Since the internal state (48 bits) is smaller than the observed output (80 bits), the system is overdefined and can be solved.

The filter function is complex (WG-style), but since we have the full description and the state size is small, we can use a SAT solver like Z3 to recover the initial state.

The approach is:
1.  **Model the LFSR**: Create 48 symbolic boolean variables for the initial state.
2.  **Simulate Clocking**: For each of the 80 time steps:
    *   Calculate the symbolic output of the filter function.
    *   Constrain it to match the given keystream bit.
    *   Update the symbolic state using the linear feedback function.
3.  **Solve**: Use Z3 to find the 48-bit initial state that satisfies all constraints.
4.  **Decrypt**: Use the recovered state to derive the key and decrypt the flag.

I wrote a solver script using `z3-solver`. It recovered the state in a few seconds.

## Solution

```python
import json
import z3
import filter_cipher
import crypto
import binascii

def solve():
    print("Loading challenge data...")
    with open("challenge.json", "r") as f:
        chal = json.load(f)

    L = chal["L"]
    feedback_taps = chal["feedback_taps"]
    filter_taps = chal["filter_taps"]
    keystream = chal["keystream"]
    nonce_hex = chal["nonce"]
    ct_hex = chal["ct"]
    
    nonce = binascii.unhexlify(nonce_hex)
    ct = binascii.unhexlify(ct_hex)

    # Z3 Solver
    solver = z3.Solver()
    
    # State variables for each step to optimize Z3 performance
    # state_vars[t] is the state at time t
    state_vars = []
    
    # Initial state
    state_0 = [z3.BitVec(f"s_0_{i}", 1) for i in range(L)]
    state_vars.append(state_0)
    
    def z3_eval_anf(bits, terms):
        acc = z3.BitVecVal(0, 1)
        for mon in terms:
            prod = z3.BitVecVal(1, 1)
            for idx in mon:
                prod = prod & bits[idx]
            acc = acc ^ prod
        return acc

    print("Building constraints...")
    
    for t in range(len(keystream)):
        curr_state = state_vars[t]
        known_bit = keystream[t]
        
        # 1. Output Constraint
        taps_bits = [curr_state[i] for i in filter_taps]
        z = z3_eval_anf(taps_bits, filter_cipher.WG_ANF_TERMS)
        solver.add(z == z3.BitVecVal(known_bit, 1))
        
        # 2. State Transition (if not last step)
        if t < len(keystream) - 1:
            fb = z3.BitVecVal(0, 1)
            for idx in feedback_taps:
                fb = fb ^ curr_state[idx]
            
            next_state_vars = [z3.BitVec(f"s_{t+1}_{i}", 1) for i in range(L)]
            solver.add(next_state_vars[0] == fb)
            for i in range(1, L):
                solver.add(next_state_vars[i] == curr_state[i-1])
            state_vars.append(next_state_vars)

    print("Solving...")
    if solver.check() == z3.sat:
        print("SAT!")
        model = solver.model()
        recovered_state = [model[state_vars[0][i]].as_long() for i in range(L)]
        
        try:
            pt = crypto.decrypt(nonce, ct, recovered_state)
            print(f"Flag: {pt.decode()}")
        except Exception as e:
            print(f"Decryption failed: {e}")
    else:
        print("UNSAT")

if __name__ == "__main__":
    solve()
```

## Flag
`uoftctf{l33ky_lfsr_w17h_n0n_l1n34r_fl4v0rrrr}`
