# 🔒 Gambler's Fallacy - CTF Challenge Writeup

**Challenge**: Gambler's Fallacy  
**Category**: Crypto / exploit  
**Status**: ✅ Solved  
**Flag**: `uoftctf{ez_m3rs3nne_untwisting!!}`


Here I'll write about the **Gambler's Fallacy** challenge, which involves exploiting a Pseudo-Random Number Generator (PRNG) state leak to predict the future and win a "zillion dollars".

## What the server did

The challenge provided a python script `chall.py` running a dice game. Here's the relevant part of the code:

```python
import random
import hmac
import hashlib

class DiceGame():
    def __init__(self):
        self.balance = 800
        self.client_seed = "1337awesome"
        self.nonce = 0
        with open("./serverseed", 'r') as f:
            random.seed(f.read())

    def roll_dice(self) -> int:
        self.server_seed = random.getrandbits(32)
        nonce_client_msg = f"{self.client_seed}-{self.nonce}".encode()
        sig = hmac.new(str(self.server_seed).encode(), nonce_client_msg, hashlib.sha256).hexdigest()
        # ... logic to convert sig to a number 0-100 ...
        return round((lucky % 1e4) * 1e-2)
```

The game lets you bet money. If you guess a "greed" value correctly (where `roll <= greed`), you win a multiplier. To get the flag, you need $10,000.

The critical flaw is in the game loop output:

```python
print(f"Game {i:05}: Roll: {roll:02}, ... Server-Seed: {self.server_seed}")
```

The server **prints** `self.server_seed` after every roll. This value is generated directly by `random.getrandbits(32)`.

## Where's the leak?

Python's `random` module uses the **Mersenne Twister (MT19937)** algorithm. This PRNG is not cryptographically secure. Its internal state consists of 624 32-bit integers.

If you can observe 624 consecutive outputs from the generator, you can completely reconstruct its internal state. Once you have the state, you can predict **every future random number** it will generate.

Since the server cheerfully prints the 32-bit `server_seed` for every game, we just need to play 624 rounds (betting the minimum to stay alive) to harvest enough data to clone the server's RNG.

## How we turned the leak into an attack

We wrote a solver script that:

1.  **Harvests State**: Connects to the server and plays 624 games with a minimal wager ($1) and a safe "greed" value ($90$) to ensure we don't go bankrupt while collecting seeds.
2.  **Clones RNG**: Uses an "untemper" function to reverse the MT19937 tempering step on each of the 624 collected seeds. This recovers the exact internal state array. We then inject this state into our own local Python `random` instance.
3.  **Predicts & Wins**:
    *   We predict the *next* `server_seed` using our cloned RNG.
    *   We replicate the server's HMAC computations to calculate exactly what the dice roll will be.
    *   We bet our entire balance (or close to it) with `greed = predicted_roll`. This guarantees a win with the maximum possible multiplier for that roll.
    *   We repeat this until we have enough money to buy the flag.

### Solve Script

```python
import socket
import re
import random
import hmac
import hashlib
import time
import sys

# [ ... Untemper and helper functions omitted for brevity ... ]

def solve():
    # Connect and collect 624 seeds
    # ... (code to play 624 games) ...
    
    # Reconstruct State
    print("[*] Reconstructing state...")
    state_vals = [untemper(y) for y in seeds[:624]]
    rng = random.Random()
    rng.setstate((3, tuple(state_vals + [624]), None))
    
    # Predict and Win
    while True:
        # Predict next seed
        next_server_seed = rng.getrandbits(32)
        predicted_roll = get_roll(next_server_seed, "1337awesome", current_nonce)
        
        # Bet aggressively knowing the result
        if 2 <= predicted_roll <= 98:
            wager = balance
            greed = predicted_roll
            # ... send bet ...
        
        if balance > 10050:
            # Buy Flag
            break
```

## Conclusion

This challenge demonstrates why you should never use a non-cryptographic PRNG (like Mersenne Twister) for anything involving money or secrets, especially if you expose its outputs. By simply watching the "random" numbers for a while, we could predict the future perfectly.

**Flag:** 🔓 `uoftctf{ez_m3rs3nne_untwisting!!}`
