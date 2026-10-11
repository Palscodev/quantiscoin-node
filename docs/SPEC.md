# QuantisCoin Protocol and Mathematical Specification

Version 1 (software 0.2.0). The normative source is the code in `backend/quantis/core/`. This document explains it and is checked by the tests in `backend/tests/`. Where they disagree, the code is what nodes enforce, so that is a documentation bug.

> QuantisCoin is an educational cryptocurrency. Its coins currently have no market value. Nothing here makes it secure for real funds (see [SECURITY.md](SECURITY.md)).

---

## 1. Design options and the choice

Three mathematically distinct designs were considered:

| | **A. Quantis (chosen)** | B. Continuous decay + ASERT | C. Fee-feedback economy |
|---|---|---|---|
| Issuance | Era-step geometric series, R_k = ⌊R₀/2^k⌋ | Per-block exponential decay R(h) = R₀·2^(−h/H) in fixed point | Halvings plus a perpetual tail emission |
| Difficulty | Windowed, damped, bounded proportional controller (Digishield-like) | Absolutely scheduled exponential target (BCH "aserti3-2d") | As A |
| Fees | Bounded linear congestion multiplier (relay policy) + consensus floor | As A | EIP-1559-style consensus base fee, ×(1 ± 1/8) per block |
| Strength | Every rule is closed-form integer arithmetic a student can verify by hand. One theme, geometric convergence, runs through issuance and control. | Smooth, responsive, elegant | Interesting closed control loop |
| Weakness | Reacts to hash-rate shocks over several windows | Fixed-point 2^x approximation is hard to audit | Fee state becomes consensus-critical; more attack surface |

**Unifying idea.** Zeno's series ½ + ¼ + ⅛ + … = 1 appears twice in the protocol. Total supply converges to 2·H·R₀. The difficulty controller's error shrinks by a constant factor (1 − 1/d) every window. These are *design choices* built on standard results (sums of geometric series, first-order linear recurrences). No new mathematics is claimed, except as noted in §9.

## 2. Units and encoding conventions

* 1 QTS = 10⁸ **quanta**. All consensus amounts are non-negative integers of quanta, so floating point is never used in consensus.
* Integers are little-endian fixed width (`u32`, `u64`). Variable counts use CompactSize `varint` (Bitcoin encoding) and **must be minimally encoded**.
* `SHA-256d(x) = SHA-256(SHA-256(x))`.
* 256-bit targets are big-endian. Hashes are displayed as plain big-endian hex of the digest bytes. Unlike Bitcoin, there is no byte reversal.

## 3. Monetary policy

Bitcoin-style issuance, scaled to a 10-million-coin cap.

| | devnet (the real network) | regtest (automated tests only) |
|---|---|---|
| Initial reward R₀ | **25 QTS** = 2.5·10⁹ quanta | 1 000 QTS |
| Halving interval H | **200 000 blocks** (≈ 139 days at 60 s) | 10 blocks |
| Coinbase maturity | **10 blocks** (≈ 10 minutes) | 3 blocks |
| Target block time | **60 s** | 15 s |

For height h ≥ 1 the **reward era** is k = ⌊(h − 1)/H⌋ and the subsidy is

```
R_k = ⌊R₀ / 2^k⌋  =  R₀ >> k        (exact integer right shift)
```

The genesis block (h = 0) issues nothing and has no spendable outputs. **Block 1 is the first block that pays 25 QTS.** Rewards are 25, 12.5, 6.25, 3.125, … QTS, each for 200 000 blocks, exactly like Bitcoin's 50 → 25 → 12.5 schedule.

**Theoretical maximum supply.** Over the real numbers,

```
S = Σ_{k≥0} H·R₀/2^k = H·R₀ · 1/(1 − ½) = 2·H·R₀ = 2 · 200 000 · 25 = 10 000 000 QTS
```

**Realized supply.** Flooring loses the fractional part in every era. For any integer n ≥ 0,

```
Σ_{k≥0} ⌊n/2^k⌋ = 2n − popcount(n)
```

(Proof sketch: write n in binary. Bit i contributes 2^i + 2^(i−1) + … + 1 = 2^(i+1) − 1 across all shifts, and summing over the set bits gives 2n − popcount(n).) R₀ = 2.5·10⁹ quanta has popcount 11, so

```
S_int = H · (2·R₀ − 11) quanta = 200 000 · 4 999 999 989 = 999 999 997 800 000 quanta = 9 999 999.978 QTS
```

Rounding destroys exactly 11·H quanta (0.022 QTS). The subsidy is 1 quantum in era 31 and **0 from era 32 onward**, because 2.5·10⁹ < 2³². That is 32 × 200 000 = 6.4 million blocks, about 12 years at one block per minute. After that, miners earn only fees. `MAX_MONEY` = 2·H·R₀ = 10⁷ QTS bounds every amount and every sum in consensus checks.

**Configurable H.** H is consensus-critical: it is included in the network magic, so changing it creates a different network. Tests: `test_monetary.py`, which covers the 25 → 12.5 → 6.25 sequence, era boundaries, exhaustion at era 32, the popcount identity, the exact realized supply, era-edge cumulative sums, and that a changed H changes the magic.

## 4. Blocks

### 4.1 Header (exactly 124 bytes)

| Offset | Field | Encoding |
|---|---|---|
| 0 | version | u32 (= 1) |
| 4 | height | u64 |
| 12 | prev_hash | 32 bytes |
| 44 | merkle_root | 32 bytes |
| 76 | timestamp | u64, Unix seconds |
| 84 | target | 32 bytes, big-endian uint256 |
| 116 | nonce | u64 |

`block_hash = SHA-256d(header)`. The proof of work is valid iff `int.from_bytes(block_hash, "big") ≤ target`. The nonce is last, so a miner computes the SHA-256 state of bytes 0–115 once and then hashes only 8 bytes per attempt.

### 4.2 Block body
`block = header ‖ varint(n_tx) ‖ tx₀ ‖ … ‖ tx_{n−1}`. tx₀ must be the only coinbase.

### 4.3 Transaction root (tagged Merkle tree)

```
leaf(txid) = SHA-256d(0x00 ‖ txid)
node(L, R) = SHA-256d(0x01 ‖ L ‖ R)
```

Each level pairs adjacent nodes from left to right, and **an odd last node is promoted unchanged**. Bitcoin instead duplicates it, which lets [a, b, c] and [a, b, c, c] share a root (CVE-2012-2459). Tagging prevents a leaf from being confused with an interior node.

### 4.4 Resource limits (consensus)
Block ≤ 64 000 bytes. Transaction ≤ 16 000 bytes, ≤ 64 inputs, ≤ 64 outputs. Pubkey ≤ 33 bytes; signature 1–72 bytes. Block size is fixed and never adapts.

## 5. Transactions (UTXO model)

```
tx     = version:u32 ‖ varint(n_in) ‖ input* ‖ varint(n_out) ‖ output* ‖ locktime:u32
input  = prev_txid:32 ‖ vout:u32 ‖ varbytes(pubkey) ‖ varbytes(sig)
output = amount:u64 ‖ h20:20
```

* `txid = SHA-256d(serialize(tx))`.
* `sighash = SHA-256d("QUANTIS/sig/v1" ‖ magic:4 ‖ serialize(tx with every sig = empty))`. Each input commits to the whole transaction, including every input's public key and every output. Including the 4-byte network **magic** means a signature for one network is invalid on any other (cross-network replay protection).
* **Signatures:** ECDSA over secp256k1 from the `cryptography` library (OpenSSL). Two consensus rules make signatures non-malleable: the DER encoding must be strict (it must re-encode identically), and s ≤ n/2 (**low-S**). The txid therefore cannot be changed by a third party.
* **Address:** `Base58Check(0x3A ‖ h20)`, where `h20 = SHA-256d(compressed_pubkey)[:20]` and the checksum is `SHA-256d(version ‖ h20)[:4]`. RIPEMD-160 is not used because it is unavailable in some OpenSSL 3 builds.
* **Coinbase:** exactly one input with prev_txid = 32 zero bytes, vout = 0xFFFFFFFF, empty pubkey, and sig = height:u64 ‖ ≤ 92 extra bytes. The height makes every coinbase txid unique. The coinbase may have zero outputs.

### 5.1 Transaction validity (non-coinbase)
1. Version 1; 1 ≤ inputs ≤ 64; 1 ≤ outputs ≤ 64; size ≤ 16 000 bytes.
2. Every output amount is in (0, MAX_MONEY], and the running sum is ≤ MAX_MONEY.
3. No input repeats an outpoint, and no input uses the null outpoint.
4. Every input spends an output that is currently unspent in the validating view.
5. A coinbase output is spendable only once `spend_height − creation_height ≥ coinbase_maturity`.
6. `h20(pubkey)` equals the spent output's h20, and the signature verifies against `sighash`.
7. `fee = Σ inputs − Σ outputs ≥ 0` and `fee ≥ size × min_fee_per_byte` (consensus floor, 1 quantum/byte).

**Double spends and replay.** Within a chain, a spent outpoint is deleted from the UTXO set, so any second spend fails rule 4. That covers replay of a confirmed transaction and two conflicting spends, whether they are in one block or across blocks. The mempool also refuses a second spend of an outpoint (first seen wins; there is no replacement).

## 6. Proof of work and difficulty

### 6.1 Relations
For a target T, each hash succeeds independently with probability p = (T + 1)/2²⁵⁶. The number of attempts is geometrically distributed with mean

```
E[hashes] = 2²⁵⁶ / (T + 1),        E[block time] = E[hashes] / (network hash rate)
work(T) = ⌊2²⁵⁶ / (T + 1)⌋,        difficulty = pow_limit / T
```

On devnet, `initial_target` = 2²²⁶, so a block needs about **1.07 billion hashes** on average until the first retarget. `pow_limit` (the easiest target ever allowed) is 2²³⁰, about **67 million hashes**: the difficulty never falls below that, however few people mine. Measured on this project's development PC (see [BENCHMARKS.md](BENCHMARKS.md)): 8 browser threads sustained about 1.6 MH/s, so a lone PC needs about 11 minutes per block at launch difficulty and about 42 s at the floor; one Python worker (about 0.25 MH/s) needs about 4.5 minutes per block at the floor. A Raspberry Pi has not been measured. Once many people mine, the controller raises the difficulty so that the *whole network* finds one block per minute.

### 6.2 Controller
Let W = 10 (retarget window), T_b = 60 s, E = W·T_b = 600 s, d = 2 (damping), c = 4 (clamp).

* If h is not a multiple of W, or h is below the first retarget height, then target(h) = target(h − 1). Block 1 uses `initial_target`, because the genesis target is not inherited.
* The **first retarget height** is the first multiple of W that is ≥ W + mtp_span + 1 = 22, i.e. **h = 30**. This guarantees that neither median used below ever includes the genesis timestamp, which is a fixed constant rather than a real mining time.
* If h is a multiple of W and h ≥ 30, then

```
A  = MTP(h−1) − MTP(h−1−W)          MTP = median timestamp of a block and its 10 predecessors
A' = clamp(A, E/c, c·E)
target(h) = min(pow_limit, max(1, ⌊ target(h−1) · ((d−1)·E + A') / (d·E) ⌋))
```

This is a single floor division on exact integers.

**Bounds.** The per-window factor lies in [((d−1) + 1/c)/d, ((d−1) + c)/d] = **[0.625, 2.5]**: difficulty can rise by at most 1.6× or fall by at most 2.5× every 10 blocks.

**Stability.** Suppose the true hash rate is constant and the target is a fraction x of its equilibrium value. Then A ≈ E/x, and away from the clamp x' = x · ((d−1) + 1/x)/d = ((d−1)·x + 1)/d. The fixed point is x* = 1, and the error evolves as x' − 1 = (1 − 1/d)(x − 1). **The error halves every window**, which is the same kind of geometric series as the issuance schedule. `test_difficulty.py::test_damping_halves_error_geometrically` checks this contraction numerically until it reaches the 1-second timestamp resolution.

**Trade-offs.** Damping and clamping prevent oscillation. They also stop a single fast or slow block, or a single manipulated timestamp, from changing difficulty much. With d = 2 the network reacts quickly (useful for a young network whose hash rate swings a lot); the cost is more jitter from the natural randomness of block times (the sum of 10 exponential block times has a relative standard deviation of about 32%, so each retarget can move difficulty by roughly ±16% from luck alone). After the network's hash power halves, the remaining error is 0.5·(½)^n after n windows, below 5% after about 4 windows (≈ 40 blocks). If every miner stops, no blocks arrive and difficulty stays where it is until mining resumes.

### 6.3 Timestamp rules
* `timestamp > MTP(previous 11 blocks)`: time effectively moves forward, and one dishonest timestamp cannot pull the median back.
* `timestamp ≤ local_clock + 120 s` (devnet; 60 s on regtest): blocks too far in the future are rejected. They are not cached as invalid, so they can be accepted later.
* Clock irregularities: honest nodes need clocks within about a minute of each other. The controller uses MTPs, not raw timestamps.

## 7. Chain selection
The active chain is the valid chain with the greatest **cumulative work** Σ work(target). On equal work the first-seen chain is kept. Reorganization disconnects blocks back to the fork point using stored undo data, then connects the new branch. All of this happens in one SQLite transaction. If any block on the new branch fails full validation, the transaction is rolled back, the previous chain is restored, and the failing block and its descendants are marked invalid (`test_chain.py`).

## 8. Fees

* **Consensus floor** (every block): fee ≥ size × 1 quantum/byte.
* **Relay policy** (local; not consensus):

```
rate(B) = r + ⌊ r·(M − 1)·min(B, B*) / B* ⌋   quanta per byte
r = 10, M = 8, B* = 64 000 bytes; B = current mempool bytes
```

  The multiplier rate/r is bounded to [1, M]. It rises linearly with congestion and saturates at B*. The tests cover an empty mempool (rate 10), a half-full one (45), and a saturated one (80, even for B → ∞).
* The **offered** fee is chosen by the user. The wallet's `preview` shows the offered fee, the relay minimum, and the consensus floor before signing, and `send` signs exactly the reviewed fee.
* **Ordering and selection:** miners sort by fee/size (exact rational comparison), with ties broken by ascending txid. A transaction is added only after all of its unconfirmed parents. Selection continues until the block would exceed 64 000 bytes minus a 300-byte coinbase reserve. The coinbase may claim at most subsidy + Σ fees. Unclaimed value is destroyed.
* **Eviction:** a full mempool evicts its lowest fee-rate transaction (and that transaction's descendants) only for a newcomer with a strictly higher rate.
* **Limitations:** the congestion signal is each node's own mempool, so different nodes may quote different minimums. A bounded formula keeps fees predictable but cannot keep them low when demand persistently exceeds block space.

## 9. Original design choices vs established results

| Item | Status |
|---|---|
| Geometric halving, cumulative-work selection, UTXO model, SHA-256d PoW, secp256k1 ECDSA | Established (Bitcoin) |
| Damped and clamped window retarget | Established in spirit (Zcash/Digishield). The constants, the MTP endpoints and the first-retarget rule are our parameter choices |
| Σ⌊n/2^k⌋ = 2n − popcount(n) | Classical identity: by Legendre's formula, this sum is the exponent of 2 in (2n)! |
| Tagged Merkle tree with odd-node promotion | Known mitigation; our particular encoding |
| Bounded linear congestion multiplier | Our design choice. **Open research question:** across realistic arrival-rate distributions, does M = 8 with a linear ramp produce lower fee variance than an exponential ramp, for the same spam cost? This is testable with mempool simulations and has not been done here. |

## 10. Genesis and network identity
`magic = SHA-256("QUANTIS/net/v1" ‖ canonical_json(NetworkParams))[:4]`. The genesis block is derived entirely from the parameters: a fixed timestamp of 2026-01-01T00:00:00Z, a coinbase with no outputs carrying the genesis message, target = pow_limit, and the smallest nonce that satisfies the PoW. Every node recomputes it at start-up. Run `python -m quantis genesis` to print the result:

| network | magic | genesis hash |
|---|---|---|
| devnet | `eef9c01e` | `000009c2775c91d393eb62ac56a81cb5070315596355833ad183568fb0d18b3d` (nonce 1 785 437) |
| regtest | `70451193` | `71870e80fc67bbcc4719c23da325de1f9bae2ae9dcf4037efd5e16ea06e4dd83` |

## 11. Consensus vs local parameters

| Consensus (changing one creates a new network) | Local (safe to change per node) |
|---|---|
| R₀, H, coinbase maturity, T_b, W, d, c, pow_limit, initial_target, MTP span, future drift, block/tx limits, consensus fee floor, genesis timestamp/message, address version | ports, bind address, advertised URL, peers, discovery, max peers, timeouts, message-size limit, mining workers / low-power / payout, relay fee policy (r, M, B*), mempool size, log level |

## 12. Peer-to-peer protocol (HTTP)
Each request carries `X-Quantis-Magic` (network) and `X-Quantis-Peer` (the sender's advertised URL).

| Method | Path | Purpose |
|---|---|---|
| GET | `/p2p/hello` | agent, protocol, magic, genesis, height, tip, chainwork, known peers |
| POST | `/p2p/hello` `{url}` | register the caller (the URL must point at the caller's own host) |
| GET | `/p2p/blocks?locator=h1,h2,…&limit=n` | active-chain hashes after the first locator hash the server knows |
| GET | `/p2p/block/{hash}` | raw block bytes |
| POST | `/p2p/block` | push a raw block |
| GET | `/p2p/mempool` | pending txids |
| GET | `/p2p/tx/{txid}` | raw pending transaction |
| POST | `/p2p/tx` | push a raw transaction |

The sync loop runs every 3 s per peer. It sends hello. If the peer reports more chainwork, the node downloads using a block locator (hashes at exponentially increasing depth), and every block goes through full validation. Every fifth round it also pulls the peer's mempool. Request bodies are capped at 1 MiB, including chunked bodies. Malformed or invalid data adds misbehavior points: +20 malformed, +50 invalid block, +10 invalid transaction. At 100 points the peer is banned for 10 minutes.
