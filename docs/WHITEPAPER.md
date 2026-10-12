# QuantisCoin: a proof-of-work currency anyone can mine

**Om Palsule** · Version 1.0 · October 2026 · Public beta

> QuantisCoin is in a public beta that will last at least one month. During the beta, QTS has no cash value, is not sold by the project, and is not traded on any exchange. This paper describes a technical design. It is not an offer of anything, and it makes no claim about what QTS is or will be worth.

## Abstract

QuantisCoin (QTS) is a cryptocurrency with its own blockchain, built from scratch. It follows Bitcoin's core design: a chain of blocks secured by SHA-256d proof of work, unspent-transaction-output (UTXO) accounting, secp256k1 signatures, a hard cap on supply, and a block reward that halves on a fixed schedule. It changes three things. Mining is open to anyone with a web browser, because the network hands out ready-made block templates that a browser can solve and that every node then fully verifies. Blocks are deliberately slow (one every 30 minutes) to keep the chain small and the reward per block meaningful. And the difficulty controller is damped and clamped so that a small, fast-changing group of miners cannot make block times swing wildly. This paper sets out the rules, the reasons for them, the security model, and the limits that are still open.

## 1. Motivation

Bitcoin proved that a currency can run without a central issuer: anyone can check every rule, and new coins come only from a public, predictable schedule. In practice, though, mining Bitcoin now requires specialised hardware, so taking part in issuance is closed to almost everyone.

QuantisCoin keeps Bitcoin's rules but resets the starting line. Its goals are:

1. **Verifiable by anyone.** Every rule is short, written down as integer arithmetic, and checked by every node on its own.
2. **Mineable by anyone.** A laptop and a browser tab are enough to take part, and the website does not need to be trusted to do so.
3. **Predictable and scarce.** A fixed maximum supply of 10 million QTS and a fixed, public issuance schedule.
4. **Cheap to run.** Slow blocks and small limits keep the full chain light enough for a Raspberry Pi.

## 2. Ledger and transactions

QuantisCoin uses the UTXO model. Every coin is an unspent output of an earlier transaction, locked to the 20-byte hash of a public key. A transaction spends whole outputs and creates new ones; the difference between inputs and outputs is the fee.

- **Signatures:** ECDSA over secp256k1, strict DER encoding, low-S only (so a signature cannot be altered into a second valid form).
- **Signature hash:** commits to the whole transaction and to the network identifier, so a transaction signed on one network is invalid on any other.
- **Units:** 1 QTS = 10⁸ quanta. All amounts and checks are exact integers.
- **Addresses:** Base58Check with a version byte, so typing errors are caught before anything is sent.
- **Limits:** blocks up to 64 000 bytes, transactions up to 16 000 bytes, at most 64 inputs and 64 outputs each.

## 3. Blocks and proof of work

Each block has a 124-byte header containing the version, height, previous block hash, Merkle root of its transactions, timestamp, target and a 64-bit nonce. A block is valid only if

```
SHA-256(SHA-256(header)) ≤ target
```

read as a 256-bit integer. The expected number of attempts to find a block is 2²⁵⁶ / (target + 1). Nodes always follow the valid chain with the most cumulative work, not the longest one.

The transaction root is a tagged Merkle tree (leaves and inner nodes are hashed with different prefixes, and an odd node is promoted rather than duplicated), which closes the duplicate-transaction ambiguity known from Bitcoin's original tree.

## 4. Monetary policy

| Parameter | Value |
|---|---|
| Initial block reward R₀ | 25 QTS |
| Halving interval H | 200 000 blocks (about 11.4 years) |
| Target block time | 30 minutes |
| Coins per day at the start | about 1 200 QTS |
| Coinbase maturity | 10 blocks (about 5 hours) |
| Maximum supply | 2·H·R₀ = 10 000 000 QTS |

The reward for block h ≥ 1 is ⌊R₀ / 2^k⌋ with k = ⌊(h − 1)/H⌋, computed as an exact integer shift. Over the real numbers the total is the geometric series H·R₀·(1 + ½ + ¼ + …) = 2·H·R₀. Because each era rounds down, the exact issued total is H·(2·R₀ − popcount(R₀)) quanta = 9 999 999.978 QTS. Half of all coins are issued in the first era (about 11.4 years); the subsidy reaches zero after era 31, after which miners are paid by fees alone.

There is **no pre-mine**: the genesis block creates no coins, and every coin in existence was mined under the same public rules.

## 5. Difficulty

A young network's mining power changes quickly as people start and stop. QuantisCoin recalculates the target every W = 10 blocks with a damped, clamped controller:

```
E  = W · 1800 s
A  = median-time-past(h−1) − median-time-past(h−1−W)
A' = clamp(A, E/4, 4·E)
target(h) = min(pow_limit, ⌊ target(h−1) · (E + A') / (2·E) ⌋)
```

Using the median of the last 11 timestamps rather than raw timestamps limits what one dishonest miner can do with the clock. With damping d = 2, the error from a step change in mining power halves every window; with clamp c = 4, difficulty can rise at most 1.6× or fall at most 2.5× per window, so a single burst of fast or slow blocks cannot swing it far. A minimum difficulty (pow_limit, about 67 million hashes per block) stops the chain becoming trivially easy when few people mine.

## 6. Browser mining

The network offers logged-in users "work": a full block template whose reward pays the user's own address, sent as the first 116 bytes of the header plus the target. The browser searches nonces with SHA-256d in background threads and returns a solution. The node then rebuilds the block and runs it through exactly the same validation as a block from any other source.

This has three useful properties:

- **The website cannot cheat the miner.** The payout address is fixed in the template the miner works on.
- **The miner cannot cheat the network.** A solution is accepted only if it meets the target, so rewards always correspond to real work.
- **No special hardware or software.** Any device with a browser takes part. Native node software is available for people who prefer it.

Browser mining is less efficient than native code, and if specialised SHA-256 hardware ever joins the network, browser miners will earn a smaller share. That is a property of proof of work, not something the protocol can prevent.

## 7. Network

Nodes speak a small HTTP protocol (hello, block locators, block and transaction download and push, mempool exchange). Every request carries the network identifier, so nodes on different networks ignore each other. Untrusted input is size-limited and fully validated; malformed data adds misbehaviour points, and a node that reaches 100 is disconnected for a period.

A new node needs no permission to join. The default configuration connects outward to the public network, so it works behind a home router with no open ports. It downloads and checks every block itself.

## 8. Fees

Fees are paid per byte. The consensus floor is 1 quantum per byte. Above that, each node's relay policy rises linearly with how full its memory pool is, from 10 to at most 80 quanta per byte, so fees stay bounded and predictable. A typical payment costs a fraction of a cent's worth of QTS. Miners include the highest fee-rate transactions first.

## 9. Security model and known limits

- **51% attacks.** Like every proof-of-work chain, an attacker controlling most of the mining power could reverse recent transactions. A small network is more exposed. Waiting for more confirmations reduces the risk for large payments.
- **One public server today.** Most users currently reach the network through one website and one main node. Independent nodes run by other people make the network more resilient, and the software is designed for that.
- **Hosted wallets.** Website wallets are encrypted with each user's password using scrypt and AES-GCM; the server cannot spend them without that password, but users who lose both their password and backup cannot recover their coins.
- **Not yet audited.** The code has its own test suite (consensus, difficulty, networking, wallet and web layers), but it has not had an independent third-party security audit. One is planned before QuantisCoin leaves beta.

## 10. Beta and what comes next

The current network is a public beta that will last at least one month. The goal of the beta is to find problems while the coins carry no cash value. The intention is that balances earned during the beta carry over to the official launch, but this is not guaranteed.

Planned work, in rough order:

1. An independent security review of the consensus and wallet code.
2. More independent nodes, so the network does not depend on one server.
3. A dedicated domain and published release signatures for the node software.
4. A native high-performance node and miner.

Ideas that are being studied but are **not** commitments: programmable transactions, and forms of "useful work" in place of pure hashing.

## 11. References

- S. Nakamoto, *Bitcoin: A Peer-to-Peer Electronic Cash System*, 2008.
- SEC 2: Recommended Elliptic Curve Domain Parameters (secp256k1), Certicom Research.
- The full QuantisCoin protocol specification, with every formula and its tests: [SPEC.md](SPEC.md).
