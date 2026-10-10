# Security model, limitations and known risks

QuantisCoin uses standard, well-reviewed cryptography (SHA-256, secp256k1 ECDSA via OpenSSL, scrypt, AES-256-GCM). **That alone does not make it secure.** It has not been audited, and its network is small. Do not use it to hold anything of value.

## What is protected, and how

| Threat | Protection | Tested by |
|---|---|---|
| Spending someone else's coins | ECDSA secp256k1 signatures over a sighash that commits to the whole transaction and the network magic | `test_tx_security.py` |
| Double spending | UTXO set; a spent output is deleted; mempool rejects conflicts; blocks with conflicting spends are invalid | `test_tx_security.py`, `test_chain.py` |
| Replay on another network | network magic in every signature hash | `test_encoding.py` |
| Signature/txid malleability | strict DER + low-S required | `test_tx_security.py` |
| Creating coins from nothing | coinbase ≤ subsidy + fees; maturity; amount range checks | `test_tx_security.py` |
| Fake proof of work / wrong difficulty | every node recomputes the expected target and checks the hash | `test_chain.py`, `test_difficulty.py` |
| Timestamp manipulation | must exceed the median of the last 11 blocks; at most 120 s in the future | `test_chain.py` |
| Corrupted state after a crash | each block connect/reorg runs in one SQLite transaction | `test_chain.py::test_atomic_rollback_on_failure` |
| Malformed / oversized network messages | strict decoding, size limits, misbehaviour scores and bans | `test_p2p.py`, `test_encoding.py` |
| Password guessing | scrypt hashes; per-user and per-IP rate limits (10 / 30 attempts per 15 min) | `test_api.py` |
| Stolen session cookie via script | HttpOnly, SameSite=Strict, Secure over HTTPS; strict Content-Security-Policy | `test_api.py` |
| Cross-site request forgery | Origin check on every state-changing request + SameSite cookies | `test_api.py` |
| DNS rebinding | Host header allow-list (`allowed_hosts`) | `test_api.py` |
| Someone claiming a new public server | first administrator needs a one-time code printed on the server console | `test_api.py` |
| Leaking keys in responses or logs | no endpoint returns seeds/keys; a test scans every response | `test_api.py::test_full_flow` |
| Browser miner cheating | the server builds the block (payout fixed) and fully validates every solution | `test_api.py::test_browser_mining_pays_the_user` |

## Important limitations

* **Hosted wallets are custodial-ish.** Wallet seeds are encrypted with the user's password and only decrypted briefly to sign, but the password travels to the server on login and when sending. A malicious or compromised server operator could capture it. A real deployment needs keys kept in the user's device (non-custodial).
* **Passwords cannot be recovered**, by design. Losing both the password and the backup file loses the coins.
* **51% attacks are cheap** on a small network: anyone with more hash power than everyone else combined can rewrite recent blocks and double-spend. Wait for more confirmations for larger amounts.
* **P2P traffic is plain HTTP** without encryption or peer authentication. Misbehaviour bans use the address a peer claims, which can be spoofed. Eclipse and Sybil attacks are not addressed.
* **No reorg depth limit or checkpoints.** A very long competing chain with more work would be accepted.
* **ECDSA nonces** come from OpenSSL's random generator (no RFC 6979 deterministic nonces). OpenSSL's generator is good, but deterministic nonces remove a class of risk.
* **Key derivation** (HMAC-SHA512 of the seed) is a QuantisCoin design, not BIP-32/39, so wallets are not compatible with other software.
* **Rate limits and the session store are in memory / single-process.** Fine for one home server, not for a large site.
* **Denial of service:** request size limits and rate limits exist, but a determined attacker can still exhaust a home connection or CPU. Cloudflare Tunnel helps.
* **Dollar values** use an operator-set reference price, not a market price.
* **Python performance:** validation is single-threaded; a huge block flood would be slow to process.

## Operating safely

If you host the QuantisCoin website, follow the checklist in its hosting guide (`docs/HOSTING.md` in the website repository): claim the admin account before going public, never expose port 8080 directly, use HTTPS with `cookie_secure = "always"`, set `allowed_hosts`, keep the system updated, and back up `data/server/`.

## Reporting problems

Write down what happened, the time, and the server log (`pm2 logs quantiscoin`). Never post wallet backup files or passwords anywhere.
