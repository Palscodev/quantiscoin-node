# QuantisCoin node

The open-source node software for **QuantisCoin (QTS)**, a small proof-of-work cryptocurrency built from scratch as a learning project. Run it on a desktop or a Raspberry Pi to keep your own copy of the blockchain, check every rule yourself, and mine coins with your CPU.

> **Learning project.** QTS is not traded anywhere and has no market value. See [docs/SECURITY.md](docs/SECURITY.md) for the security model and its limitations.

| | |
|---|---|
| Block reward | 25 QTS, halving every 200,000 blocks |
| Maximum supply | 10,000,000 QTS |
| Block time | 60 seconds target; difficulty adjusts every 10 blocks |
| Proof of work | SHA-256d over a 124-byte header |
| Signatures | ECDSA secp256k1, strict DER, low-S |

## Mine with your own computer in 4 steps

**1. Install Python 3.11 or newer** (python.org; on a Raspberry Pi it is already installed).

**2. Download and install.** Windows (PowerShell):

```bash
py -3 -m venv .venv
```

```bash
.venv\Scripts\pip install -r requirements.txt -e .
```

macOS / Linux / Raspberry Pi:

```bash
bash scripts/setup_pi.sh
```

**3. Edit `config/node.toml`:**
* `peers`: the network's peer address, shown on the QuantisCoin website's **Mining** page.
* `[mining] address`: your wallet address from the website (it starts with `Q`). Rewards are paid there.

**4. Start the node:**

```bash
.venv/bin/python -m quantis node --config config/node.toml
```

(On Windows: `.venv\Scripts\python -m quantis node --config config\node.toml`.)

The node downloads the blockchain from its peers, checks every block, and starts mining. Watch it at http://127.0.0.1:8331/api/status. When you find a block, the reward appears in your website wallet and unlocks after 10 more blocks.

Your node connects *out* to the network, so it works behind a normal home router with no port forwarding.

## Measure your mining speed

```bash
.venv/bin/python -m quantis bench --workers 1,2,4
```

Set `workers` in `config/node.toml` to how many CPU processes you want to use (1 is a good choice on a Raspberry Pi; `low_power = true` halves the load).

## Other commands

| Command | Purpose |
|---|---|
| `python -m quantis node --config FILE` | Run a node (API on 127.0.0.1, P2P, optional miner) |
| `python -m quantis bench` | Measure hash rate |
| `python -m quantis policy` | Print the full reward schedule |
| `python -m quantis genesis` | Print the genesis block (every node computes the same one) |
| `python -m pytest` | Run the test suite (`pip install pytest` first) |

`config/devnet-node1..3.toml` start a three-node network on your own computer, and `config/regtest.toml` is a test network with instant blocks.

## What's inside

```
backend/quantis/core/      consensus: blocks, transactions, validation, difficulty, monetary policy, chain state, mempool
backend/quantis/p2p/       peer-to-peer protocol and chain synchronization
backend/quantis/mining/    CPU miner, block templates, browser-mining job server
backend/quantis/wallet/    encrypted keystore and wallet logic
backend/quantis/api/       HTTP API used by wallets and websites
backend/tests/             automated tests (consensus, security, persistence, networking)
docs/SPEC.md               the protocol and its mathematics
```

The full rules (issuance as a geometric series, the damped difficulty controller, fees, chain selection) are explained in [docs/SPEC.md](docs/SPEC.md).

## Contributing

Bug reports and pull requests are welcome. Please run `python -m pytest` before submitting. Never post wallet backup files or passwords in issues.

## License

MIT; see [LICENSE](LICENSE).
