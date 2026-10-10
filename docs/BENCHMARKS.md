# Mining performance: measured results

All numbers below were **measured** on the development PC with the project's own benchmark (`python -m quantis bench`, also available as `npm run bench` in the website repository, which runs the real mining worker code against an unsolvable target) or with the real website miner. Nothing here is estimated except where marked.

**Machine:** Windows 11 Pro, Intel 64 Family 6 Model 186 (16 logical CPUs), CPython 3.14.0, Node 24, a Chromium-based browser.

## The important caveat: this PC throttles itself

The per-second samples swing by **3–10×** within a single run, for example `[3.44, 3.29, 0.73, 0.72, 0.31, 0.72, 0.73, 0.73, 1.68, 2.91, 3.07, 3.32]` MH/s for 4 workers. The cause is the operating system's power and thermal management, not the miner: the same drop appears in a bare hashing loop with no node code (verified separately). So the useful figures are ranges. In one run, low-power mode even measured higher than normal mode, which only shows how much the machine's clock speed varies.

## Native node miner (Python worker processes)

| Workers | Measured range (MH/s) | Median of 2nd half of run | Expected time per block at launch difficulty (134 million hashes) |
|---|---|---|---|
| 1 | 0.11 – 0.79 | 0.24 | ≈ 9.4 min |
| 2 | 0.22 – 1.69 | 0.43 | ≈ 5.3 min |
| 4 | 0.31 – 3.44 | 2.9 – 3.1 | ≈ 45 s when not throttled |
| 1, low-power | 0.12 – 0.50 | 0.12 – 0.38 | ≈ 6 – 18 min |

Runs: 2026-10-09 17:01 (4 s), 2026-10-10 07:32 (12 s, while the test suite was also running), 2026-10-10 07:34 (12 s, isolated).

## Browser miner (JavaScript Web Workers)

| Threads | Measured | Notes |
|---|---|---|
| 2 | 0.43 – 0.47 MH/s (also 1.39 MH/s in a burst) | found 3 real blocks in 20 s at the *old*, easy difficulty |
| 8 | **1.58 MH/s** sustained over 65 s | found a real block at the new launch difficulty after 110 s (expected ≈ 85 s) |

## Raspberry Pi

**Not measured**: no Raspberry Pi was available. Run `python -m quantis bench` on the Pi and add the results here. Based on typical single-core SHA-256 performance, we *expect* a Pi 4 to manage very roughly 0.1–0.3 MH/s per core in Python. If it were the only miner at launch, a block would take tens of minutes until the first difficulty retarget (block 30). After that the difficulty can fall by up to 2.5× every 10 blocks, down to the floor of about 1 million hashes per block, which a Pi can always meet.

## How to reproduce

```bash
python -m quantis bench --workers 1,2,4
```

For the browser, log in, open **Mine**, choose the threads, and read "Your speed" after about a minute.
