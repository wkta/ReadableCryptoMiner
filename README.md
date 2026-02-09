
# ReadableCryptoMiner

Educational Python 3 code for understanding Monero-era `CryptoNight` mining and Stratum/JSON-RPC interactions.

## Project Status

This project is **deprecated for real Monero mining**.

Monero switched its Proof-of-Work algorithm from CryptoNight-family variants to **RandomX** on **2019-11-30** (network upgrade at block **1978433**).

Strictly speaking, this repository implements a **CryptoNight variant=1 style path (Apr 2018 era)** and is **not** a RandomX miner. It is also **not** a complete CryptoNight v4 / CryptoNight-R implementation.

Use this repository as educational/reference code only, not as a current XMR miner.

## Historical Context (Monero PoW)

1. CryptoNight v0 from genesis (block `0`, 2014-04-18)
2. CryptoNight v1 at block `1546000` (2018-04-06)
3. CryptoNight v2 at block `1685555` (2018-10-18)
4. CryptoNight v3 / CryptoNight-R (`CN/R`, often called `CNv4` in miner tooling) at block `1788000` (2019-03-09)
5. RandomX v0 at block `1978433` (2019-11-30)

References:

- https://docs.getmonero.org/proof-of-work/cryptonight/
- https://docs.getmonero.org/proof-of-work/random-x/
- https://github.com/tevador/RandomX

## Scope and Limitations

- The code is intentionally readable and optimized for learning, not performance.
- The implementation is CPU-only and very slow compared to production miners.
- CLI currently exposes `--algo cryptonight` only, with code paths tied to CryptoNight `variant=1` behavior.

## Command Line Interface

```text
ggminer.py [-h] [-a {cryptonight}] [-o URL] [-u USERNAME] [-p PASSWORD] [-t THREAD] [-d DEBUG]

optional arguments:
  -h, --help                       show this help message and exit
  -a, --algo                       hashing algorithm to use for proof of work {cryptonight}
  -o URL, --url URL                stratum mining server url (e.g. stratum+tcp://foobar.com:3333)
  -u USERNAME, --user USERNAME     username for mining server
  -p PASSWORD, --pass PASSWORD     password for mining server
  -t THREAD, --thread THREAD       number of mining threads to start
  -d, --debug                      show extra debug information
```

## Quick Start (Legacy Demo)

```shell
python src/rd_cryptominer/ggminer.py --url stratum+tcp://example.com:3333 --debug 2
```

Use this as a protocol/hash experimentation entry point, not for production mining.

## Config File Format

```json
{
  "wallet": "YOUR_XMR_ADDRESS",
  "rigName": "YOUR_WORKER",
  "email": "YOUR_EMAIL"
}
```

## License

The code is licensed under MIT + LGPLv3. See `LICENSE` for details.
