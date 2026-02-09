
# ReadableCryptoMiner

Educational Python 3 code for understanding Monero-era `CryptoNight` mining and Stratum/JSON-RPC interactions.

## Project Status

This project is **deprecated for real Monero mining**.

Monero switched its Proof-of-Work algorithm from CryptoNight-family variants to **RandomX** on **2019-11-30** (network upgrade at block **1978433**). This repository still targets CryptoNight-era logic, so it is useful as a learning/reference project, not as a current XMR miner.

## Historical Context (Monero PoW)

- 2018-04-06: network upgrade to CryptoNight variant 1 (`CNv1`)
- 2018-10-18: network upgrade to CryptoNight variant 2 (`CNv2`)
- 2019-03-09: network upgrade to CryptoNight-R (`CN/R`)
- 2019-11-30: network upgrade to **RandomX** (current PoW family for Monero mainnet)

References:

- https://docs.getmonero.org/proof-of-work/cryptonight/
- https://docs.getmonero.org/proof-of-work/random-x/
- https://github.com/tevador/RandomX

## Scope and Limitations

- The code is intentionally readable and optimized for learning, not performance.
- The implementation is CPU-only and very slow compared to production miners.
- CLI currently exposes `--algo cryptonight` only.

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
