# ReadableCryptoMiner

Monero CPU miner fully written in python3, for learning purpose only!
Heavily inspired from https://github.com/ricmoo/nightminer/ but uses JSON RPC 2.0 and cryptonight algorithm.

The miner is fully written in python 3.
**It is extremely slow and therefore not suited for mercantile use.**

## Command Line Interface

    ggminer.py [-h] [-a {cryptonight}] [-o URL] [-u USERNAME] [-p PASSWORD] [-t THREAD] [-d DEBUG]

    optional arguments:
      -h, --help                       show this help message and exit
      -a, --algo                       hashing algorithm to use for proof of work {cryptonight}
      -o URL, --url URL                stratum mining server url (eg: stratum+tcp://foobar.com:3333)
      -u USERNAME, --user USERNAME     username for mining server
      -p PASSWORD, --pass PASSWORD     password for mining server
      -t THREAD, --thread THREAD       number of mining threads to start
      -d, --debug                      show extra debug information
  
## License

The code is licensed under MIT + LGPLv3, see LICENSE file for more info.
