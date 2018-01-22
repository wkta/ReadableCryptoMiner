# Simple-XMR-Miner

Monero CPU miner written in python3 for learning purpose.
Heavily inspired from https://github.com/ricmoo/nightminer/ but uses JSON RPC 2.0 and cryptonight algorithm.

The miner is in python 3, the hash function is in C (see the folder cryptonight_lib/)
It is slow, about 40% of best miners on my system.
I may try to implement a miner only in C.

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
  
  
