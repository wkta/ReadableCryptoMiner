# ~ main file ~
#
# Provided under the MIT+LGPLv3 rules, see LICENSE file for more info
#
# This miner has been written for learning purpose only,
# heavily inspired from https://github.com/ricmoo/nightminer/
import argparse
import sys

import Utils
from Miner import Miner
from Utils import log, LEVEL_INFO


def test_job(given_miner):
    """
    this tests only the old version of CryptoNight (before Cn/V4) and it shows how the miner
    behaves when the share has been found properly.
    """
    job_msg = {
        "blob": "0505ad91b1cb05473f162f06104953ab34112ea403d365f3e83f339c44328ca3dbd87ba7e62f4a00000000557056bfa4105\
abde09055edea9a0a5d3f333412a74bc96417a23bc68f8d73e405",
        "job_id": "488788125594146", "target": "285c8f02"
    }

    job_context = given_miner._subscription.prepare_job(job_msg)
    given_miner._subscription._id = "dummy"
    job = given_miner._subscription.create_job(job_context)
    log("start test job", LEVEL_INFO)
    for result in job.mine(nonce_start=0x24000000):
        log("Found share: " + str(result), LEVEL_INFO)
    log("end test job", LEVEL_INFO)
    # expected_result = {
    #     "id": "523289590119384", "job_id": "218283583596348", "nonce": "24000082",
    #     "result": "df6911d024c62d910e53b012f6b8ed0eedfaf53f60819e261207d91044258202"
    # }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="CPU-Miner for cryptocurrency using the cryptonight\
         pow algorithm and the stratum protocol (JSON RPC2)"
    )

    parser.add_argument("-a", "--algo", default="cryptonight", choices=["cryptonight"],
                        help="hashing algorithm to use for proof of work")
    parser.add_argument("-o", "--url", help="stratum mining server url (eg: stratum+tcp://foobar.com:3333)")
    parser.add_argument("-u", "--user", dest="username", default="", help="username for mining server")
    parser.add_argument("-p", "--pass", dest="password", default="", help="password for mining server")
    parser.add_argument('-t', '--thread', default="1", help="Number of mining threads to start")
    parser.add_argument('-d', '--debug', help="show extra debug information")
    options = parser.parse_args(sys.argv[1:])
    if options.debug:
        Utils.DEBUG = True

    if options.url:
        miner = Miner(options.url, options.username, options.password, options.algo, int(options.thread))

        # dummy test
        # test_job(miner)
        # sys.exit(1)

        miner.serve_forever()
    else:
        parser.print_help()
