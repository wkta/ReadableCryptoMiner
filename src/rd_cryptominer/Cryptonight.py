import binascii
import math

from PowEngine import PowEngine, NonceLayout
from Subscription import Subscription
from crypto_primitives.slow_hash_lgplv3 import slow_hash_glue_func


class CryptonightVariant1Engine(PowEngine):
    """
    CryptoNight variant=1 engine (Apr 2018 era).
    This preserves the repository's current hashing behavior.
    """

    def __init__(self):
        layout = NonceLayout(offset=39, size=4, endian="big", max_nonce=0x7fffffff)
        PowEngine.__init__(self, name="cryptonight", nonce_layout=layout)

    def normalize_target(self, target):
        # Pool target is little-endian hex; compare logic uses big-endian view.
        return "".join([target[i:i + 2] for i in range(0, len(target), 2)][::-1])

    def estimate_difficulty(self, target):
        return math.floor((2 ** 32 - 1) / int(target, 16))

    def compute_pow(self, header):
        output = [None for _ in range(32)]
        slow_hash_glue_func(output, list(header), 76)
        return binascii.hexlify(bytes(output)).decode()

    def share_value(self, pow_hash, target_len):
        tar = pow_hash[-target_len:]
        return "".join([tar[i:i + 2] for i in range(0, len(tar), 2)][::-1])


class SubscriptionCryptonight(Subscription):
    """Subscription bound to the CryptoNight variant=1 engine."""

    def __init__(self):
        Subscription.__init__(self, pow_engine=CryptonightVariant1Engine())
