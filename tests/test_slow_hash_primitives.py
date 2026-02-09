import builtins
import importlib
import sys
import unittest
from pathlib import Path


class TestSlowHashPrimitives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        src_dir = root / "src"
        if str(src_dir) not in sys.path:
            sys.path.insert(0, str(src_dir))

        # slow_hash_lgplv3 currently runs demo code and calls sys.exit() at import.
        # Patch those side effects so tests can import the module safely.
        original_exit = sys.exit
        original_print = builtins.print
        sys.exit = lambda *args, **kwargs: None
        builtins.print = lambda *args, **kwargs: None
        try:
            cls.slow_hash = importlib.import_module(
                "rd_cryptominer.crypto_primitives.slow_hash_lgplv3"
            )
        finally:
            sys.exit = original_exit
            builtins.print = original_print

    def test_round_known_vector(self):
        result = list(self.slow_hash.round(list(range(16))))
        expected = [106, 106, 92, 69, 44, 109, 51, 81, 176, 217, 93, 97, 39, 156, 33, 92]
        self.assertEqual(result, expected)

    def test_kexp_zero_key_shape_and_tail(self):
        expanded = self.slow_hash.kexp([0] * 32)
        self.assertEqual(len(expanded), 160)
        self.assertEqual(expanded[:32], [0] * 32)
        self.assertEqual(
            expanded[-16:],
            [43, 49, 43, 223, 106, 205, 220, 143, 86, 188, 166, 181, 189, 187, 170, 30],
        )

    def test_keccak_zero_block_known_head_tail(self):
        digest = self.slow_hash.keccak([0] * 200)
        self.assertEqual(len(digest), 200)
        self.assertEqual(digest[:16], [231, 221, 225, 64, 121, 143, 37, 241, 138, 71, 192, 51, 249, 204, 213, 132])
        self.assertEqual(digest[-16:], [59, 161, 48, 127, 233, 68, 246, 117, 73, 162, 236, 92, 123, 255, 241, 234])

    def test_blake_zero_block_known_digest(self):
        digest = self.slow_hash.blake([0] * 200)
        digest_hex = "".join(f"{byte:02x}" for byte in digest)
        self.assertEqual(digest_hex, "6879a6ed74b61e9bf13bd3124b2bca08b33b7226f3bcb328888ba3d4613af43a")

    def test_cn_slow_hash_variant1_known_vector(self):
        inp = [
            0x05, 0x05, 0x84, 0xE2, 0xFA, 0xCC, 0x05, 0xFE,
            0x5C, 0x31, 0x96, 0xE9, 0x95, 0xAE, 0x88, 0x31,
            0x0B, 0xA8, 0x6E, 0xAE, 0x4A, 0xB6, 0x25, 0xAB,
            0xD2, 0x6E, 0x19, 0x2F, 0x26, 0xF3, 0x2C, 0x7D,
            0xCB, 0x6D, 0xB1, 0xD1, 0x08, 0xD7, 0x68, 0x5D,
            0x00, 0x08, 0x57, 0xD6, 0x62, 0xEA, 0x60, 0x02,
            0xE5, 0x19, 0xA2, 0x76, 0xB9, 0xD6, 0x9A, 0xB9,
            0xF0, 0xDF, 0x14, 0xC9, 0xF5, 0x86, 0xE1, 0x1A,
            0xE4, 0x57, 0xB1, 0xB5, 0x74, 0x05, 0xAF, 0xBF,
            0x9C, 0xC0, 0xCB, 0x06,
        ]
        digest = self.slow_hash.cn_slow_hash(inp, quiet=1, variant=1)
        digest_hex = "".join(f"{byte:02x}" for byte in digest)
        self.assertEqual(digest_hex, "fc24238f960c14727386295bd0fcecbace8f2aef74ad7108771c7c832b0a9f00")


if __name__ == "__main__":
    unittest.main()
