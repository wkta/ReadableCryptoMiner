import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from rd_cryptominer.Job import Job
from rd_cryptominer.PowEngine import NonceLayout, PowEngine


class DummyEngine(PowEngine):
    def __init__(self, layout):
        PowEngine.__init__(self, name="dummy", nonce_layout=layout)

    def compute_pow(self, header):
        return header.hex()

    def share_value(self, pow_hash, target_len):
        return pow_hash[-target_len:]


class JobEngine(PowEngine):
    def __init__(self):
        layout = NonceLayout(offset=0, size=4, endian="big", max_nonce=4)
        PowEngine.__init__(self, name="job-engine", nonce_layout=layout)

    def compute_pow(self, header):
        nonce = int.from_bytes(header[:4], byteorder="big")
        return "{:08x}".format(nonce)

    def share_value(self, pow_hash, target_len):
        return pow_hash[-target_len:]


class TestNonceLayout(unittest.TestCase):
    def test_nonce_layout_attributes(self):
        layout = NonceLayout(offset=39, size=4, endian="big", max_nonce=123)
        self.assertEqual(layout.offset, 39)
        self.assertEqual(layout.size, 4)
        self.assertEqual(layout.endian, "big")
        self.assertEqual(layout.max_nonce, 123)


class TestPowEngine(unittest.TestCase):
    def test_build_input_nonce_encoding_and_validation(self):
        engine = DummyEngine(NonceLayout(offset=2, size=4, endian="little", max_nonce=10))
        blob = bytes.fromhex("00112233445566778899")

        built = engine.build_input(blob, 0x0A0B0C0D)
        self.assertEqual(built.hex(), "00110d0c0b0a66778899")
        self.assertEqual(engine.format_nonce(0x0A0B0C0D), "0a0b0c0d")
        self.assertTrue(engine.is_share_valid("001122", "22"))
        self.assertFalse(engine.is_share_valid("001123", "22"))


class TestJob(unittest.TestCase):
    def test_job_mine_uses_engine_for_share_submission(self):
        engine = JobEngine()
        ctx = engine.prepare_job(
            {
                "job_id": "job-1",
                "blob": ("00" * 8),
                "target": "00000002",
                "height": 1,
                "seed_hash": "00" * 32,
            }
        )
        job = Job(
            subscription_id="sub-1",
            job_context=ctx,
            pow_worker=engine.create_worker(ctx),
        )

        shares = list(job.mine(nonce_start=0, nonce_stride=1))
        self.assertEqual(len(shares), 3)
        self.assertEqual(shares[0]["id"], "sub-1")
        self.assertEqual(shares[0]["job_id"], "job-1")
        self.assertEqual(shares[0]["nonce"], "00000000")
        self.assertEqual(shares[0]["result"], "00000000")
        self.assertEqual(shares[-1]["nonce"], "00000002")
        self.assertGreaterEqual(job.hashrate, 0.0)


if __name__ == "__main__":
    unittest.main()
