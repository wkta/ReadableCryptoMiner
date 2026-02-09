import struct


class NonceLayout(object):
    """Describes where/how a nonce is encoded inside a job blob."""

    def __init__(self, offset, size=4, endian="big", max_nonce=0x7fffffff):
        self.offset = offset
        self.size = size
        self.endian = endian
        self.max_nonce = max_nonce


class JobContext(object):
    """Algorithm-agnostic job payload passed to workers."""

    def __init__(self, job_id, blob, target, raw_target=None, height=None, seed_hash=None):
        self.job_id = job_id
        self.blob = blob
        self.target = target
        self.raw_target = raw_target
        self.height = height
        self.seed_hash = seed_hash


class PowWorker(object):
    """Per-job worker. Hold mutable state here, not on shared engine instances."""

    def __init__(self, pow_engine, job_context):
        self._pow_engine = pow_engine
        self._job_context = job_context

    @property
    def job_context(self):
        return self._job_context

    @property
    def max_nonce(self):
        return self._pow_engine.max_nonce

    def build_input(self, blob_bin, nonce):
        nonce_bin = self._pow_engine.encode_nonce(nonce)
        off = self._pow_engine.nonce_layout.offset
        return blob_bin[:off] + nonce_bin + blob_bin[off + len(nonce_bin):]

    def format_nonce(self, nonce):
        width = self._pow_engine.nonce_layout.size * 2
        return "{0:0{1}x}".format(nonce, width)

    def compute_pow(self, header):
        return self._pow_engine.compute_pow(header)

    def share_value(self, pow_hash, target_len):
        return self._pow_engine.share_value(pow_hash, target_len)

    def is_share_valid(self, pow_hash, target):
        return self.share_value(pow_hash, len(target)) <= target


class PowEngine(object):
    """Algorithm strategy used by the generic mining loop."""

    def __init__(self, name, nonce_layout):
        self._name = name
        self._nonce_layout = nonce_layout

    @property
    def name(self):
        return self._name

    @property
    def nonce_layout(self):
        return self._nonce_layout

    @property
    def max_nonce(self):
        return self._nonce_layout.max_nonce

    def on_new_job(self, job_msg):
        """Hook for algorithms that need job-derived state (e.g. cache/seed)."""
        return None

    def normalize_target(self, target):
        return target

    def prepare_job(self, job_msg):
        return JobContext(
            job_id=job_msg["job_id"],
            blob=job_msg["blob"],
            target=self.normalize_target(job_msg["target"]),
            raw_target=job_msg.get("target"),
            height=job_msg.get("height"),
            seed_hash=job_msg.get("seed_hash"),
        )

    def create_worker(self, job_context):
        return PowWorker(self, job_context)

    def estimate_difficulty(self, target):
        return None

    def encode_nonce(self, nonce):
        if self._nonce_layout.size != 4:
            raise ValueError("Only 4-byte nonce layouts are currently supported")
        if self._nonce_layout.endian == "big":
            return struct.pack(">I", nonce)
        if self._nonce_layout.endian == "little":
            return struct.pack("<I", nonce)
        raise ValueError("Unsupported nonce endianness: {}".format(self._nonce_layout.endian))

    def build_input(self, blob_bin, nonce):
        nonce_bin = self.encode_nonce(nonce)
        off = self._nonce_layout.offset
        return blob_bin[:off] + nonce_bin + blob_bin[off + len(nonce_bin):]

    def format_nonce(self, nonce):
        width = self._nonce_layout.size * 2
        return "{0:0{1}x}".format(nonce, width)

    def compute_pow(self, header):
        raise NotImplementedError("Subclasses must implement compute_pow")

    def share_value(self, pow_hash, target_len):
        raise NotImplementedError("Subclasses must implement share_value")

    def is_share_valid(self, pow_hash, target):
        return self.share_value(pow_hash, len(target)) <= target
