import time
import binascii


class Job(object):
    """Job from pool"""

    def __init__(self, subscription_id, job_context, pow_worker):

        # From job context
        self._subscription_id = subscription_id
        self._job_context = job_context

        # PoW algorithm worker (per-job state holder)
        self._pow_worker = pow_worker

        # Flag to stop this job's mine coroutine
        self._done = False

        # Hash metrics (start time, delta time, total hashes)
        self._dt = 0.0
        self._hash_count = 0

    @property
    def job_id(self):
        return self._job_context.job_id

    @property
    def blob(self):
        return self._job_context.blob

    @property
    def target(self):
        return self._job_context.target

    @property
    def pow(self):
        return self._pow_worker

    @property
    def context(self):
        return self._job_context

    @property
    def hashrate(self):
        return self._hash_count / self._dt if self._dt > 0 else 0.0

    def stop(self):
        """Requests the mine coroutine stop after its current iteration"""
        self._done = True

    def mine(self, nonce_start=0, nonce_stride=13):
        t0 = time.time()

        blob_bin = binascii.unhexlify(self.blob)
        for nonce in range(nonce_start, self._pow_worker.max_nonce, nonce_stride):
            if self._done:
                self._dt = time.time() - t0
                return

            # PoW attempt
            data = self._pow_worker.build_input(blob_bin, nonce)
            pow_hash = self._pow_worker.compute_pow(data)

            if self._pow_worker.is_share_valid(pow_hash, self.target):
                result = {
                    "id": self._subscription_id,
                    "job_id": self.job_id,
                    "nonce": self._pow_worker.format_nonce(nonce),
                    "result": pow_hash,
                }
                self._dt = time.time() - t0
                yield result
            self._hash_count += 1
