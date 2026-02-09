from Job import Job


class Subscription(object):
    """Encapsulates generic subscription state and job creation."""

    class StateException(Exception):
        pass

    def __init__(self, pow_engine):
        self._id = None
        self._worker_name = None
        self._pow_engine = pow_engine

    @property
    def id(self):
        return self._id

    @property
    def worker_name(self):
        return self._worker_name

    @property
    def pow_engine(self):
        return self._pow_engine

    def set_worker_name(self, worker_name):
        if self._worker_name:
            raise self.StateException("Already authenticated")
        self._worker_name = worker_name

    def set_subscription(self, subscription_id):
        if self._id is not None:
            raise self.StateException("Already subscribed")
        self._id = subscription_id

    def prepare_job(self, job_msg):
        return self._pow_engine.prepare_job(job_msg)

    def estimate_difficulty(self, target):
        return self._pow_engine.estimate_difficulty(target)

    def create_job(self, job_context):
        if self._id is None:
            raise self.StateException("Not subscribed")
        pow_worker = self._pow_engine.create_worker(job_context)

        return Job(
            subscription_id=self.id,
            job_context=job_context,
            pow_worker=pow_worker,
        )

    def __str__(self):
        return "<Subscription id={}, worker_name={}>".format(self.id, self.worker_name)
