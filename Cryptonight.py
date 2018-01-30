from Job import Job
import binascii #TODO: move outside ?

# TODO: move into other file if another implementation is done
# Subscription state
class Subscription(object):
	'''Encapsulates the Subscription state from the JSON-RPC2 server'''

	# Subclasses should override this
	def ProofOfWork(header):
		raise Exception('Do not use the Subscription class directly, subclass it')

	class StateException(Exception): pass

	def __init__(self):
		self._id = None
		#self._difficulty = None
		#self._target = None
		self._worker_name = None

		self._mining_thread = None

	@property
	def id(self): return self._id
	@property
	def worker_name(self): return self._worker_name
	#@property
	#def difficulty(self): return self._difficulty
	#@property
	#def target(self): return self._target


	def set_worker_name(self, worker_name):
		if self._worker_name:
			raise self.StateException('Already authenticated as %r (requesting %r)' % (self._username, username))
		self._worker_name = worker_name


	def set_subscription(self, subscription_id):
		if self._id is not None:
			raise self.StateException('Already subscribed')

		self._id = subscription_id


	def create_job(self, job_id, blob, target):
		'''Creates a new Job object populated with all the goodness it needs to mine.'''

		if self._id is None:
			raise self.StateException('Not subscribed')

		return Job(
			subscription_id = self.id,
			job_id = job_id,
			blob = blob,
			target = target,
			proof_of_work = self.ProofOfWork
		)


	def __str__(self):
		return '<Subscription id={}, worker_name={}>'.format(self.id, self.worker_name)

##############
import os
import ctypes

if os.name == 'nt':
	lib = ctypes.cdll.LoadLibrary('cryptonight_lib/project/Release/cryptonight_lib.dll')
else:
	lib = ctypes.cdll.LoadLibrary('cryptonight_lib/libcryptonight_lib.so')

c_pow = lib.cryptonight_hash
c_pow.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_int]


def cryptonight_proof_of_work(data):
	output = ctypes.create_string_buffer(32)

	c_pow(output, data, 76)
	outputhex =  binascii.hexlify(output).decode() #TODO: move outside?

	return outputhex


class SubscriptionCryptonight(Subscription):
	'''Subscription for Cryptonight-based coins, like XMR (Monero).'''

	ProofOfWork = lambda s, h: (cryptonight_proof_of_work(h))

