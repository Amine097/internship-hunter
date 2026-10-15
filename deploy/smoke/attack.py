"""Run INSIDE the discovery container (piped over stdin). Simulates an attacker that has
obtained Redis access: injects a pickled gadget job and a forged function-name job.
Prints the injected job ids; the smoke test then proves neither executed."""
import os
from pathlib import Path

import redis
from rq import Queue
from rq.job import Job
from rq.serializers import JSONSerializer

c = redis.Redis.from_url(os.environ["REDIS_URL"])
gadget = Job.create(Path.write_text, args=(Path("/tmp/PWNED-PICKLE"), "x"), connection=c)
gadget.origin = "discovery"
gadget.save()
Queue("discovery", connection=c).push_job_id(gadget.id)
forged = Queue("discovery", connection=c, serializer=JSONSerializer).enqueue(
    "subprocess.run", ["touch", "/tmp/PWNED-NAME"])
print(gadget.id, forged.id)
