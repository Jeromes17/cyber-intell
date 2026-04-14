# inspect_queue.py
import redis, rq, json
r = redis.from_url("redis://localhost:6379/0")
q = rq.Queue('default', connection=r)
print("Queued count:", q.count)
print("Job IDs (last 10):", q.job_ids[-10:])
