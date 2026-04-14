import dashboard, redis, rq, inspect

print("has enqueue_processing_job:", hasattr(dashboard, "enqueue_processing_job"))
print("RQ_AVAILABLE in dashboard:", getattr(dashboard, "RQ_AVAILABLE", None))
print("redis version:", redis.__version__)
print("rq version:", rq.__version__)
