# worker.py — Windows-friendly RQ worker with signal shim (development only)
import os
import logging
import signal
import time
import redis
from typing import List

# ---- WINDOWS SIGNAL SHIM (monkeypatch missing APIs) ----
if os.name == "nt" or not hasattr(signal, "SIGALRM"):
    logging.getLogger("c0r3_worker").debug("Applying Windows signal shim (no-op alarm/setitimer).")
    if not hasattr(signal, "SIGALRM"):
        if hasattr(signal, "SIGABRT"):
            signal.SIGALRM = signal.SIGABRT
        elif hasattr(signal, "SIGTERM"):
            signal.SIGALRM = signal.SIGTERM
        else:
            signal.SIGALRM = signal.SIGINT

    if not hasattr(signal, "alarm"):
        def _alarm_noop(seconds: int = 0):
            return 0
        signal.alarm = _alarm_noop  # type: ignore

    if not hasattr(signal, "setitimer"):
        def _setitimer_noop(which, seconds, interval=0.0):
            return (0.0, 0.0)
        signal.setitimer = _setitimer_noop  # type: ignore

    if not hasattr(signal, "getitimer"):
        def _getitimer_noop(which):
            return (0.0, 0.0)
        signal.getitimer = _getitimer_noop  # type: ignore

# -------- RQ imports (after shim) --------
from rq import Queue
from rq.worker import SimpleWorker

# Try to also import Worker for POSIX fallback
try:
    from rq import Worker as ForkingWorker  # type: ignore
except Exception:
    ForkingWorker = None  # type: ignore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("c0r3_worker")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
# Which queues to listen to (comma-separated env var), default: default,alerts
QUEUES = os.environ.get("QUEUES", "default,alerts").split(",")

def start_worker():
    redis_conn = redis.from_url(REDIS_URL)

    # Build Queue objects list
    queue_objs: List[Queue] = []
    for qn in QUEUES:
        qn = qn.strip()
        if not qn:
            continue
        queue_objs.append(Queue(qn, connection=redis_conn))

    if not queue_objs:
        logger.error("No queues configured to listen to. Exiting.")
        return

    # Use SimpleWorker on Windows or if fork not available
    use_simple = (os.name == "nt") or (not hasattr(os, "fork"))

    if use_simple:
        logger.info("Starting SimpleWorker on queues: %s", ", ".join([q.name for q in queue_objs]))
        w = SimpleWorker(queue_objs, connection=redis_conn)
        try:
            w.work(burst=False)
        except KeyboardInterrupt:
            logger.info("Worker stopped by user (KeyboardInterrupt)")
        except Exception as e:
            logger.exception("SimpleWorker exception: %s", e)
    else:
        if ForkingWorker is None:
            logger.warning("ForkingWorker not available; falling back to SimpleWorker")
            w = SimpleWorker(queue_objs, connection=redis_conn)
            try:
                w.work()
            except KeyboardInterrupt:
                pass
        else:
            logger.info("Starting forking Worker on queues: %s", ", ".join([q.name for q in queue_objs]))
            w = ForkingWorker(queue_objs, connection=redis_conn)
            try:
                w.work()
            except KeyboardInterrupt:
                logger.info("Worker stopped by user (KeyboardInterrupt)")
            except Exception as e:
                logger.exception("Forking Worker exception: %s", e)

if __name__ == "__main__":
    logger.info("Worker connecting to Redis at %s, listening queues: %s", REDIS_URL, QUEUES)
    start_worker()
# worker.py — Windows-friendly RQ worker with signal shim (development only)
import os
import logging
import signal
import time
import redis
from typing import List

# ---- WINDOWS SIGNAL SHIM (monkeypatch missing APIs) ----
if os.name == "nt" or not hasattr(signal, "SIGALRM"):
    logging.getLogger("c0r3_worker").debug("Applying Windows signal shim (no-op alarm/setitimer).")
    if not hasattr(signal, "SIGALRM"):
        if hasattr(signal, "SIGABRT"):
            signal.SIGALRM = signal.SIGABRT
        elif hasattr(signal, "SIGTERM"):
            signal.SIGALRM = signal.SIGTERM
        else:
            signal.SIGALRM = signal.SIGINT

    if not hasattr(signal, "alarm"):
        def _alarm_noop(seconds: int = 0):
            return 0
        signal.alarm = _alarm_noop  # type: ignore

    if not hasattr(signal, "setitimer"):
        def _setitimer_noop(which, seconds, interval=0.0):
            return (0.0, 0.0)
        signal.setitimer = _setitimer_noop  # type: ignore

    if not hasattr(signal, "getitimer"):
        def _getitimer_noop(which):
            return (0.0, 0.0)
        signal.getitimer = _getitimer_noop  # type: ignore

# -------- RQ imports (after shim) --------
from rq import Queue
from rq.worker import SimpleWorker

# Try to also import Worker for POSIX fallback
try:
    from rq import Worker as ForkingWorker  # type: ignore
except Exception:
    ForkingWorker = None  # type: ignore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("c0r3_worker")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
# Which queues to listen to (comma-separated env var), default: default,alerts
QUEUES = os.environ.get("QUEUES", "default,alerts").split(",")

def start_worker():
    redis_conn = redis.from_url(REDIS_URL)

    # Build Queue objects list
    queue_objs: List[Queue] = []
    for qn in QUEUES:
        qn = qn.strip()
        if not qn:
            continue
        queue_objs.append(Queue(qn, connection=redis_conn))

    if not queue_objs:
        logger.error("No queues configured to listen to. Exiting.")
        return

    # Use SimpleWorker on Windows or if fork not available
    use_simple = (os.name == "nt") or (not hasattr(os, "fork"))

    if use_simple:
        logger.info("Starting SimpleWorker on queues: %s", ", ".join([q.name for q in queue_objs]))
        w = SimpleWorker(queue_objs, connection=redis_conn)
        try:
            w.work(burst=False)
        except KeyboardInterrupt:
            logger.info("Worker stopped by user (KeyboardInterrupt)")
        except Exception as e:
            logger.exception("SimpleWorker exception: %s", e)
    else:
        if ForkingWorker is None:
            logger.warning("ForkingWorker not available; falling back to SimpleWorker")
            w = SimpleWorker(queue_objs, connection=redis_conn)
            try:
                w.work()
            except KeyboardInterrupt:
                pass
        else:
            logger.info("Starting forking Worker on queues: %s", ", ".join([q.name for q in queue_objs]))
            w = ForkingWorker(queue_objs, connection=redis_conn)
            try:
                w.work()
            except KeyboardInterrupt:
                logger.info("Worker stopped by user (KeyboardInterrupt)")
            except Exception as e:
                logger.exception("Forking Worker exception: %s", e)

if __name__ == "__main__":
    logger.info("Worker connecting to Redis at %s, listening queues: %s", REDIS_URL, QUEUES)
    start_worker()
