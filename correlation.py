from collections import defaultdict, deque
from threading import Lock
import time


class SlidingWindow:
    # Thread-safe in-memory sliding window counter.
    def __init__(self, window_seconds):
        self.window = window_seconds
        self._data = defaultdict(deque)
        self._lock = Lock()

    def add(self, key, value=True):
        with self._lock:
            now = time.time()
            dq = self._data[key]
            dq.append((now, value))
            self._evict(dq, now)

    def count(self, key):
        with self._lock:
            now = time.time()
            dq = self._data.get(key)
            if not dq:
                return 0
            self._evict(dq, now)
            return len(dq)

    def distinct(self, key):
        with self._lock:
            now = time.time()
            dq = self._data.get(key)
            if not dq:
                return 0
            self._evict(dq, now)
            return len({v for _, v in dq})

    def _evict(self, dq, now):
        cutoff = now - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
