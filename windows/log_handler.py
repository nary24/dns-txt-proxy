import logging
from collections import deque


class RingBufferHandler(logging.Handler):
    def __init__(self, maxlen=2000):
        super().__init__()
        self.maxlen = maxlen
        self.buffer = deque(maxlen=maxlen)
        self.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

    def emit(self, record):
        self.buffer.append(self.format(record))

    def get_all(self):
        return list(self.buffer)
