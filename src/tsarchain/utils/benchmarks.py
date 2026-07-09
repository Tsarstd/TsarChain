import time
import logging
import functools
from tsarchain.utils import config as CFG

log = logging.getLogger(__name__)

def benchmark(label: str, threshold_ms: float):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not CFG.DEBUG_BENCHMARKS:
                return func(*args, **kwargs)
                
            start = time.perf_counter()
            result = func(*args, **kwargs)
            end = time.perf_counter()
            
            elapsed_ms = round((end - start) * 1000.0, 3)
            if elapsed_ms > threshold_ms:
                log.warning("[%s] Benchmark : %.3f ms", label, elapsed_ms)
                
            return result
        return wrapper
    return decorator