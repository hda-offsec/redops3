
import time
import threading
from core.intelligence import AttackVectorMapper

def test_async_geolocation():
    target = "8.8.8.8"
    print(f"Testing async geolocation lookup for {target}...")

    result_container = {}
    done_event = threading.Event()

    def my_callback(result):
        print(f"Callback received result: {result}")
        result_container['data'] = result
        done_event.set()

    start_time = time.time()
    t = AttackVectorMapper.get_ip_geolocation(target, callback=my_callback)
    end_time = time.time()

    dispatch_duration = end_time - start_time
    print(f"Dispatch duration: {dispatch_duration:.4f} seconds")

    if dispatch_duration > 0.01:
        print("WARNING: Dispatch took longer than expected (0.01s). Is it blocking?")

    assert t is not None, "Should return a thread object"
    assert t.is_alive(), "Thread should be alive"

    print("Waiting for callback...")
    if not done_event.wait(timeout=5):
        print("ERROR: Callback timed out!")
        exit(1)

    print("Callback executed successfully.")
    assert result_container.get('data') is not None
    print("Test PASSED")

if __name__ == "__main__":
    test_async_geolocation()
