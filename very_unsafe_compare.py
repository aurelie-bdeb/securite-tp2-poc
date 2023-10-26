import time


def very_unsafe_compare(a: str, b: str, delay: float):
    if len(a) != len(b):
        return False

    for i in range(len(a)):
        time.sleep(delay)
        if a[i] != b[i]:
            return False

    return True
