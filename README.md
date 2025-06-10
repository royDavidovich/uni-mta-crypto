# MTA Crypto - Multithreaded Brute Force Decryption

## Authors
- Noam Fishbain
- Omer Chomsky
- Roy Davidovich

## Overview
This project is a multithreaded application that simulates a brute-force password cracking scenario. The goal is to demonstrate thread synchronization between a producer (encrypter) and multiple consumers (decrypters), using mutexes and condition variables in C.

The encrypter thread generates a random password, encrypts it with a randomly generated key, and broadcasts the ciphertext to multiple decrypter threads. Each decrypter attempts to crack the password by guessing random keys and checking for printable plaintext. If a valid decryption is found, the result is sent back to the encrypter for validation.

## Features

- Dynamically configurable number of decrypter threads
- Adjustable password length
- Optional timeout for each cracking attempt
- Real-time logging of progress and results
- Thread-safe communication via `pthread` primitives

## Usage

```bash
./mta_crypto -n <num-of-decrypters> -l <password-length> [-t <timeout-seconds>]
```

### Flags

- `-n`, `--num-of-decrypters` : Number of decrypter threads to create (≥ 1)
- `-l`, `--password-length` : Length of the password in bytes (must be a multiple of 8)
- `-t`, `--timeout` : Optional timeout in seconds for each password cracking session

## Requirements

- POSIX-compliant system (e.g., Linux)
- GCC or Clang with pthread support
- `mta-utils-dev` cryptographic library (install using provided `.deb`)

### Installation of the Utility Library

```bash
sudo dpkg --install mta-utils-dev.deb
```

Alternatively, clone and build from source:
[LinuxCourseCodePub/mta_crypt_lib](https://github.com/gavrielk/LinuxCourseCodePub/blob/master/mta_crypt_lib/)

## Notes

- Passwords are generated using `MTA_get_rand_char()` and are guaranteed to be printable.
- Keys are 1/8 the length of the password.
- The system logs all major events including successful decryption, timeouts, and incorrect guesses.
- All the MTA functions (e.g., `MTA_encrypt`, `MTA_decrypt`, `MTA_get_rand_char`) were provided by our mentor, gavrielk.
