#!/usr/bin/python3
'''
   ╒══════════════════╕ ╓─ ──── ─ ──══── ─ ────── ─ ────── ─ ──══── ─ ──── ─┐
 ┌─┤▌  RELEASE INFO  ▐├─╜ ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀ └┐
 █ ╘══════════════════╛                                                      █
 █   [ Filename ......................................... crypto_2024.py ]   █
 █   [ Type ......................CyberOps Throne #3 Task - Cryptography ]   █
 █                                                                           █
 █             [ Written by ........................... telsak ]             █
 █             [ Created date ................... Apr 17, 2024 ]             █
 └┐ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ┌┘
  └ ──── ─ ──══── ─ ────── ─ ───── ─ ──══── ─ ──── ─ ────── ─ ──══── ─ ──── ┘
'''

import signal
import sys
import time
import random
import os
import fcntl
import json
from requests import post

async def send_post(message):
    async with httpx.AsyncClient() as client:
        response = await client.post('███ REDACTED ███', data=message)

def block_ip(ip_address):
    with open('blacklist', 'w') as ifile:
        fcntl.flock(ifile.fileno(), fcntl.LOCK_EX)
        try:
            data = ifile.readlines()
        except:
            data = []
        data.append(str(ip_address))
        ifile.writelines(data)

        fcntl.flock(ifile.fileno(), fcntl.LOCK_UN)
    return

def ip_blocked(ip_address):
    with open('blacklist', 'r') as bfile:
        fcntl.flock(bfile.fileno(), fcntl.LOCK_EX)
        try:
            data = bfile.readlines()
        except:
            data = []
        fcntl.flock(bfile.fileno(), fcntl.LOCK_UN)
    return ip_address in data

def ceasar_cipher(encrypted_str, key):
    # positive: shift right, negative: shift left
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    shifted = ""
    for letter in encrypted_str:
        num = ((ord(letter) - 65 + int(key)) % 26) + 65
        shifted += chr(num)
    return shifted

def decrypt_transposition(encrypted_str, key):
    key_len = len(key)
    blocks = [encrypted_str[:key_len], encrypted_str[key_len:]]

    decrypted_str = ""
    for block in blocks:
        for i, v in sorted(list(zip(key, block))):
            decrypted_str += v
    return decrypted_str

def encrypt_transposition(plain, key):
    key_len = len(key)
    blocks = [plain[i:i + key_len] for i in range(0, len(plain), key_len)]

    encrypted_str = ""
    original_i = sorted(range(len(key)), key=lambda x: key[x])

    for block in blocks:
        scrambled = [''] * len(block)
        for i, char in enumerate(block):
            scrambled[original_i[i]] = char
        encrypted_str += ''.join(scrambled)
    return encrypted_str

def filter_words(input_file):
    filtered_words = []

    with open(input_file, 'r') as infile:
        for line in infile:
            words = line.split()
            for word in words:
                if len(word) >= 10 and len(word) % 2 == 0:
                    filtered_words.append(word)
    return filtered_words

def log_webhook(msg='Null'):
    url = '███ REDACTED ███'
    post(url, json={"username": 'cyberops: throne_game3', "content": msg})

def timeout_handler(signum, frame):
    print(f'\n  {76 * "▓"}')
    old_terminal(f"\n  Protocol VALKYR/EXPIRE triggered. Connection terminated.")
    print(f'\n  {76 * "▓"}\n')
    sys.exit(1)

def old_terminal(text, delay=0.05):
    try:
        for letter in text:
            sys.stdout.write(letter)
            sys.stdout.flush()
            time.sleep(delay)
    except BrokenPipeError:
        client = os.getenv('NCAT_REMOTE_ADDR')
        print(f'Client disconnected: {client}')

def seed_trans(word_length):
    chars = [str(i) for i in range(1,word_length+1)]
    while ''.join(chars) == ''.join([str(i) for i in range(1,word_length+1)]):
        random.shuffle(chars)
    return ''.join(chars)

def save_success(ekey, entry):
    try:
        with open('wins.json', 'r+') as wfile:
            fcntl.flock(wfile.fileno(), fcntl.LOCK_EX)

            try:
                data = json.load(wfile)
            except error as e:
                # error getting json data
                data = {}
            if ekey in data:
                data[ekey].append(entry)
            else:
                data[ekey] = [entry]

            wfile.seek(0)
            wfile.truncate()
            json.dump(data, wfile, indent=2)

            fcntl.flock(wfile.fileno(), fcntl.LOCK_UN)
        return True
    except FileNotFoundError:
        with open('wins.json', 'w') as wfile:
            json.dump({ekey: [entry]}, wfile, indent=2)
        return True
    return False

def format_entry(username, left):
    time_used = TIMEOUT - left
    return {
            "timestamp": time.time(),
            "time_used": str(time_used),
            "username": username,
            "socket": f"{os.getenv('NCAT_REMOTE_ADDR')}:{os.getenv('NCAT_REMOTE_PORT')}"
        }

TIMEOUT=120

access = "███ REDACTED ███"
core = "███ REDACTED ███"

if ip_blocked(os.getenv('NCAT_REMOTE_ADDR')):
    print(f'\n  {76 * "▓"}')
    old_terminal(f"\n  IPS: GARMR/AUTH/{os.getenv('NCAT_REMOTE_ADDR')}/ALERT")
    old_terminal(f"\n       ACCESS TO THE MAINFRAME HAS BEEN DENIED.")
    old_terminal(f"\n       INCIDENT RECORDED ODIN:Eye/LOG.\n")
    print(f'\n  {76 * "▓"}\n')
    sys.exit(1)

# shared file lock for the readonly stuff
with open('cnap.txt', 'r') as cfile:
    fcntl.flock(cfile, fcntl.LOCK_SH)
    flines = cfile.readlines()
    fcntl.flock(cfile, fcntl.LOCK_UN)

words = [███ REDACTED ███]

plaintext = words[random.randint(0, len(words)-1)]
ceasar = random.randint(1,20)
transp = seed_trans(len(plaintext)//2)

for line in flines:
    if 'ENCRYPTED_MESSAGE' in line:
        # generate the assignment
        p_to_c = ceasar_cipher(plaintext, ceasar)
        c_to_tp = encrypt_transposition(p_to_c, str(transp))
        line = line.replace('ENCRYPTED_MESSAGE', c_to_tp)
    elif 'CEASAR_KEY' in line:
        line = line.replace('CEASAR_KEY', str(ceasar))
    elif 'TRANSPOSITION_KEY' in line:
        line = line.replace('TRANSPOSITION_KEY', str(transp))
    old_terminal(line, 0.005)

try:
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(TIMEOUT)
    freeze = 0
    port = os.getenv('NCAT_REMOTE_PORT')
    user = f'{port}:TCP'
    print(f'  Alert! VALKYR/EXPIRE detected! {TIMEOUT} seconds until trigger!\n')
    while True:
        win = 'none'
        try:
            response = input(f"  ICE spread:{freeze * '>'}{(63 - freeze - len(user)) * '-'}{user}\n  Enter your solution: ").strip()
            if response.isascii() and response.isalpha():
                if response == plaintext:
                    win = 'assignment'
                elif response == access:
                    win = 'access'
                elif response == core:
                    win = 'core'
                if win in ['assignment', 'access', 'core']:
                    time_left = signal.alarm(0)
                    # no numbers or åäö
                    i = ['assignment', 'access', 'core'].index(win) + 1
                    print(f'\n  You\'ve completed stage {i} - {win.capitalize()}')
                    if i == 1:
                        if TIMEOUT - time_left < 5:
                            print(███ REDACTED ███)
                        else:
                            print(███ REDACTED ███)
                    elif i == 2:
                        print(███ REDACTED ███)
                    elif i == 3:
                        print(███ REDACTED ███)
                    username = input('\n  Enter your HV username: ')
                    entry = format_entry(username.strip(), time_left)
                    log_webhook(f'{win}: {entry}')
                    if save_success(win, entry):
                        print('\n  CLosing connection..\n')
                        sys.exit(0)
					else:
						sys.exit(1)
        except:
            print(os.getenv("NCAT_REMOTE_ADDR"), 'has disconnected')
            sys.exit(0)
        try:
            freeze += 16
            print(f'  Incorrect! ICE countermeasures engaged! Criticality {(freeze // 6)*10}%!\n')
            if 63 - freeze - len(user) <= 0:
                # cancel the timeout alarm
                signal.alarm(0)
                print(f'  {76 * "▓"}')
                old_terminal(f'  LOG: VIGILANT ICE triggered by unauthorized access from external node.\n')
                old_terminal(f'       Incident elevated to YMIR/TRACE\n')
                old_terminal(f'  IPS: Process halted! LATTICE/{c_to_tp}/* has been purged!\n')
                old_terminal(f'       ODIN:Eye/NET')
                for i in range(1, 101):
                    print(f'\r       ODIN:Eye/NET {i}%', end='')
                    sys.stdout.flush()
                    time.sleep(0.03)
                old_terminal(f' - Node location aquired.')
                old_terminal(f'\n       Enact protocol TYR/')
                old_terminal(f'{os.getenv("NCAT_REMOTE_ADDR")}', 0.2)
                old_terminal(f'/BLOCK\n')
                block_ip(os.getenv('NCAT_REMOTE_ADDR'))
                print(f'  {76 * "▓"}\n')
                sys.exit(1)
            sys.stdout.flush()
            time.sleep(freeze // 9)
        except (EOFError, BrokenPipeError):
            print(os.getenv("NCAT_REMOTE_ADDR"), 'has disconnected')
            sys.exit(0)

finally:
    signal.alarm(0)


