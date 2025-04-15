import time

import requests

r = requests.get("https://raw.githubusercontent.com/0xresetti/malwareguard/refs/heads/main/malwareguard.py")
print(r.text)
time.sleep(1)
