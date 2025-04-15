import time

import requests

r = requests.get("https://pastebin.com/JbVD6htC")
print(r.text)
time.sleep(1)
