import os
os.system('openssl rsautl -decrypt -inkey client.key -in encrypt.enc > top_secret.txt')
