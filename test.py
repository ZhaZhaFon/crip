import util
import os

pub_key, pri_key = util.generate_asymetric_key()
with open('pub.key', 'wb') as f:
    f.write(pub_key)
with open('pri.key', 'wb') as f:
    f.write(pri_key)

os.system('openssl req -new -key pri.key -out client.req -config myserver.cnf')