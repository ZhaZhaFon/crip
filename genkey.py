import os
#生成私钥
os.system('openssl genrsa -out client.key 1024 nopass')

#生成公钥
os.system('openssl rsa -in client.key -pubout -out client_pub.key ')

#生成req，并发送给CA签署
os.system('openssl req -new -key client.key -out client.req')
os.system('scp ./client.req yxs@219.223.192.188:/opt/cert ')

#验证CA证书 
#os.system('openssl verify -CAfile ca.crt client.crt') 

#证书提取公钥 
#os.system('openssl x509 -in client.crt -pubkey -out B_pub.key') 

