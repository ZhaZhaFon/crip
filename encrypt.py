import os

#验证CA证书
crt_name = input("press crt name: ") 
os.system('openssl verify -CAfile ca.crt %s.crt'%crt_name) 

#证书提取公钥 
os.system('openssl x509 -in %s.crt -pubkey -out B_pub.key'%crt_name) 

file_name = input("press file path(q represent quit): ")
if file_name == 'q':
    Break
else:
    
    os.system('openssl rsautl -encrypt -inkey B_pub.key -pubin -in %s -out encrypt.enc'%file_name      
    )