import os
os.system('cd /opt/easy-rsa/')

file_name = input("input crt name(q represent quit): ")
if file_name == 'q':
    Break
else:
    
    os.system('./easyrsa import-req /opt/cert/client.req %s'%file_name)
    os.system('./easyrsa sign-req client %s'%file_name)
    print('Certificate created at: /opt/easy-rsa/pki/issued/%s.crt'%file_name)