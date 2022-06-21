import os
cur_path = os.getcwd()
cpath = cur_path + '/opt/easy-rsa/'
os.chdir(cpath)

file_name = input("input crt name(q represent quit): ")
if file_name == 'q':
    pass
else:
    
    os.system('./easyrsa import-req client.req %s'%file_name)
    os.system('./easyrsa sign-req client %s'%file_name)
    print('Certificate created at: ./opt/easy-rsa/pki/issued/%s.crt'%file_name)