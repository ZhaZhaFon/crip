prepare-client1:
	rm -rf client1
	mkdir -p client1/storage
	rm /home/zzf/A_Crytography/crypt/opt/easy-rsa/pki/issued/client1.crt
	rm /home/zzf/A_Crytography/crypt/opt/easy-rsa/pki/reqs/client1.req

client-1:
	python client.py

prepare-client2:
	rm -rf client2
	mkdir -p client2/storage
	rm /home/zzf/A_Crytography/crypt/opt/easy-rsa/pki/issued/client2.crt
	rm /home/zzf/A_Crytography/crypt/opt/easy-rsa/pki/reqs/client2.req
client-2:
	python client.py

serve:
	rm -rf server
	rm /home/zzf/A_Crytography/crypt/opt/easy-rsa/pki/issued/server.crt
	rm /home/zzf/A_Crytography/crypt/opt/easy-rsa/pki/reqs/server.req
	python server.py

ca:
	python ca.py