import socket,os,time,sys,codecs
from termcolor import colored

if len(sys.argv) < 3:
    print("\nUsage :listen.py PORT OUTPUTPATH")
    print("Example :listen.py 3389 output.txt")
    sys.exit(1)


ip = "0.0.0.0"
port = int(sys.argv[1])
outputpath = str(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind((ip, port))
s.listen(1)
asciiart = ["  ,/         \.",
" ((           ))",
"  \`.       ,'/",
"   )')     (`(",
" ,'`/       \,`.",
"(`-(         )-')",
""" \-'\,-'"`-./`-/""",
"  \-')     (`-/",
"  /`'       `'\ ",
" (  _       _  )",
" | ( \     / ) |",
" |  `.\   /,'  |",
" |    `\ /'    |",
" (             )",
"  \           /",
"   \         /",
"    `.     ,'",
"      `-.-'"]
for art in asciiart:
    print(colored(art,"red"))
    time.sleep(0.1)
    
print(colored("Coded By Kral4 | https://github.com/rootkral4\nFor Educational Purposes Only\n\n","red"))
print(colored("[!]Waiting For Connection...","yellow"))
s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
c, addr = s.accept()

print(colored('[+]Got Connection {}',"green").format(addr))

def recvall():
    trigger = True
    data = b''
    data = c.recv(4096)
    while trigger == True:
        if "EOFD" not in str(data):
            data += c.recv(4096)
        else:
            trigger = False
            data = data[:-4]
            return data
            break
open(outputpath, 'w').close()
while True:
    data = recvall()
    if "ALL DONE" in str(data):
        print(colored("[+]Done","green"))
        sys.exit(0)
    else:
        with codecs.open(outputpath, 'a+', encoding='utf8', errors='ignore') as f:
            f.write(data.decode().replace("EOFD",""))
       
    
