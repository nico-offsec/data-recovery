import socket
import requests
import os

def submit_hash(h, md):
    output = open(h + '.txt','w')
    output.write('Decryption in progress\n')
    # call hashcat
    command = "hashcat -m 0 \'%s\' /home/nico/school/rockyou.txt -o %s.txt" % (h,h)
    print(command)
    os.system(command)

def check_existing_hash(h):
    try:
        hashfile = open(h + ".txt",'r').read()
        return hashfile
    except Exception as e:
        return None


""" Move try-catch out of serve code """
def doesFileExist(filename):
    try:
        open(filename + '.txt', "r")
        return True
    except IOError:
        return False


def enum_acceptable():
    return {
        32: "md5",
        40: "sha1",
        64: "sha256"
    }

def validate_md(h, md):
    print(md)
    print(len(md))
    print(len(h))
    print(type(md))
    acceptable = enum_acceptable()
    # Check if supported MD
    if md not in acceptable.values():
        raise TypeError("%s not in %s" % (str(md), str(acceptable.values())))

    # Check length
    l = len(h)
    acceptable_lengths = enum_acceptable()
    if acceptable[l] == md:
        return True
    else:
        return False

def socket_serve(host, port):
    acceptable = enum_acceptable()
    acceptable_methods = acceptable.values()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)
            while True:
                # Recieve payload
                data = conn.recv(256).decode('utf-8')
                if data:
                    # Parse payload and extract hash/message_digest
                    h, md = str(data).split("|")
                    md = md.strip()
                    # check if hash is valid
                    if md == "GET":
                        if doesFileExist(h):
                            hashfile = open(h + ".txt",'r').read()
                            conn.send(bytes(hashfile,'utf-8'))
                            continue

                    b = validate_md(h, md)
                    if not b:
                        continue
                    else:
                        # If valid hash
                            submit_hash(h, md)
    except Exception as e:
        print("[!] Caught %s" % (str(e)))
    finally:
        s.close()



def main():
    host = '127.0.0.1'
    port = 8080
    try:
        print ("[+] Spawning the password cracking server on port " + str(port))
        socket_serve(host, port)
    except e:
        print("[!] Caught %s" % (str(e)))

if __name__ == "__main__":
     main()
