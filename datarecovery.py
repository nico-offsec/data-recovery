import re
import time
import argparse
import sys
import os
import psutil
import csv
import socket

def pretty_output(extensions,found_files):
    for extension in extensions:
        count = 0
        offsets = []
        for files in found_files:
            if files[2] == extension:
                count+=1
                offsets.append(files[0])
        if count > 0:
            print ("[+] Found %s at offset(s): %s" % (extension,str(offsets)))

def to_decimal(hex_input):
    decimal_out = int(str(hex_input), 16)
    return decimal_out

def to_little_endian(hex_input):
    ba = bytearray.fromhex(hex_input)
    ba.reverse()
    s = ''.join(format(x, '02x') for x in ba)
    return (s.upper())

def write_file(output,filestring):
    open(output, 'wb').write(bytes.fromhex(filestring))

def make_regex(footer):
    return r".*" + footer + "0*$"

def reporting(data,output=None,title=None):
    if output is None:
        print ("[!] No output file listed. Defaulting to ./report.csv")
        output = "./report.csv"
    with open(output,'w',newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(title)
        for row in data:
            csvwriter.writerow(row)

def get_sector_size(header):
    header = re.findall('..?',header[0:512].hex())
    return to_decimal(str(to_little_endian("".join(header[11:13]))))

def disk_info(header):
    header = re.findall('..?',header[0:512].hex())
    OEM = bytearray.fromhex("".join(header[3:11])).decode()
    bytes_per_sector = to_decimal(str(to_little_endian("".join(header[11:13]))))
    sec_per_cluster = to_decimal(header[13])
    bytes_per_cluster = sec_per_cluster * bytes_per_sector
    sectors_in_partition = to_decimal(str(to_little_endian("".join(header[40:48]))))
    reserved_clusters = to_decimal(str(to_little_endian("".join(header[14:16]))))
    unused = to_decimal(str(to_little_endian("".join(header[16:21]))))
    media_descriptor = header[21]
    starting_MFT_cluster = str("".join(header[48:56]))
    serial_number = to_little_endian("".join(header[72:80]))
    print ("OEM: \t\t\t\t" + str(OEM))
    print ("Bytes per sector: \t\t" + str(bytes_per_sector))
    print ("Sectors per cluster: \t\t" + str(sec_per_cluster))
    print ("Bytes per cluster: \t\t" + str(bytes_per_cluster))
    print ("Sectors in partition: \t\t" + str(sectors_in_partition))
    print ("Media Descriptor: \t\t" + str(media_descriptor))
    print ("Starting MFT Cluster: \t\t" + str(starting_MFT_cluster))
    print ("Total space on drive: \t\t" + str(bytes_per_sector * sectors_in_partition))
    print ("UUID: \t\t\t\t" + str(serial_number))
    sys.exit()

def too_big(bytesize,maxsize=1_000_000):
    if bytesize >= maxsize:
        print ("[!] File size above threshold or it is corrupt. Skipping.")
        return True
    return False

def check_headers(header,extensions):
    # Headers in the form of a dictionary
    items = [
        ("jpeg","ffd8ff","ffd9"),   # jpeg
        ("png","89504e47","49454e44ae426082"), # png
        ("pdf","255044462d","0a2525454f460a"), # pdf
        ("zip","504b03041400","e86e05") # zip
        ]

    for item in items:
        label,k,v = item
        if (header[0:(len(k))] == k) and label in extensions:
            #print ("Found header: " + k)
            return item
    return (False,False,False)

def get_byte_size(drivetype):
    if drivetype == "NTFS":
        return 512
    if drivetype == "FAT32":
        return 512

def recover_files(contents,found_items,outputpath):
    byte_size = 0
    for found in found_items:
        while True:
            start_sector = found[0] + byte_size
            end_sector = start_sector + 512
            var = contents[start_sector:end_sector].hex()
            if re.findall(make_regex(found[1]), var):
                write_file(outputpath + 'recovered_' + str(start_sector) + '.' + found[2],contents[found[0]:end_sector].hex())
                #print ("wrote to file")
                found.append("Recovered")
                byte_size = 0
                break
            if too_big(byte_size):
                print ("\t[-] Sector %s " % (found[0]))
                byte_size = 0
                found.append("Unrecoverable")
                break
            else:
                byte_size += 512
    return found_items

def discover_files(contents,extensions):
    found_items = []
    byte_size = get_byte_size("NTFS")
    for i in range(0, len(contents), 512):
        if i % 1_000_000_000 == 0:
            print ("[+] Searched " + str(i) + " bytes so far.")
        line = contents[i:i+512].hex()
        label,header,footer = check_headers(line,extensions)
        if label:
            found_items.append([i,footer,label])
    return found_items

def check_source(source):
    disks = []
    for disk in psutil.disk_partitions():
        if "loop" in str(disk[0]):
            continue
        else:
            disks.append(disk[0])
    if source in disks:
        print ("[!] This is a live drive. This is highly not recommended!")
        print ("[!] Press Control+C to exit now and use '--create-image' to create an image of the drive ")
        print ("[!] Press any other button to continue")
        input()
        return True
    else:
        if os.path.exists(source):
            return True
        else:
            return False

def create_image(drivepath=None,imagepath=None):
    if drivepath == None:
        drivepath = list_disks()
    if imagepath == "./":
        print ("[!] Destination path not found. Defaulting to current directory.")
        imagepath = "./image.img"
    else:
        imagepath = imagepath + "image.img"
    with open(drivepath,'rb') as f:
        sector_size = get_sector_size(f.read(512))
        f.seek(0)
        #print("Sector size is " + str(sector_size))
        with open(imagepath, "wb") as i:
            while True:
                if i.write(f.read(sector_size)) == 0:
                    break

def list_disks():
    count = 1
    disks = []
    for disk in psutil.disk_partitions():
        if "loop" in str(disk[0]):
            continue
        else:
            disks.append(disk[0])
            print("Selection: " + str(count)) 
            print("Disk path:\t"+disk[0]+"\nDisk Mountpoint\t"+disk[1])
            print("-"*50)
            count+=1
    selection = input("Select the drive number you want: ")
    return disks[int(selection) - 1]

def decrypt_password(hashinput,hashtype):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1',8080))
    sending = hashinput + "|" + hashtype
    s.sendall(sending.encode())
    if hashtype == "GET":
        output = s.recv(1024)
        print(output.decode())
    else:
        print("[+] Hash submitted. Check back for cracking status")
    return

def main():
    parser = argparse.ArgumentParser(description="Forensics toolkit")
    source = parser.add_mutually_exclusive_group()
    action = parser.add_mutually_exclusive_group()
    source.add_argument("-H", "--hashcrack", dest="hashinput", help="Send a hash to be cracked")
    parser.add_argument("-T", "--type", dest="hashtype", help="Used with --hashcrack. Inputs type of hash: MD5 | SHA1 | SHA256")
    action.add_argument("-r", "--recover", action="store_true",help="Recover all files")
    action.add_argument("-l", "--locate", action="store_true", help="List file counts and offsets")
    action.add_argument("-c", "--create-image", action="store_true", dest="create_image", default=False)
    source.add_argument("-i", "--image", dest="source", action="store", help="Source File Location", default=None)
    parser.add_argument("-x", "--extensions",dest="extensions",action="store",help="Select extension types (separate with commas)")
    parser.add_argument("-o", "--output-file",dest="destination",action="store",help="Destination to write files", default="./")
    parser.add_argument("-a", "--attributes",action="store_true",help="Get drive attributes", default=False)
    parser.add_argument("-z", "--report",dest="report",help="Report output location (csv)", default=None)
    args, leftovers = parser.parse_known_args()


    if (args.hashinput and not args.hashtype) or (args.hashtype and not args.hashinput):
        print("[!] Must include --type with --hashcrack")
        sys.exit()

    if (args.hashinput):
        decrypt_password(args.hashinput,args.hashtype)
        sys.exit()
    

    if not args.recover and not args.locate and not args.attributes and not args.create_image:
        print ("[!] You must select either -r, -l, -c, or -a")
        sys.exit()

    if args.attributes and not args.source:
        print ("[!] You must select an image")
        sys.exit()
    

    if args.destination[-1] != "/":
        args.destination = args.destination + "/"

    if not os.path.isdir(args.destination):
        print ("Output is not an existing directory. Try again")
        sys.exit()


    if args.create_image:
        create_image(args.source,args.destination)
        sys.exit()


    if check_source(args.source):
        contents = open(args.source,'rb').read()

    if args.extensions is None:
        extensions = ["jpeg","png","docx","pdf","zip"]
    else:
        extensions = args.extensions.split(",")
        
    if args.locate or args.recover:
        found_items = discover_files(contents,extensions)
        if not args.recover:
            pretty_output(extensions,found_items)

    if args.recover:
        found_items = recover_files(contents,found_items,args.destination)

    if args.report and args.locate:
        reporting(data=found_items,output=args.report,title=['Beginning sector','Expected Trailer','File Type'])
    
    if args.report and args.recover:
        reporting(data=found_items,output=args.report,title=['Beginning sector','Expected Trailer','File Type','Recovered'])

    if args.attributes and args.source:
        disk_info(contents)


main()
            