import csv, socket, argparse#, openpyxl
import struct, random

parser = argparse.ArgumentParser(description="Check multiple TCP and UDP ports")
parser.add_argument("-F", "--file", default="addresses.csv", help = "Provide CSV file name with address pairs")
args = parser.parse_args()
filename = args.file
result = []

def buildpacket(host):
    randint = random.randint(0, 65535)
    packet = struct.pack(">H", randint)  # Query Ids (Just 1 for now)
    packet += struct.pack(">H", 0x0100)  # Flags
    packet += struct.pack(">H", 1)  # Questions
    packet += struct.pack(">H", 0)  # Answers
    packet += struct.pack(">H", 0)  # Authorities
    packet += struct.pack(">H", 0)  # Additional
    split_url = host.split(".")
    for part in split_url:
        packet += struct.pack("B", len(part))
        for s in part:
            packet += struct.pack('c',s.encode())
    packet += struct.pack("B", 0)  # End of String
    packet += struct.pack(">H", 1)  # Query Type
    packet += struct.pack(">H", 1)  # Query Class
    return packet

with open(filename, newline='') as csvfile:
    addresses = csv.reader(csvfile, delimiter=',', quotechar='"')
    for row in addresses:
        print(':'.join(row))
    
        if(row[2] != "TCP" and row[2] != "UDP"):
            print("CSV malformed, try again")
            exit(1)
        if(row[2] == "TCP"):
            with(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                try:
                    s.settimeout(3)
                    s.connect((row[0],int(row[1])))
                    print(f"Connection: {row[0]}:{row[1]}/{row[2]} SUCCESS\n")
                    result.append(([row[0],row[1],row[2]], "SUCCESS"))
                except:
                    print(f"Connection: {row[0]}:{row[1]}/{row[2]} FAIL\n")
                    result.append(([row[0],row[1],row[2]], "FAIL"))
        if(row[2] == "UDP"):
            with(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
                try:
                    s.settimeout(3)
                    packet = buildpacket(row[0])
                    s.sendto(bytes(packet),(row[0],int(row[1])))
                    data, addressn = s.recvfrom(1024)
                    print(f"Connection: {row[0]}:{row[1]}/{row[2]} SUCCESS\n")
                    result.append(([row[0],row[1],row[2]], "SUCCESS"))
                except:
                    print(f"Connection: {row[0]}:{row[1]}/{row[2]} FAIL\n")
                    result.append(([row[0],row[1],row[2]], "FAIL"))

outfile = "mignetresults.csv"
with open(outfile, "w", newline='') as csvfile:
    resultscsv = csv.writer(csvfile, quoting = csv.QUOTE_NONNUMERIC)
    for row in result:
        resultscsv.writerow(row)

print("FINISHED")


    