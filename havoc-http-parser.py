"""
Havoc HTTP traffic parser.
Can recover the AES keys, the executed commands, and the uploaded and downloaded files.

Author : @BoBNewz
"""

import pyshark, argparse, os
from Crypto.Cipher import AES
from Crypto.Util import Counter

"""
Havoc header: 

Packet Size : 4 bytes
Magic Value : 4 bytes
Agent ID : 4 bytes
Command ID : 4 bytes
Request ID : 4 bytes
AES Key : 32 bytes
AES IV : 16 bytes
"""

DefaultMagicValue = "deadbeef"
DemonInit = "00000063"
DemonGetJob = "00000001"
directory_path = "__output"

def find_havoc_header(pcap):
    for packet in pcap:
        http_packet = packet['http']

        if hasattr(http_packet, 'file_data'):
            hexdata = http_packet.file_data.binary_value.hex()

            if DefaultMagicValue in hexdata and DemonInit in hexdata:
                packetsize = hexdata[:8]
                magicvalue = hexdata[8:16]
                agentID = hexdata[16:24]
                commandID = hexdata[24:32]
                requestID = hexdata[32:40]
                aeskey = hexdata[40:104]
                aesIV = hexdata[104:136]
                ip_c2 = packet.ip.dst
    try:
        if packetsize and magicvalue and agentID and commandID and requestID and aeskey and aesIV and ip_c2:
            print(f"\nPacket Size : {packetsize}\nMagic Value : {magicvalue}\nAgent ID : {agentID}\nCommand ID : {commandID}\nRequest ID : {requestID}\nAES Key : {aeskey}\nAES IV : {aesIV}\nC2 IP : {ip_c2}\n")
    except:
        print("[-] Canno't find AES keys...")

def decrypt_packets(ciphertext, key, iv, packet_counter):
    counter = Counter.new(128, initial_value=int.from_bytes(bytes.fromhex(iv), byteorder='big'))
    cipher = AES.new(bytes.fromhex(key), AES.MODE_CTR, counter=counter)

    plaintext = cipher.decrypt(bytes.fromhex(ciphertext))

    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

    file_path = os.path.join(directory_path, f"{packet_counter}_decrypted.bin")

    with open(file_path, "wb") as file:
        file.write(plaintext)
        file.close()
        print(f"[+] Plaintext saved into {file_path}")

def get_packets(pcap, key, iv, ip_c2):
    packet_counter = 0
    for packet in pcap:
        http_packet = packet['http']
        if hasattr(http_packet, 'file_data'):
            hexdata = http_packet.file_data.binary_value.hex()
            if (len(hexdata) > 40 and DefaultMagicValue in hexdata and DemonGetJob in hexdata and packet.ip.dst == ip_c2):
                packet_counter+=1
                #print(bytes.fromhex(key), len(bytes.fromhex(iv)))
                decrypt_packets(hexdata[40:], key, iv, packet_counter)
                    
            elif len(hexdata) > 40 and packet.ip.src == ip_c2:
                packet_counter+=1
                decrypt_packets(hexdata[24:], key, iv, packet_counter)

    if not packet_counter:
        print(f"[-] No Havoc traffic with the {ip_c2} IP address as C2.")

def main(pcap_file, aes_key=None, aes_iv=None, c2_ip=None):
    pcap = pyshark.FileCapture(pcap_file, display_filter='http')

    if aes_key:
        get_packets(pcap, aes_key, aes_iv, c2_ip)

    else:
        find_havoc_header(pcap)

if __name__ == "__main__":
    parser = argparse.ArgumentParser("Havoc HTTP parser")

    subparser = parser.add_subparsers(dest="mode", required=True)
    search_parser = subparser.add_parser("search_keys", help="Analyze the PCAP file to find the AES key and IV, then decrypt the traffic using these keys.")
    search_parser.add_argument("--pcap", help="PCAP with Havoc traffic.", type=str, required=True)

    decrypt_parser = subparser.add_parser("decrypt", help="Decrypt the traffic using the provided AES key, IV, and C2 IP.")
    decrypt_parser.add_argument("--pcap", help="PCAP with Havoc traffic.", type=str, required=True)
    decrypt_parser.add_argument("--aeskey", help="AES Key used to encrypt and decrypt the traffic.", type=str, required=True)
    decrypt_parser.add_argument("--aesiv", help="AES IV used to encrypt and decrypt the traffic.", type=str, required=True)
    decrypt_parser.add_argument("--c2", help="IP of the C2 (Command & Control).", type=str, required=True)

    args = parser.parse_args()

    if args.mode == "decrypt":
        main(args.pcap, args.aeskey, args.aesiv, args.c2)
    else:
        main(args.pcap)