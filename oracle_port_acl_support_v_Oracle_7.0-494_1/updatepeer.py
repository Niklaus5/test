#!/usr/bin/python3

import sys
import ipaddress
import argparse
import subprocess
import os
from datetime import datetime
import ipaddress
import socket
import re
import base64
import binascii
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

userid = ''
domain = ''
allowedips = ''
virtualip = ''
acllist = ''
publicKey = ''
server_pub_key = ''
server_public_ip = ""
dns_list = ""
internal_server_list = []
ssh_private_key_path = ""
presharedkey = ""
persistentkeepalive = ""
primary_ssh_host = ''
primary_ssh_user = ''
client_public_key = ''
client_private_key = ''


class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = key

    def encrypt(self, raw):
        byte_array = raw.encode("UTF-8")
        padded = self.pad(byte_array)
        iv = os.urandom(AES.block_size)
        cipher = AES.new(self.key.encode("UTF-8"), AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(padded)
        return base64.b64encode(iv + encrypted).decode("UTF-8")

    def decrypt(self, enc):
        byte_array = base64.b64decode(enc)
        iv = byte_array[0:16]
        messagebytes = byte_array[16:]
        cipher = AES.new(self.key.encode("UTF-8"), AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(messagebytes)
        decrypted = self.unpad(decrypted_padded)
        return decrypted.decode("UTF-8")

    def pad(self, bytearray):
        BLOCK_SIZE = AES.block_size
        pad_len = BLOCK_SIZE - len(bytearray) % BLOCK_SIZE
        return bytearray + (bytes([pad_len]) * pad_len)

    def unpad(self, bytearray):
        last_byte = bytearray[-1]
        return bytearray[0:-last_byte]


def log(msg):
    timenow = datetime.now()
    time = timenow.strftime("%d/%m/%Y %H:%M:%S")
    logfile = open("logs/turboscriptlog.log", "a")
    logfile.write(time + ":" + msg + "\n")
    logfile.close()


def get_server_user_host(serverentry):
    list = serverentry.split('@')
    return (list[0], list[1])


def get_value_from_keyvaluepair(keyvaluepair):
    templist = keyvaluepair.split("=")
    return templist[1].strip()

# It must be there in turbo interface table 
def fetch_server_public_key():
    stream = subprocess.Popen("wg show " + interfacename + " public-key", shell=True, stdout=subprocess.PIPE)
    result = stream.stdout.read().decode('ascii').strip()
    server_public_key = result
    error = ''
    return (server_public_key, error)


def encrypt_data(data, key):
    # Encrypt data with aes encryption key key and initialize vector iv.
    aes = AESCipher(key)
    return aes.encrypt(data)


def decrypt_data(data, key):
    # Encrypt data with aes encryption key key and initialize vector iv.
    aes = AESCipher(key)
    return aes.decrypt(data)


def create_client_config(username, domain, virtualip, allowedips, serverpubkey, encrypt, client_private_key, client_public_key):

    #os.system("wg set " + interfacename + " peer " + client_public_key + " allowed-ips " + virtualip + " >/dev/null 2>&1")
    os.system("wg set " + interfacename + " peer " + client_public_key + " allowed-ips " + virtualip + " acl " + acllist + " >/dev/null 2>&1")
    log("wg set " + interfacename + " peer " + client_public_key + " allowed-ips " + virtualip + " acl " + acllist)

    os.system("ip -4 route add " + virtualip + " dev " + interfacename + " >/dev/null 2>&1")
    #log("ran ip -4 route add " + virtualip + " dev" + interfacename)

    #log("/************************************User Login***************************************/")
    log("User '" + userid + "' peer is added with '" + domain + "' domain, allowed-ip's '" + allowedips + "', virtual-ip '" + virtualip + "'")

    # GENERATE CLIENT CONFIG FILE.
    allowedipslist = allowedips.split(",")
    targetipslist = []
    for i in allowedipslist:
        address = i.strip()
        if len(address) > 0:
            if "/" in address:
                targetipslist.append(address)
            elif "-" in address:
                splitlist = address.split("-")
                startip = ipaddress.IPv4Address(splitlist[0])
                endip = ipaddress.IPv4Address(splitlist[1])

                res = [ipaddr for ipaddr in ipaddress.summarize_address_range(
                    startip, endip)]
                for j in res:
                    targetipslist.append(str(j))
            else:
                # To support hostnames.
                regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
                result = regex.match(address)
                if not result:
                    address = socket.gethostbyname(address).strip()
                ip = address + '/32'
                targetipslist.append(ip)
        else:
            continue

    final_allowed_ips = ",".join(targetipslist)
    if ('0.0.0.0/1' in final_allowed_ips):
        final_allowed_ips = '0.0.0.0/0'

    client_config_data_list = []
    client_config_data_list.append('[Interface]')
    client_config_data_list.append('PrivateKey = ' + client_private_key)
    client_config_data_list.append('Address = ' + virtualip)
    if len(dns_list) > 0:
        client_config_data_list.append('DNS = ' + dns_list)
    client_config_data_list.append('\n')
    client_config_data_list.append('[Peer]')
    client_config_data_list.append('PublicKey = ' + serverpubkey)
    client_config_data_list.append('AllowedIPs = ' + final_allowed_ips)
    client_config_data_list.append('Endpoint = ' + server_public_ip + ':' + interfaceport)
    if len(persistentkeepalive) > 0:
        client_config_data_list.append(
            'PersistentKeepAlive = ' + persistentkeepalive)
    else:
        client_config_data_list.append('PersistentKeepAlive = 30')

    client_config_file = "\n".join(client_config_data_list)

    #log("client configuration file is => " + client_config_file)

    if (encrypt is False):
        return client_config_file
    else:
        encconf = encrypt_data(client_config_file, rdk)
        return encconf


def remove_client_config(userid, domain, publicKey):

    os.system("wg set " + interfacename + " peer " + publicKey + " remove >/dev/null 2>&1")
    #log("wg set " + interfacename + " peer " + publicKey + " remove")

    os.system("ip route del " + virtualip + ">/dev/null 2>&1")
    #log("run ip route del " + virtualip)

    log("User '" + userid + "' peer is removed with '" + domain + "' domain and virtualIP '" + virtualip + "'")
    #log("/************************************User Logout***************************************/")


parser = argparse.ArgumentParser(description='upate peer to wireguard server')
parser.add_argument('action', metavar='action', type=str,
                    help='Action can be : "add" followed by userid, domain, allowedips, virtualip or "remove" to remove peer.')
parser.add_argument('--userid', metavar='userid', type=str, help='userid')
parser.add_argument('--domain', metavar='domain', type=str, help='domain')
parser.add_argument('--allowedips', metavar='allowedips',
                    type=str, help='comma separated list of subnets.')
parser.add_argument('--virtualip', metavar='virtualip',
                    type=str, help='virtual ip of client')
parser.add_argument('--rdk', help='Encryption key', type=str)
parser.add_argument('--dnslist', help='DNS server list', type=str)
parser.add_argument('--interfacename', help='Wireguard Interface Name', type=str)
parser.add_argument('--interfaceport', help='Wireguard port', type=str)
parser.add_argument('--endpoint', help='Wireguard Client Endpoint', type=str)
parser.add_argument('--keepalive', help='Wireguard Keepalive interval', type=str)
parser.add_argument('--pk', help='Wireguard Private Key', type=str)
parser.add_argument('--acllist', help='Wireguard acl list', type=str)
parser.add_argument('--publicKey', help='Wireguard public key', type=str)
parser.add_argument('--serverPublicKey', help='Wireguard server public key', type=str)

args = parser.parse_args()

userid = args.userid
domain = args.domain
allowedips = args.allowedips
virtualip = args.virtualip
rdk = args.rdk
dns_list = args.dnslist
interfacename = args.interfacename
interfaceport = args.interfaceport
server_public_ip = args.endpoint
persistentkeepalive = args.keepalive
client_private_key = args.pk
acllist = args.acllist
client_public_key = args.publicKey
server_pub_key = args.serverPublicKey 

if "add" in args.action:
    if ((len(sys.argv) - 1) < 14 or (len(sys.argv) - 1) > 15):
        print(
            'Correct usage example: updatepper add --userid="user" --domain="domain" --allowedips="172.17.0.0/16,192.168.0.0/16" --virtualip="10.0.0.2" --rdk="SCLLC48N8LIXMI8V7S" --dnslist=8.8.8.8 --interfacename=wg0 --interfaceport=443 --endpoint=192.168.1.2 --keepalive=30 --pk="xyz" --acllist="0,139.59.8.21/32/6/1-443/1,13.35.191.78/32/17/0/0" --publicKey="sfgsfgsdfgsdfgsdfgsdfgsdfg=" --serverPublicKey="sfgsfgsdfgsdfgsdfgsdfgsdfg="')
        exit(-1)
    else:
        encrypt = False
        if userid == '' or domain == '' or allowedips == '' or virtualip == '' or interfacename == '' or interfaceport == '' or server_public_ip == '' or persistentkeepalive == '':
            exit(-1)
        #log('parameters are incorrect. params are : userid:' + userid + ' domain' + domain + ' allowedips:' + allowedips + ' virtualip:' + virtualip + ' rdk:' + rdk)

        if rdk is None:
            encrypt = False
        else:
            encrypt = True

        if "/" not in virtualip:
            virtualip = virtualip + "/32"

        client_config = create_client_config(userid, domain, virtualip, allowedips, server_pub_key, encrypt, client_private_key, client_public_key)
        print(client_config)
elif "remove" in args.action:
    if (len(sys.argv) - 1) != 6:
        print('Error: Incorrect number of arguments or incorrect arguments.')
        print('Correct usage example: updatepper remove --userid="user" --domain="domain" --virtualip="10.0.0.2" --publicKey="asdfasjdflaskdjflaskjgaslkgalsgasdg="')
        exit(-1)
    else:
        remove_client_config(userid, domain, client_public_key)
