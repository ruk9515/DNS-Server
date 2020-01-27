from scapy.all import *
import json
import os
from time import time

other_server_ip = '10.1.0.4'


def filter_dns(packet):
    return (DNS in packet) and (packet.opcode == 0) and (packet[DNSQR].qtype == 1) and (packet[IP].src != packet[IP].dst)


def filter_google(packet):
    return (DNS in packet) and (packet[IP].src == other_server_ip)


def insert_record(qname, ttl, rdata):
    try:
        data_file = open('data.json', 'r+')
        json_data = data_file.read()
        data = json.loads(json_data)
        record = {"Name": qname, "TTL": ttl, "IPv4": rdata}
        data.append(record)
        json_data = json.dumps(data)
        data_file.seek(0)
        data_file.write(json_data)
        data_file.truncate()
        data_file.close()
        print(f'Inserted new record succesfuly for {qname}')
    except Exception as e:
        print(f'Couldnt insert new record: ${e}')


def get_record(qname):
    data_file = open('data.json')
    data = json.loads(data_file.read())
    data_file.close()
    for record in data:
        if (record["Name"] == qname):
            return (record["Name"], record["TTL"], record["IPv4"])
    return query_other_server(qname)


def query_other_server(qname):
    request = IP(dst=other_server_ip)/UDP(dport=53)/DNS(qd=DNSQR(qname=qname))
    send(request, verbose=0)
    packet = sniff(lfilter=filter_google,
                   filter='dst port 53', count=1, timeout=3)
    try:
        packet = packet[0]
        rdata = packet[DNSRR].rdata
        if(type(rdata) is bytes):
            rdata = rdata.decode('utf-8')
        ttl = packet[DNSRR].ttl
        insert_record(qname, ttl, rdata)
        return (qname, ttl, rdata)
    except:
        return False


def get_response(packet, record):
    ip = packet[IP].src
    id = packet[DNS].id
    dport = packet[UDP].sport
    if(record):
        rname = record[0]
        ttl = record[1]
        rdata = record[2]
        response = IP(dst=ip)/UDP(dport=dport)/DNS(id=id, qr=1, ra=1, qdcount=1,
                                                   ancount=1, qd=DNSQR(), an=DNSRR(rrname=rname, ttl=ttl, rdata=rdata))
    else:
        response = IP(dst=ip)/UDP(dport=dport)/DNS(id=id, qr=1,
                                                   ra=1, qdcount=1, rcode=3, qd=DNSQR())
    return response


def main():
    while True:
        print('************\nListening for DNS queries')
        packet = sniff(lfilter=filter_dns, filter='dst port 53', count=1)[0]
        startTime = time()
        qname = (packet[DNSQR].qname).decode('utf-8')
        src = packet[IP].src
        print(f'Packet Recieved for {qname} from {src}')
        record = get_record(qname)
        res = get_response(packet, record)
        send(res, verbose=0)
        endTime = time()
        duration = str(endTime - startTime)[:4]
        print(f'Time: {duration}s\n*************')


if(__name__ == '__main__'):
    main()
