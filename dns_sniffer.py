#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
from optparse import OptionParser
from termcolor import colored
from pyfiglet import Figlet
from scapy.all import sniff, ARP, DNSQR, UDP, IP, IPv6, DNS

queries_liste = {}
quiet = False
databaseConn = None
databaseCursor = None

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def process(pkt):
    global quiet
    global databaseConn
    ip46 = IPv6 if IPv6 in pkt else IP
    if pkt.haslayer(DNSQR) and UDP in pkt and pkt[UDP].sport == 53 and ip46 in pkt:
        query = pkt[DNS].qd.qname.decode("utf-8") if pkt[DNS].qd is not None else "?"

        if pkt[ip46].dst not in queries_liste:
            queries_liste[pkt[ip46].dst] = {}

        if pkt[ip46].src not in queries_liste[pkt[ip46].dst]:
            queries_liste[pkt[ip46].dst][pkt[ip46].src] = {}
        
        if query not in queries_liste[pkt[ip46].dst][pkt[ip46].src]:
            queries_liste[pkt[ip46].dst][pkt[ip46].src][query] = {'count': 1, 'src_mac': pkt.src, 'dst_mac': pkt.dst}
        else:
            queries_liste[pkt[ip46].dst][pkt[ip46].src][query]['count'] += 1

        if databaseConn and query is not None and query != "?":
            databaseCursor.execute("INSERT OR IGNORE INTO domains (domain) VALUES (?);", (query,))
            databaseConn.commit()

            databaseCursor.execute("SELECT idDomain FROM domains WHERE domain=?;", (query,))
            domainId = databaseCursor.fetchone()[0]

            databaseCursor.execute("SELECT count, idWhoAsk FROM whoAsk WHERE ipFrom=? AND ipTo=? AND domainId=?;", (pkt[ip46].src, pkt[ip46].dst, domainId))
            whoAsk = databaseCursor.fetchone()

            if whoAsk:
                databaseCursor.execute("UPDATE whoAsk SET count=? WHERE idWhoAsk=?",(whoAsk[0]+1 if whoAsk[0] else 2, whoAsk[1]))
            else:
                databaseCursor.execute("INSERT INTO whoAsk (ipFrom, ipTo, domainId, count) VALUES (?,?,?,1);", (pkt[ip46].src, pkt[ip46].dst, domainId))

            databaseConn.commit()

        if not quiet:
            clear_screen()
            print_banner()
            print_output()

def init_db(databasePath):
    global databaseConn
    global databaseCursor
    databaseConn = sqlite3.connect(databasePath)
    databaseCursor=databaseConn.cursor()

    databaseCursor.execute("""CREATE TABLE if not exists domains (
                            idDomain INTEGER PRIMARY KEY AUTOINCREMENT,
                            domain TEXT DEFAULT NULL,
                            UNIQUE(domain)
                        );""")
    databaseCursor.execute("""CREATE TABLE if not exists whoAsk (
                            idWhoAsk INTEGER PRIMARY KEY AUTOINCREMENT,
                            ipFrom TEXT DEFAULT NULL,
                            ipTo TEXT DEFAULT NULL,
                            domainId INTEGER,
                            count INTEGER,
                            UNIQUE(ipFrom, ipTo, domainId),
                            FOREIGN KEY(domainId) REFERENCES domains(id)
                        );""")

def print_banner():
    fig = Figlet(font='big')
    banner = fig.renderText('Mr.Root DNS Sniffer')
    print(colored(banner, 'green'))  # Change 'green' to any other color you prefer

def print_output():
    for ip_src, queries in queries_liste.items():
        for ip_dst, data in queries.items():
            if 'src_mac' in data and 'dst_mac' in data:
                print(colored("IP Source: {}, MAC Source: {}, IP Destination: {}, MAC Destination: {}".format(
                    ip_src, data['src_mac'], ip_dst, data['dst_mac']), 'yellow'))
                for query, query_data in data.items():
                    if query not in ['src_mac', 'dst_mac', 'count']:
                        print("   Query: {}, Count: {}".format(query, query_data['count']))
            else:
                print(colored("IP Source: {}, IP Destination: {}".format(ip_src, ip_dst), 'yellow'))
                for query, query_data in data.items():
                    if query not in ['count']:
                        print("   Query: {}, Count: {}".format(query, query_data['count']))

if __name__ == "__main__":
    parser = OptionParser(usage="%prog: [options]")
    parser.add_option("-i", "--iface", dest="iface", default='', help="Interface. Ex: Wi-Fi or Ethernet")
    parser.add_option("-t", "--type", dest="iface_type", default='', help="Interface type. Ex: wifi or ethernet")
    parser.add_option("-q", "--quiet", dest="quiet", action="store_true", help="Quiet")
    parser.add_option("-d", "--database", dest="databasePath", default='', help="Path to sqlite database for logging. Ex: db.sqlite")
    parser.add_option("-e", "--export", dest="exportPath", default='', help="Export sqlite database to CSV. Ex: db.csv")
    (options, args) = parser.parse_args()

    iface = options.iface
    iface_type = options.iface_type.lower()  # Convert to lowercase for consistency
    quiet = options.quiet
    databasePath = options.databasePath

    if databasePath != "":
        try:
            import sqlite3
        except ImportError:
            from sys import exit
            exit("You need to set up sqlite3")

        init_db(databasePath)

    if options.exportPath:
        databaseCursor.execute("SELECT domain, ipFrom, ipTo, count FROM domains, whoAsk WHERE idDomain = domainId ORDER BY count DESC;")
        data = databaseCursor.fetchall()
        import csv
        with open(options.exportPath, 'w') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerows([( 'domain', 'ipFrom', 'ipTo', 'count')])
            writer.writerows(data)
    else:
        try:
            if not quiet:
                clear_screen()
                print_banner()
                print_output()
            if iface != "":
                sniff(filter='udp port 53', store=0, prn=process, iface=iface)
            else:
                sniff(filter='udp port 53', store=0, prn=process)
        except KeyboardInterrupt:
            pass

