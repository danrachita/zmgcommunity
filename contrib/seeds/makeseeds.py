#!/usr/bin/env python3
# Copyright (c) 2013-2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Generate seeds.txt from Pieter's DNS seeder
#

NSEEDS=512

MAX_SEEDS_PER_ASN=2

MIN_BLOCKS = 615801

# These are hosts that have been observed to be behaving strangely (e.g.
# aggressively connecting to every node).
SUSPICIOUS_HOSTS = {
    ""
}

import re
import sys
import dns.resolver
import collections

PATTERN_IPV4 = re.compile(r"^((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})):(\d+)$")
PATTERN_IPV6 = re.compile(r"^\[([0-9a-z:]+)\]:(\d+)$")
PATTERN_ONION = re.compile(r"^([abcdefghijklmnopqrstuvwxyz234567]{16}\.onion):(\d+)$")
PATTERN_AGENT = re.compile(r"^(/ZMGCore:2.2.(0|1|99)/)$")

def parseline(line):
    sline = line.split()
    if len(sline) < 11:
       return None
    m = PATTERN_IPV4.match(sline[0])
    sortkey = None
    ip = None
    if m is None:
        m = PATTERN_IPV6.match(sline[0])
        if m is None:
            m = PATTERN_ONION.match(sline[0])
            if m is None:
                return None
            else:
                net = 'onion'
                zmgtr = sortkey = m.group(1)
                port = int(m.group(2))
        else:
            net = 'ipv6'
            if m.group(1) in ['::']: # Not interested in localhost
                return None
            zmgtr = m.group(1)
            sortkey = zmgtr # XXX parse IPv6 into number, could use name_to_ipv6 from generate-seeds
            port = int(m.group(2))
    else:
        # Do IPv4 sanity check
        ip = 0
        for i in range(0,4):
            if int(m.group(i+2)) < 0 or int(m.group(i+2)) > 255:
                return None
            ip = ip + (int(m.group(i+2)) << (8*(3-i)))
        if ip == 0:
            return None
        net = 'ipv4'
        sortkey = ip
        zmgtr = m.group(1)
        port = int(m.group(6))
    # Skip bad results.
    if sline[1] == 0:
        return None
    # Extract uptime %.
    uptime30 = float(sline[7][:-1])
    # Extract Unix timestamp of last success.
    lastsuccess = int(sline[2])
    # Extract protocol version.
    version = int(sline[10])
    # Extract user agent.
    if len(sline) > 11:
        agent = sline[11][1:] + sline[12][:-1]
    else:
        agent = sline[11][1:-1]
    # Extract service flags.
    service = int(sline[9], 16)
    # Extract blocks.
    blocks = int(sline[8])
    # Construct result.
    return {
        'net': net,
        'ip': zmgtr,
        'port': port,
        'ipnum': ip,
        'uptime': uptime30,
        'lastsuccess': lastsuccess,
        'version': version,
        'agent': agent,
        'service': service,
        'blocks': blocks,
        'sortkey': sortkey,
    }

def filtermultiport(zmg):
    '''Filter out hosts with more nodes per IP'''
    hist = collections.defaultdict(list)
    for ip in zmg:
        hist[ip['sortkey']].append(ip)
    return [value[0] for (key,value) in list(hist.items()) if len(value)==1]

# Based on Greg Maxwell's seed_filter.py
def filterbyasn(zmg, max_per_asn, max_total):
    # Sift out zmg by type
    zmg_ipv4 = [ip for ip in zmg if ip['net'] == 'ipv4']
    zmg_ipv6 = [ip for ip in zmg if ip['net'] == 'ipv6']
    zmg_onion = [ip for ip in zmg if ip['net'] == 'onion']

    # Filter IPv4 by ASN
    result = []
    asn_count = {}
    for ip in zmg_ipv4:
        if len(result) == max_total:
            break
        try:
            asn = int([x.to_text() for x in dns.resolver.query('.'.join(reversed(ip['ip'].split('.'))) + '.origin.asn.cymru.com', 'TXT').response.answer][0].split('\"')[1].split(' ')[0])
            if asn not in asn_count:
                asn_count[asn] = 0
            if asn_count[asn] == max_per_asn:
                continue
            asn_count[asn] += 1
            result.append(ip)
        except:
            sys.stderr.write('ERR: Could not resolve ASN for "' + ip['ip'] + '"\n')

    # TODO: filter IPv6 by ASN

    # Add back non-IPv4
    result.extend(zmg_ipv6)
    result.extend(zmg_onion)
    return result

def main():
    lines = sys.stdin.readlines()
    zmg = [parseline(line) for line in lines]

    # Skip entries with valid address.
    zmg = [ip for ip in zmg if ip is not None]
    # Skip entries from suspicious hosts.
    zmg = [ip for ip in zmg if ip['ip'] not in SUSPICIOUS_HOSTS]
    # Enforce minimal number of blocks.
    zmg = [ip for ip in zmg if ip['blocks'] >= MIN_BLOCKS]
    # Require service bit 1.
    zmg = [ip for ip in zmg if (ip['service'] & 1) == 1]
    # Require at least 50% 30-day uptime.
    zmg = [ip for ip in zmg if ip['uptime'] > 50]
    # Require a known and recent user agent.
    zmg = [ip for ip in zmg if PATTERN_AGENT.match(re.sub(' ', '-', ip['agent']))]
    # Sort by availability (and use last success as tie breaker)
    zmg.sort(key=lambda x: (x['uptime'], x['lastsuccess'], x['ip']), reverse=True)
    # Filter out hosts with multiple bitcoin ports, these are likely abusive
    zmg = filtermultiport(zmg)
    # Look up ASNs and limit results, both per ASN and globally.
    zmg = filterbyasn(zmg, MAX_SEEDS_PER_ASN, NSEEDS)
    # Sort the results by IP address (for deterministic output).
    zmg.sort(key=lambda x: (x['net'], x['sortkey']))

    for ip in zmg:
        if ip['net'] == 'ipv6':
            print('[%s]:%i' % (ip['ip'], ip['port']))
        else:
            print('%s:%i' % (ip['ip'], ip['port']))

if __name__ == '__main__':
    main()
