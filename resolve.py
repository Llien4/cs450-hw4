"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

import dns.flags
import dns.rcode

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

cache = {}
ns_cache = {}

def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response

def lookup(target_name, qtype, active=None):
    key = (str(target_name).lower(), qtype)

    if key in cache:
        return cache[key]

    query = dns.message.make_query(target_name, qtype)
    query.flags &= ~dns.flags.RD

    if active is None:
        active = set()

    if key in active:
        return dns.message.make_response(query)

    active.add(key)
    try:
        servers = [[list(ROOT_SERVERS), [], None]]
        best_zone = None

        for zone in ns_cache:
            name = dns.name.from_text(zone)
            if target_name.is_subdomain(name):
                if best_zone is None or len(name.labels) > len(best_zone.labels):
                    best_zone = name

        if best_zone is not None:
            servers.append([list(ns_cache[str(best_zone).lower()]), [], None])

        tried = set()

        while servers:
            current = servers[-1]
            addresses = current[0]
            missing = current[1]
            zone = current[2]

            if addresses:
                server = addresses.pop(0)
                if server in tried:
                    continue

                tried.add(server)
                try:
                    response = dns.query.udp(query, server, timeout=3)
                except Exception:
                    continue

                if response.rcode() == dns.rcode.NXDOMAIN:
                    if response.flags & dns.flags.AA:
                        cache[key] = response
                        return response
                    continue

                if response.rcode() != dns.rcode.NOERROR:
                    continue

                if response.answer:
                    found = False
                    cname = None
                    for rrset in response.answer:
                        if rrset.rdtype == qtype:
                            found = True
                        if rrset.rdtype == dns.rdatatype.CNAME:
                            for record in rrset:
                                cname = record.target

                    if cname is not None:
                        if qtype == dns.rdatatype.CNAME or not found:
                            result = lookup(cname, qtype, active)
                            for rrset in result.answer:
                                if rrset not in response.answer:
                                    response.answer.append(rrset)

                    cache[key] = response
                    return response

                ns_names = []
                next_zone = None
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NS:
                        if target_name.is_subdomain(rrset.name):
                            next_zone = rrset.name
                            for record in rrset:
                                ns_names.append(record.target)

                if not ns_names:
                    if response.flags & dns.flags.AA:
                        cache[key] = response
                        return response
                    continue

                next_ips = []
                glued = set()
                for rrset in response.additional:
                    if rrset.rdtype == dns.rdatatype.A:
                        if rrset.name in ns_names:
                            glued.add(rrset.name)

                            for record in rrset:
                                next_ips.append(record.address)

                if next_ips:
                    ns_cache[str(next_zone).lower()] = list(next_ips)

                missing_ns = []
                for ns in ns_names:
                    if ns not in glued:
                        missing_ns.append(ns)

                if next_ips or missing_ns:
                    servers.append([next_ips, missing_ns, next_zone])

            elif missing:
                ns = missing.pop(0)
                result = lookup(ns, dns.rdatatype.A, active)
                for rrset in result.answer:
                    if rrset.rdtype == dns.rdatatype.A:
                        for record in rrset:
                            if record.address not in addresses:
                                addresses.append(record.address)

                if addresses and zone is not None:
                    zone_key = str(zone).lower()
                    if zone_key not in ns_cache:
                        ns_cache[zone_key] = []

                    for ip in addresses:
                        if ip not in ns_cache[zone_key]:
                            ns_cache[zone_key].append(ip)
            else:
                servers.pop()

        return dns.message.make_response(query)
    finally:
        active.remove(key)

def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))

def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        try:
            results = collect_results(a_domain_name)
            if any(results.values()):
                print_results(results)
            else:
                print("No DNS records found for", a_domain_name)
        except Exception:
            print("Could not resolve", a_domain_name)
if __name__ == "__main__":
    main()