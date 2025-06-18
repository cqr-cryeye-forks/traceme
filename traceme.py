#!/usr/bin/env python3

import argparse
import json

import requests
import simplekml
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def traceroute(host: str) -> list[str]:
    ip_addr = []
    for i in range(1, 50):
        icmp = IP(dst=host, ttl=i) / ICMP()
        b = sr1(icmp, timeout=8, verbose=False)
        if b is None:
            print(f"TTL={i} \t*****Router Drops the packet*****")
        else:
            if i == 1:
                print(f"\nSource_IP: {b.src}\n")
            if b.src in ip_addr:
                print(f"\nDestination_IP: {b.src}\n")
                break
            print(f"TTL={i} \tIntermediate_IP={b.src}")
            ip_addr.append(b.src)
    return ip_addr


def get_location(ip_addresses: list[str]) -> list[dict]:
    locations = []
    for ip in ip_addresses:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        response_dict = response.json()
        if response_dict.get("status") != "fail":
            locations.append({
                "ip": ip,
                "city": response_dict['city'],
                "latitude": response_dict['lat'],
                "longitude": response_dict['lon']
            })
        else:
            print(f"Failed to get location for IP: {ip}")
    print("Locations: \t", locations)
    return locations


def create_kml(host: str, locations: list[dict]) -> str:
    kml = simplekml.Kml(name="TracerouteMap", open=1)
    for loc in locations:
        pnt = kml.newpoint(name=loc['city'])
        pnt.coords = [(loc['longitude'], loc['latitude'])]
    filename = f"tracemap_of_{host}.kml"
    kml.save(filename)
    return filename


def save_to_json(host: str, locations: list[dict], output_file: str) -> None:
    data = {
        "target_host": host,
        "locations": locations
    }
    with open(output_file, 'w') as jf:
        json.dump(data, jf, indent=2)
    print(f"Results saved to {output_file}")


if __name__ == '__main__':
    print("\nTraceRoute Started *****")
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Give Hostname or IP Address", required=True)
    parser.add_argument("--output", help="Save result in JSON file", default="result.json")
    parser.add_argument("--kml-file", help="Save KML file", action="store_true", dest="kml_file")
    options = parser.parse_args()

    print("Host:", options.host)
    ip_addresses = traceroute(options.host)
    print("[+] TraceRoute Done!!!\n")

    print("Getting IP Address GeoLocation")
    locations = get_location(ip_addresses)
    print("\n[+] Done!!!\n")

    if options.kml_file:
        print("Creating KML file!!!")
        file = create_kml(options.host, locations)
        print(f"[+] Open {file} file in Google Earth")

    save_to_json(options.host, locations, options.output)
    print("[+] Almost Done!!!\n")
