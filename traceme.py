#!/usr/bin/python3

import argparse
import json
import pathlib
from typing import Final

import requests
import simplekml
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1


def traceroute(host):
    ip_addr = []
    for i in range(1, 50):
        icmp = IP(dst=host, ttl=i) / ICMP()
        b = sr1(icmp, timeout=3, verbose=False)

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


def get_location(ip_addresses):
    locations = []
    for ip in ip_addresses:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        response_dict = response.json()

        if response_dict.get("status") == "fail":
            print(f"Failed to get location for IP: {ip}")
            continue

        locations.append({
            "ip": ip,
            "city": response_dict['city'],
            "latitude": response_dict['lat'],
            "longitude": response_dict['lon']
        })

    print("Locations: \t", locations)
    return locations


def create_kml(host, locations):
    kml = simplekml.Kml(name="TracerouteMap Map", open=1)
    tour = kml.newgxtour(name="Packet Route")
    playlist = tour.newgxplaylist()

    # Plotting points
    for loc in locations:
        pnt = kml.newpoint(name=loc['city'])
        pnt.coords = [(loc['longitude'], loc['latitude'])]
        pnt.style.labelstyle.color = simplekml.Color.red  # Make the text red
        pnt.style.labelstyle.scale = 3  # Make the text twice as big
        pnt.style.iconstyle.icon.href = 'https://cdn2.iconfinder.com/data/icons/social-media-8/512/pointer.png'
        pnt.style.iconstyle.scale = 2
        flyto = playlist.newgxflyto(gxduration=7)
        flyto.camera.longitude = loc['longitude']
        flyto.camera.latitude = loc['latitude']
        wait = playlist.newgxwait(gxduration=3)

    # Joining points with lines
    for i in range(len(locations) - 1):
        name = f"{locations[i]['city']} to {locations[i + 1]['city']}"
        lin = kml.newlinestring(name=name)
        lin.coords = [(locations[i]['longitude'], locations[i]['latitude']),
                      (locations[i + 1]['longitude'], locations[i + 1]['latitude'])]
        lin.style.linestyle.width = 8
        lin.style.linestyle.color = simplekml.Color.cyan
        lin.tessellate = 1
        lin.altitudemode = simplekml.AltitudeMode.clamptoground

    filename = f"tracemap_of_{host}.kml"
    kml.save(filename)
    return filename


def save_to_json(host, locations, output_file):
    data = {
        "host": host,
        "locations": locations
    }
    with open(output_file, 'w') as jf:
        json.dump(data, jf, indent=2)
    print("DATA:\n", data, "\n\n")
    print(f"Results saved to {output_file}")


if __name__ == '__main__':
    print("\nTraceRoute Started *****")

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Give Hostname or IP Address", required=True)
    parser.add_argument("--output", help="Save result in JSON file", required=False)
    options = parser.parse_args()

    print("Host:", options.host)

    OUTPUT: Final[pathlib.Path] = pathlib.Path(__file__).parent / options.output

    ip_addresses = traceroute(options.host)
    print("[+] TraceRoute Done!!!\n")

    print("Getting IP Address GeoLocation")
    locations = get_location(ip_addresses)
    print("\n[+] Done!!!\n")

    print("Creating KML file!!!")
    file = create_kml(options.host, locations)
    print("[+] Almost Done!!!\n")

    if options.output:
        save_to_json(options.host, locations, OUTPUT)

    print(f"[+] Open {file} file in Google-Earth")
