"""Notification about a new device

The notification is created a few seconds after the device was detected,
once it had time to get its addresses and DHCP lease:

    New device on network lan: Mac
    MAC address: 3e:f1:18:4d:d9:23 (randomized address, vendor unknown)
    IPv4: 192.168.1.50
    IPv6: 2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac
"""
import ipaddress
import logging
import os
import re
import subprocess
import threading
import time

from .constants import DEVICE_STATES

logger = logging.getLogger(__name__)

DNSMASQ_LEASES = '/tmp/dhcp.leases'
HOSTS_DIR = '/tmp/hosts'  # hosts files read by dnsmasq, e.g. written by odhcpd

# give the device time to get its addresses and DHCP lease
FIRST_LOOKUP_DELAY = 5
LOOKUP_INTERVAL = 5
MAX_LOOKUP_TIME = 30

# number of devices listed in the notification about learned devices
LEARNED_LIMIT = 20

TEXTS = {
    'cs': {
        'title': 'Nové zařízení v síti {network}: {name}',
        'mac': 'MAC adresa: {mac}',
        'randomized': 'náhodná adresa, výrobce neznámý',
        'learned': 'Databáze zařízení byla při startu prázdná, proto byla již přítomná zařízení uložena'
                   ' bez samostatných oznámení ({count}):',
        'more': 'další: {count} (dev-detect list)',
    },
    'en': {
        'title': 'New device on network {network}: {name}',
        'mac': 'MAC address: {mac}',
        'randomized': 'randomized address, vendor unknown',
        'learned': 'The device database was empty at start, so devices already present were stored'
                   ' without separate notifications ({count}):',
        'more': 'more: {count} (dev-detect list)',
    },
}

HOSTNAME_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,62}')


class Device:
    def __init__(self, mac, iface):
        self.mac = mac
        self.iface = iface
        self.network = iface
        self.hostname = None
        self.vendor = None
        self.addresses = set()


def is_randomized(mac):
    """Locally administered address, as used by devices with private (random) MAC address"""
    return bool(int(mac.split(':')[0], 16) & 0x02)


def sort_addresses(addresses):
    """IPv4 first, then IPv6; link-local addresses only when nothing else is known"""
    parsed = {ipaddress.ip_address(address) for address in addresses}
    ipv4 = sorted(a for a in parsed if a.version == 4)
    ipv6 = sorted(a for a in parsed if a.version == 6 and not a.is_link_local)
    link_local = sorted(a for a in parsed if a.version == 6 and a.is_link_local)
    return [str(a) for a in (ipv4 + ipv6 or link_local)]


def valid_hostname(name):
    return bool(name) and bool(HOSTNAME_PATTERN.fullmatch(name))


def dnsmasq_lease(mac, path=None):
    """Return IPv4 address and hostname of the newest DHCPv4 lease of the MAC address

    Lines are '<expiry> <mac> <ip> <hostname or *> <client id>'. DHCPv6 lines
    have IAID in place of the MAC address and do not match.
    """
    newest = None
    try:
        with open(path or DNSMASQ_LEASES) as leases:
            for line in leases:
                fields = line.split()
                if len(fields) < 4 or fields[1].lower() != mac:
                    continue
                try:
                    expiry = int(fields[0]) or float('inf')  # 0 means infinite lease
                    ipaddress.IPv4Address(fields[2])
                except ValueError:
                    continue
                if newest is None or expiry > newest[0]:
                    newest = (expiry, fields[2], fields[3])
    except OSError:
        return None, None

    if newest is None:
        return None, None
    _, ip, hostname = newest
    return ip, hostname if valid_hostname(hostname) else None


def hosts_hostname(addresses, directory=None):
    """Return hostname of one of the addresses from hosts files read by dnsmasq

    odhcpd writes there '<address> <hostname>[.<domain>]' lines for its DHCPv6
    clients (in older versions mixed with lease records starting with '#').
    """
    wanted = {ipaddress.ip_address(a) for a in addresses}
    directory = directory or HOSTS_DIR
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return None
    for name in names:
        try:
            with open(os.path.join(directory, name)) as hosts:
                for line in hosts:
                    fields = line.split()
                    if line.startswith('#') or len(fields) < 2:
                        continue
                    try:
                        address = ipaddress.ip_address(fields[0])
                    except ValueError:
                        continue
                    hostname = fields[1].split('.')[0]
                    if address in wanted and valid_hostname(hostname):
                        return hostname
        except (OSError, UnicodeDecodeError):
            continue
    return None


def neighbour_addresses(mac, iface):
    """Return all addresses of the MAC address in the neighbour table of the interface"""
    from pyroute2 import IPRoute

    with IPRoute() as ipr:
        indexes = ipr.link_lookup(ifname=iface)
        if not indexes:
            return set()
        return {
            message.get_attr('NDA_DST')
            for message in ipr.get_neighbours(ifindex=indexes[0])
            if message.get_attr('NDA_LLADDR') == mac
            and message.get('state', 0) & DEVICE_STATES
            and message.get_attr('NDA_DST')
        }


def network_name(iface):
    """Return name of the network (e.g. lan, guest_turris) using the interface"""
    from euci import EUci

    with EUci() as uci:
        for section, options in uci.get('network', default={}).items():
            if uci.get('network', section, default='') != 'interface':
                continue
            if options.get('device') == iface:
                return section
            if options.get('type') == 'bridge' and 'br-' + section == iface:  # old syntax
                return section
    return iface


def vendor(mac):
    """Return device vendor based on MAC address"""
    if is_randomized(mac):
        return None
    try:
        result = subprocess.run(
            ['ouidb', mac],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.debug('Cannot look up vendor of %s: %s', mac, e)
        return None
    lines = result.stdout.strip().splitlines()
    return lines[0].strip().rstrip(',') or None if lines else None


def gather(mac, ip, iface, sleep=time.sleep):
    """Find out as much as possible about the device"""
    device = Device(mac, iface)
    device.addresses.add(ip)
    for name, lookup in (('network', lambda: network_name(iface)), ('vendor', lambda: vendor(mac))):
        try:
            setattr(device, name, lookup() or getattr(device, name))
        except Exception:
            logger.warning('Cannot find %s of device %s', name, mac, exc_info=True)

    waited = 0
    delay = FIRST_LOOKUP_DELAY
    while True:
        sleep(delay)
        waited += delay
        try:
            device.addresses |= neighbour_addresses(mac, iface)
        except Exception:
            logger.warning('Cannot read addresses of device %s', mac, exc_info=True)
        ipv4, hostname = dnsmasq_lease(mac)
        if ipv4:
            device.addresses.add(ipv4)
        device.hostname = hostname or hosts_hostname(device.addresses)
        if device.hostname or waited >= MAX_LOOKUP_TIME:
            return device
        delay = LOOKUP_INTERVAL


def compose(device, lang):
    texts = TEXTS[lang]
    detail = texts['randomized'] if is_randomized(device.mac) else device.vendor
    lines = [
        texts['title'].format(network=device.network, name=device.hostname or device.mac),
        texts['mac'].format(mac=device.mac) + (' ({})'.format(detail) if detail else ''),
    ]
    for address in sort_addresses(device.addresses):
        lines.append('IPv{}: {}'.format(ipaddress.ip_address(address).version, address))
    return '\n'.join(lines)


def create_notification(message_cs, message_en, subject):
    """Create notification (reForis, e-mail, ntfy) using create_notification of user-notify

    create_notification also accepts a single message whose parts marked with
    _() are translated from the user-notify catalog; until these texts are in
    the catalog, both the Czech and the English message are passed.
    """
    command = ['create_notification', '-s', 'news', message_cs, message_en]
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.error('Cannot create notification about %s: %s', subject, e)
        return
    if result.returncode != 0:
        logger.error('Cannot create notification about %s: %s', subject, result.stderr.strip())


def send(device):
    create_notification(compose(device, 'cs'), compose(device, 'en'), 'device ' + device.mac)


def compose_learned(devices, lang, networks=None):
    """devices are (mac, interfaces, hostname), networks maps interfaces to network names"""
    networks = networks or {}
    texts = TEXTS[lang]
    lines = [texts['learned'].format(count=len(devices))]
    for mac, ifaces, hostname in devices[:LEARNED_LIMIT]:
        details = [hostname] + [networks.get(iface, iface) for iface in ifaces]
        lines.append('{} ({})'.format(mac, ', '.join(filter(None, details))))
    if len(devices) > LEARNED_LIMIT:
        lines.append(texts['more'].format(count=len(devices) - LEARNED_LIMIT))
    return '\n'.join(lines)


def report_learned(devices):
    try:
        networks = {}
        for iface in {iface for _, ifaces, _ in devices for iface in ifaces}:
            try:
                networks[iface] = network_name(iface)
            except Exception:
                logger.debug('Cannot find network of interface %s', iface, exc_info=True)
        create_notification(
            compose_learned(devices, 'cs', networks), compose_learned(devices, 'en', networks),
            '{} learned devices'.format(len(devices)),
        )
    except Exception:
        logger.exception('Cannot report learned devices')


def learned_devices(devices):
    """Report in background devices that were stored without reporting each of them

    devices are (mac, interfaces, hostname)
    """
    threading.Thread(target=report_learned, args=(list(devices),), daemon=True).start()


def report(mac, ip, iface, on_details=None):
    try:
        device = gather(mac, ip, iface)
        if on_details:
            try:
                on_details(device)
            except Exception:
                logger.exception('Cannot process details of device %s', mac)
        send(device)
    except Exception:
        logger.exception('Cannot report new device %s', mac)


def new_device(mac, ip, iface, on_details=None):
    """Report new device in background, once more is known about it

    on_details is called with the Device before the notification is sent.
    """
    threading.Thread(target=report, args=(mac, ip, iface, on_details), daemon=True).start()
