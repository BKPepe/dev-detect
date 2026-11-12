import argparse
import errno
import logging
import os
import time

from . import notify
from .constants import DEVICE_STATES, IPV4, IPV6, NTF_PROXY, REACHABLE, RTMGRP_LINK, RTMGRP_NEIGH
from .storage import DEFAULT_DB_PATH, DatabaseStorage, StorageError

logger = logging.getLogger(__name__)

# br-guest_turris is the guest bridge on systems migrated from Turris OS 5
DEFAULT_INTERFACES = ('br-lan', 'br-guest-turris', 'br-guest_turris')

# minimal time in seconds between neighbour table scans after lost messages
RESYNC_INTERVAL = 30

# Names of one network. Saving the guest network settings in reForis renames the
# guest bridge of systems migrated from Turris OS 5 to br-guest-turris.
SAME_NETWORK = (('br-guest-turris', 'br-guest_turris'),)

# how often to record that a known device is still present, in seconds;
# every write wears out the internal flash a bit
LAST_SEEN_INTERVAL = 6 * 3600

ADDRMAP = {
    IPV4: '4',
    IPV6: '6'
}


def network_names(iface):
    """Return all names of the network on the interface"""
    for names in SAME_NETWORK:
        if iface in names:
            return names
    return (iface,)


def new_device_notify(mac, ip, addr_family, iface, on_details=None):
    logger.info("New device detected on interface '%s'. MAC: %s | IPv%s address: %s",
                iface, mac, ADDRMAP.get(addr_family), ip)
    notify.new_device(mac, ip, iface, on_details)


def get_interfaces(ipr, watched_interfaces):
    """Try to find all watched interfaces among present ones"""
    interfaces = {}
    links = ipr.get_links()

    for l in links:
        ifname = l.get_attr('IFLA_IFNAME')

        if ifname in watched_interfaces:
            interfaces[l['index']] = ifname

    for ifname in watched_interfaces:
        if ifname not in interfaces.values():
            logger.info("Interface '%s' does not exist, it will be watched once it appears", ifname)
    if not interfaces:
        logger.warning('None of the watched interfaces exists: %s', ', '.join(watched_interfaces))

    return interfaces


def update_interfaces(message, interfaces, watched_interfaces):
    """Follow watched interfaces that are created, re-created or removed

    netifd deletes a bridge when its interface goes down and creates it again
    with a new index, e.g. on network restart.
    """
    if message.get('family') != 0:  # skip e.g. AF_BRIDGE messages about bridge ports
        return
    ifname = message.get_attr('IFLA_IFNAME')
    index = message.get('index')
    if ifname not in watched_interfaces or index is None:
        return

    if message.get('event') == 'RTM_NEWLINK':
        if interfaces.get(index) == ifname:
            return
        for stale in [i for i, name in interfaces.items() if name == ifname]:
            del interfaces[stale]
        interfaces[index] = ifname
        logger.info("Watching interface '%s' (index %d)", ifname, index)
    elif interfaces.pop(index, None):
        logger.info("Interface '%s' was removed", ifname)


class DeviceTracker:
    """Decide whether a device is new and remember it

    The database stays the source of truth, so a device removed from it by
    `dev-detect remove` is reported again. A device that cannot be stored is
    kept in memory instead, so that it is reported only once even when the
    database is not writable.

    With per_network, a device is new on each interface it appears on, unless
    it is known on every interface (added by `dev-detect add` or stored by an
    older version).
    """
    def __init__(self, storage, known_static_leases=False, per_network=False):
        self.storage = storage
        self.known_static_leases = known_static_leases
        self.per_network = per_network
        self.unsaved = {}  # (mac, iface) or mac -> (mac, iface)
        self.last_seen_written = {}
        self.learning = False
        self.learned = {}  # mac -> interfaces

    def start_learning(self):
        """Store devices found by the startup scan without reporting each, if the database is empty

        E.g. on the first start, or on a start after the database was cleared
        (`dev-detect clear` and a restart of the service) or lost, when every
        device present would be reported. They are reported in one notification.
        """
        try:
            self.learning = self.storage.is_empty()
        except StorageError as e:
            logger.error('Cannot read device database: %s', e)

    def finish_learning(self):
        if not self.learning:
            return
        self.learning = False
        if not self.learned:
            return
        logger.info('Device database was empty, %d devices present were stored without reporting each',
                    len(self.learned))
        devices = []
        for mac, ifaces in self.learned.items():
            _, hostname = notify.dnsmasq_lease(mac)
            if hostname:
                try:
                    self.storage.set_hostname(mac, hostname)
                except StorageError as e:
                    logger.warning('Cannot store hostname of device %s: %s', mac, e)
            devices.append((mac, ifaces, hostname))
        notify.learned_devices(devices)
        self.learned = {}

    def is_new(self, mac, iface, present=True):
        """Is the device new? present means its presence was just confirmed (REACHABLE)"""
        names = network_names(iface)
        key = (mac, names[0]) if self.per_network else mac
        if key in self.unsaved:
            return False

        try:
            if self.storage.search(mac, names if self.per_network else None):
                if present:
                    self._touch(mac)
                return False
        except StorageError as e:
            self._keep_unsaved(key, mac, iface, e)

        lease_name = self._static_lease(mac)
        if key not in self.unsaved:
            self._store(key, mac, iface, lease_name)

        if lease_name is not None:
            logger.info('Device %s has a static DHCP lease, it is known', mac)
            return False
        if self.learning:
            ifaces = self.learned.setdefault(mac, [])
            if iface not in ifaces:
                ifaces.append(iface)
            return False
        return True

    def _store(self, key, mac, iface, name):
        try:
            self.storage.store(mac, iface)
            if name:
                self.storage.set_name(mac, name)
        except StorageError as e:
            self._keep_unsaved(key, mac, iface, e)
        else:
            self._store_unsaved()

    def _keep_unsaved(self, key, mac, iface, error):
        logger.error('Cannot record device %s, it will not be reported again until restart: %s', mac, error)
        self.unsaved[key] = (mac, iface)

    def _static_lease(self, mac):
        """Return name of static DHCP lease of the device ('' if unnamed), None if there is none"""
        if not self.known_static_leases:
            return None
        try:
            return static_lease(mac)
        except Exception:
            logger.warning('Cannot read static DHCP leases', exc_info=True)
            return None

    def _touch(self, mac):
        now = time.monotonic()
        if now - self.last_seen_written.get(mac, now - LAST_SEEN_INTERVAL) < LAST_SEEN_INTERVAL:
            return
        self.last_seen_written[mac] = now
        try:
            self.storage.touch(mac)
        except StorageError as e:  # not worth more than the next attempt in LAST_SEEN_INTERVAL
            logger.debug('Cannot record that device %s is present: %s', mac, e)

    def remember_details(self, device):
        """Store hostname found out for the notification (runs in its thread)"""
        if not device.hostname:
            return
        storage = DatabaseStorage(self.storage.db_path)  # a connection cannot be shared by threads
        try:
            storage.set_hostname(device.mac, device.hostname)
        except StorageError as e:
            logger.warning('Cannot store hostname of device %s: %s', device.mac, e)
        finally:
            storage.close()

    def _store_unsaved(self):
        """Database works again, store devices that could not be stored before"""
        for key, (mac, iface) in list(self.unsaved.items()):
            try:
                self.storage.store(mac, iface)
            except StorageError:
                return
            del self.unsaved[key]


def static_lease(mac):
    """Return name of the static DHCP lease of the MAC address ('' if unnamed), None if there is none"""
    from euci import EUci

    with EUci() as uci:
        for section, options in uci.get('dhcp', default={}).items():
            if uci.get('dhcp', section, default='') != 'host':
                continue
            macs = options.get('mac', ())
            if isinstance(macs, str):
                macs = macs.split()
            if mac in (other.lower().replace('-', ':') for other in macs):
                return options.get('name', '')
    return None


def is_device(message, interfaces):
    """Is the neighbour entry one of a device on a watched interface?

    Applies to the neighbour table scan and to broadcast messages alike. Bridge
    FDB (AF_BRIDGE), proxy, static and NOARP entries are not devices.
    """
    return (
        message.get('family') in (IPV4, IPV6)
        and message.get('ifindex') in interfaces
        and bool(message.get('state', 0) & DEVICE_STATES)
        and not message.get('flags', 0) & NTF_PROXY
    )


def process_netlink_message(message, interfaces, tracker):
    if not is_device(message, interfaces):
        return

    mac = message.get_attr('NDA_LLADDR')
    ip = message.get_attr('NDA_DST')

    # sometimes IP or MAC address is missing in netlink message
    if not mac or not ip:
        return
    if int(mac.split(':')[0], 16) & 0x01:  # multicast or broadcast address
        return

    iface = interfaces[message['ifindex']]
    if tracker.is_new(mac, iface, present=bool(message.get('state', 0) & REACHABLE)):
        new_device_notify(mac, ip, message['family'], iface, on_details=tracker.remember_details)


def scan_neighbours(scanner, interfaces, tracker):
    """Check devices already present in the neighbour table"""
    for message in scanner.get_neighbours():
        process_netlink_message(message, interfaces, tracker)


def synchronize(scanner, interfaces, watched_interfaces, tracker, attempts=3):
    """Find watched interfaces and check devices already in the neighbour table

    The scanner is a netlink socket that is not subscribed to any broadcast,
    so that the replies do not compete with broadcast messages for buffer
    space (dumps are flow controlled, broadcast messages are not). Return
    False when it failed.
    """
    for attempt in range(1, attempts + 1):
        try:
            current = get_interfaces(scanner, watched_interfaces)
            interfaces.clear()
            interfaces.update(current)
            scan_neighbours(scanner, interfaces, tracker)
            return True
        except Exception as e:  # e.g. pyroute2 NetlinkDumpInterrupted when links change meanwhile
            error = e
            logger.debug('Neighbour scan attempt %d failed', attempt, exc_info=True)
    logger.warning('Neighbour scan failed, it is repeated later: %s', error)
    return False


def detect_devices(ipr, interfaces, watched_interfaces, tracker, scanner, sync_needed=False):
    """Detect new devices from netlink broadcast

    The kernel drops broadcast messages when the receive buffer is full and
    reports it as ENOBUFS. Lost messages are then made up for by scanning the
    neighbour table again, at most once per RESYNC_INTERVAL. A failed scan is
    repeated the same way.
    """
    last_sync = time.monotonic()
    while True:
        try:
            messages = ipr.get()
        except OSError as e:
            if e.errno != errno.ENOBUFS:
                raise
            if not sync_needed:
                logger.warning('Netlink receive buffer overflowed and messages were lost, scanning neighbours again')
            sync_needed = True
            messages = ()

        if sync_needed and time.monotonic() - last_sync >= RESYNC_INTERVAL:
            sync_needed = not synchronize(scanner, interfaces, watched_interfaces, tracker)
            last_sync = time.monotonic()

        for message in messages:
            event = message.get('event')

            if event in ('RTM_NEWLINK', 'RTM_DELLINK'):
                update_interfaces(message, interfaces, watched_interfaces)

            # we are interested only in new devices on selected interfaces
            elif event == 'RTM_NEWNEIGH':
                process_netlink_message(message, interfaces, tracker)


def open_storage(db_path):
    """Open database, creating its directory (e.g. on a newly mounted /srv)"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    except OSError as e:
        logger.error('Cannot create directory for %s: %s', db_path, e)
    return DatabaseStorage(db_path)


def read_config(uci):
    return {
        'db_path': uci.get('dev-detect', 'storage', 'db_path', dtype=str, default=DEFAULT_DB_PATH),
        'interfaces': uci.get('dev-detect', 'watchlist', 'ifaces', dtype=str, default=DEFAULT_INTERFACES, list=True),
        'learn_on_empty': uci.get('dev-detect', 'detection', 'learn_on_empty', dtype=bool, default=True),
        'known_static_leases': uci.get('dev-detect', 'detection', 'known_static_leases', dtype=bool, default=True),
        'per_network': uci.get('dev-detect', 'detection', 'per_network', dtype=bool, default=True),
    }


def setup_logging(loglevel):
    logging_format = "%(levelname)s: %(message)s"
    logging.basicConfig(level=loglevel, format=logging_format)
    logger.setLevel(loglevel)


def main():
    # imported here so that the detection logic can be tested without them
    from euci import EUci
    from pyroute2 import IPRoute

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help="Show debug messages", action="store_true")

    args = parser.parse_args()

    setup_logging(logging.DEBUG if args.debug else logging.INFO)

    with EUci() as uci:
        config = read_config(uci)
    watched_interfaces = config['interfaces']

    tracker = DeviceTracker(open_storage(config['db_path']), config['known_static_leases'], config['per_network'])
    if config['learn_on_empty']:
        tracker.start_learning()

    with IPRoute() as ipr, IPRoute() as scanner:
        ipr.bind(groups=RTMGRP_NEIGH | RTMGRP_LINK)  # subscribe to netlink broadcast

        interfaces = {}
        synced = synchronize(scanner, interfaces, watched_interfaces, tracker)
        tracker.finish_learning()
        detect_devices(ipr, interfaces, watched_interfaces, tracker, scanner, sync_needed=not synced)


if __name__ == "__main__":
    main()
