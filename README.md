# Network device detection

Dev-detect is network device detection daemon inspired by now deprecated `pakon-dev-detect`. It is written from scratch using netlink as source of events on network.

Dependencies:
* python3-pyroute2 - pure python netlink library
* python3-logging
* python3-sqlite3
* python3-uci
* ouidb - get device vendors based on MAC address

Package ships reasonable defaults for turris routers, however users can customize daemon behavior or scope of it's operation in `uci` config file (`/etc/config/dev-detect`).

## CLI client 

Package include simple cli interface called `dev-detect` to interact with device database.

You can use one of following commands:
```
search <MAC>               Search device by MAC address
add <MAC> [--name NAME]    Mark device as known, so that it is not reported
remove <MAC>               Delete specified MAC address
list                       List known devices
clear                      Clear/reset database
```

Devices become known when they are reported. `list` shows where and when they were first and last seen and their hostname. A device can be marked as known in advance with `add`, and `remove` makes it reported again next time it appears.

For full options see help:
```
dev-detect --help
```

## Notifications

New devices are reported through the Turris notification system (reForis, e-mail, ntfy). The notification is created a few seconds after the device appears, so that it can include all addresses the device uses and the hostname from its DHCP lease:

```
New device on network lan: Mac
MAC address: 3e:f1:18:4d:d9:23 (randomized address, vendor unknown)
IPv4: 192.168.1.50
IPv6: 2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac
```

The vendor is looked up by `ouidb`. Devices using a private (randomized) MAC address have no vendor and may be reported again when their address changes.

## Networks

A device is reported when it appears on a watched network for the first time, so that e.g. a device getting from the guest network into the private one is reported too. Devices added by `dev-detect add` (or stored by older versions) are known on every network. To report each device only once, wherever it appears, set:

```
config detection 'detection'
    option per_network '0'
```

## Static DHCP leases

Devices with a static DHCP lease (`config host` in `/etc/config/dhcp`) are known to the administrator, so they are stored without being reported, named after the lease. To report them as well, set:

```
config detection 'detection'
    option known_static_leases '0'
```

## Empty database

When the device database is empty when the daemon starts (on the first start, or when the service starts after `dev-detect clear` or after the database was lost), devices that are present are stored without reporting each of them, and a single notification lists them. To report each of them instead, set:

```
config detection 'detection'
    option learn_on_empty '0'
```

## Persistence

Detected devices are stored in sqlite database in order to remember already discovered devices.

By default it is stored on internal storage, which is suitable when you expect small number of devices that appears regularly (e.g. home network, small office). 

If you want to enable device detection in network where you could expect lots of different clients connecting through your router, e.g. public Wi-Fi AP, it is recommended to store database either on external persistent storage (flash drive, external HDD) or ramdisk as precaution to wearing out internal storage.

Just change `db_path` location in `storage` section.

```
config storage 'storage'
    option db_path   '/path/to/persistent/storage/dev-detect.db'
```

## Watch list

By default `dev-detect` only detect devices on internal lan bridges (`br-lan` and the guest network bridge `br-guest-turris`, or `br-guest_turris` on systems migrated from Turris OS 5), however it can be configured to check multiple interfaces.

Interfaces that do not exist yet are watched as soon as they appear, and an interface that is re-created (e.g. on network restart) keeps being watched.

To add another network interface to watch list, append `list ifaces <interface>` line to `watchlist` section.


For example: `eth1`
```
config watchlist 'watchlist'
        [...]
        list ifaces 'eth1'
```
