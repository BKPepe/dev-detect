import subprocess
import sys
import types

import pytest

from dev_detect import notify

MAC = '3e:f1:18:4d:d9:23'  # locally administered (randomized)
APPLE_MAC = 'f0:18:98:aa:bb:cc'
IPV6 = '2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac'

LEASES = """\
1731430000 f0:18:98:aa:bb:cc 192.168.1.60 MacBook 01:f0:18:98:aa:bb:cc
1731440000 3e:f1:18:4d:d9:23 192.168.1.50 Mac 01:3e:f1:18:4d:d9:23
1731420000 3e:f1:18:4d:d9:23 192.168.1.49 * 01:3e:f1:18:4d:d9:23
1731450000 02:00:00:00:00:01 192.168.1.70 printer 3e:f1:18:4d:d9:23
1731450000 02:00:00:00:00:02 192.168.1.71 * *
0 02:00:00:00:00:03 192.168.1.72 old *
1731460000 02:00:00:00:00:03 192.168.1.73 new *
duid 00:01:00:01:2c:2f:5a:2d:d8:58:d7:00:6a:6b
1731460000 1234567 2a00:1028:8388:a84e::1234 phone 00:01:00:01:2c:2f:5a:2d:3e:f1:18:4d:d9:23
"""


@pytest.fixture
def leases(tmp_path, monkeypatch):
    path = tmp_path / 'dhcp.leases'
    path.write_text(LEASES)
    monkeypatch.setattr(notify, 'DNSMASQ_LEASES', str(path))
    return path


@pytest.mark.parametrize('mac, expected', [
    (MAC, ('192.168.1.50', 'Mac')),  # newest lease wins
    ('3E:F1:18:4D:D9:23'.lower(), ('192.168.1.50', 'Mac')),
    ('02:00:00:00:00:01', ('192.168.1.70', 'printer')),
    ('02:00:00:00:00:02', ('192.168.1.71', None)),  # client sent no hostname
    ('02:00:00:00:00:03', ('192.168.1.72', 'old')),  # infinite lease
    ('02:00:00:00:00:04', (None, None)),
])
def test_dnsmasq_lease(leases, mac, expected):
    assert notify.dnsmasq_lease(mac) == expected


def test_dnsmasq_lease_without_leases_file(tmp_path):
    assert notify.dnsmasq_lease(MAC, path=str(tmp_path / 'missing')) == (None, None)


def test_hosts_hostname(tmp_path):
    (tmp_path / 'odhcpd').write_text(
        '# br-lan 00010001 1 Mac 1731460000 a 64 2a00:1028:8388:a84e:0:0:0:1234/128\n'
        '2a00:1028:8388:a84e:0:0:0:1234\tMac.lan\tMac\n'
    )
    (tmp_path / 'other').write_text('fd00::1\trouter\n')

    assert notify.hosts_hostname({'2a00:1028:8388:a84e::1234'}, directory=str(tmp_path)) == 'Mac'
    assert notify.hosts_hostname({IPV6, '192.168.1.50'}, directory=str(tmp_path)) is None
    assert notify.hosts_hostname({IPV6}, directory=str(tmp_path / 'missing')) is None


def test_vendor_is_not_looked_up_for_randomized_address(monkeypatch):
    monkeypatch.setattr(subprocess, 'run', lambda *args, **kwargs: pytest.fail('ouidb called'))
    assert notify.vendor(MAC) is None


def test_vendor(monkeypatch):
    def run(command, **kwargs):
        assert command == ['ouidb', APPLE_MAC]
        return subprocess.CompletedProcess(command, 0, stdout='Apple,\n')
    monkeypatch.setattr(subprocess, 'run', run)

    assert notify.vendor(APPLE_MAC) == 'Apple'


def test_vendor_without_ouidb(monkeypatch):
    def run(command, **kwargs):
        raise FileNotFoundError(command[0])
    monkeypatch.setattr(subprocess, 'run', run)

    assert notify.vendor(APPLE_MAC) is None


def device(mac=MAC, hostname='Mac', vendor=None, addresses=('192.168.1.50', IPV6, 'fe80::848:7d4a:60d1:ce7')):
    result = notify.Device(mac, 'br-lan')
    result.network = 'lan'
    result.hostname = hostname
    result.vendor = vendor
    result.addresses = set(addresses)
    return result


def test_compose():
    assert notify.compose(device(), 'en') == (
        'New device on network lan: Mac\n'
        'MAC address: 3e:f1:18:4d:d9:23 (randomized address, vendor unknown)\n'
        'IPv4: 192.168.1.50\n'
        'IPv6: 2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac'
    )
    assert notify.compose(device(), 'cs') == (
        'Nové zařízení v síti lan: Mac\n'
        'MAC adresa: 3e:f1:18:4d:d9:23 (náhodná adresa, výrobce neznámý)\n'
        'IPv4: 192.168.1.50\n'
        'IPv6: 2a00:1028:8388:a84e:a1a4:8dbf:7ab8:e5ac'
    )


def test_compose_with_vendor_and_without_hostname():
    message = notify.compose(device(APPLE_MAC, hostname=None, vendor='Apple', addresses=['fe80::1']), 'en')

    assert message == (
        'New device on network lan: f0:18:98:aa:bb:cc\n'
        'MAC address: f0:18:98:aa:bb:cc (Apple)\n'
        'IPv6: fe80::1'  # link-local address only when nothing else is known
    )


@pytest.mark.parametrize('lang', ['cs', 'en'])
@pytest.mark.parametrize('dev', [device(), device(APPLE_MAC, None, None, ['192.168.1.60'])])
def test_composed_message_has_no_double_spaces(lang, dev):
    assert '  ' not in notify.compose(dev, lang)


class FakeEUci:
    config = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, config, section=None, option=None, default=None, **kwargs):
        assert config == 'network'
        if section is None:
            return {name: options for name, (_, options) in self.config.items()}
        return self.config[section][0]


@pytest.fixture
def uci(monkeypatch):
    monkeypatch.setitem(sys.modules, 'euci', types.SimpleNamespace(EUci=FakeEUci))
    return FakeEUci


def test_network_name(uci):
    uci.config = {
        'br_lan': ('device', {'name': 'br-lan', 'type': 'bridge'}),
        'lan': ('interface', {'device': 'br-lan', 'proto': 'static'}),
        'guest_turris': ('interface', {'device': 'br-guest-turris'}),
        'old': ('interface', {'type': 'bridge', 'ifname': 'eth1'}),
    }

    assert notify.network_name('br-lan') == 'lan'
    assert notify.network_name('br-guest-turris') == 'guest_turris'
    assert notify.network_name('br-old') == 'old'
    assert notify.network_name('eth2') == 'eth2'


def test_gather(leases, monkeypatch):
    sleeps = []
    monkeypatch.setattr(notify, 'neighbour_addresses', lambda mac, iface: {IPV6})
    monkeypatch.setattr(notify, 'network_name', lambda iface: 'lan')
    result = notify.gather(MAC, 'fe80::848:7d4a:60d1:ce7', 'br-lan', sleep=sleeps.append)

    assert sleeps == [notify.FIRST_LOOKUP_DELAY]
    assert result.network == 'lan'
    assert result.hostname == 'Mac'
    assert result.addresses == {'fe80::848:7d4a:60d1:ce7', IPV6, '192.168.1.50'}


def test_gather_waits_for_hostname_at_most_max_lookup_time(tmp_path, monkeypatch, caplog):
    sleeps = []
    monkeypatch.setattr(notify, 'DNSMASQ_LEASES', str(tmp_path / 'missing'))
    monkeypatch.setattr(notify, 'HOSTS_DIR', str(tmp_path / 'missing'))
    monkeypatch.setattr(notify, 'neighbour_addresses', lambda mac, iface: set())

    def broken_uci(iface):
        raise RuntimeError('uci is broken')
    monkeypatch.setattr(notify, 'network_name', broken_uci)
    result = notify.gather(APPLE_MAC, '192.168.1.60', 'br-lan', sleep=sleeps.append)

    assert sum(sleeps) == notify.MAX_LOOKUP_TIME
    assert result.hostname is None
    assert result.network == 'br-lan'
    assert 'Cannot find network' in caplog.text


def test_send(monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout='', stderr='')
    monkeypatch.setattr(subprocess, 'run', run)
    notify.send(device())

    assert commands == [['create_notification', '-s', 'news', notify.compose(device(), 'cs'),
                         notify.compose(device(), 'en')]]


@pytest.mark.parametrize('outcome', ['missing', 'failing'])
def test_send_failure_is_logged(monkeypatch, caplog, outcome):
    def run(command, **kwargs):
        if outcome == 'missing':
            raise FileNotFoundError(command[0])
        return subprocess.CompletedProcess(command, 1, stdout='', stderr='Unknown notification severity')
    monkeypatch.setattr(subprocess, 'run', run)
    notify.send(device())

    assert 'Cannot create notification about device 3e:f1:18:4d:d9:23' in caplog.text


def test_report_never_raises(monkeypatch, caplog):
    def gather(*args):
        raise ValueError('unexpected')
    monkeypatch.setattr(notify, 'gather', gather)
    notify.report(MAC, '192.168.1.50', 'br-lan')

    assert 'Cannot report new device' in caplog.text
