import os
import shutil
import sqlite3
import time

import pytest

from dev_detect.storage import SCHEMA_VERSION, DatabaseStorage, StorageError

MAC = 'aa:bb:cc:dd:ee:ff'
OTHER_MAC = 'a1:b2:c3:d4:e5:f6'


def test_store(storage):
    """Test simple write"""
    storage.store('aa:bb:cc:dd:ee:ff')
    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff']


def test_store_again(storage):
    """Test that only unique values are stored"""
    storage.store('aa:bb:cc:dd:ee:ff')
    storage.store('aa:bb:cc:dd:ee:ff')

    macs = storage.get_known()

    assert macs == ['aa:bb:cc:dd:ee:ff']


@pytest.mark.parametrize(
    'storage, searched, expected',
    [
        (['aa:bb:cc:dd:ee:ff'], 'aa:bb:cc:dd:ee:ff', True),
        (['aa:bb:cc:dd:ee:ff'], 'a1:b2:c2:d4:e5:f6', False),
        (['aa:bb:cc:dd:ee:ff'], 'aaaa', False),
    ],
    indirect=['storage']
)
def test_search(storage, searched, expected):
    assert storage.search(searched) is expected


@pytest.mark.parametrize(
    'storage', [('aa:bb:cc:dd:ee:ff',)],
    indirect=True
)
def test_remove(storage):
    storage.remove('aa:bb:cc:dd:ee:ff')
    macs = storage.get_known()

    assert macs == []


@pytest.mark.parametrize(
    'storage',
    [
        ('aa:bb:cc:dd:ee:ff', 'a1:b2:c3:d4:e5:f6',)
    ],
    indirect=True
)
def test_clear(storage):
    storage.clear()
    macs = storage.get_known()

    assert macs == []


def test_store_reports_new_devices(storage):
    assert storage.store('aa:bb:cc:dd:ee:ff') is True
    assert storage.store('aa:bb:cc:dd:ee:ff') is False


def test_missing_directory_is_not_created(tmp_path):
    directory = tmp_path / 'srv' / 'dev-detect'
    storage = DatabaseStorage(str(directory / 'dev-detect.db'))

    with pytest.raises(StorageError):
        storage.store(MAC)
    assert not directory.exists()
    storage.close()


def test_replaced_database_is_reopened(tmp_path):
    """Reads follow the file at db_path, not the inode opened first"""
    db_path = str(tmp_path / 'dev-detect.db')
    daemon = DatabaseStorage(db_path)
    daemon.store(MAC)

    replacement = str(tmp_path / 'restored.db')
    shutil.copy(db_path, replacement)
    os.replace(replacement, db_path)
    cli = DatabaseStorage(db_path)
    assert cli.remove(MAC)

    assert not daemon.search(MAC)
    assert daemon.store(OTHER_MAC)
    assert cli.get_known() == [OTHER_MAC]
    daemon.close()
    cli.close()


def test_deleted_database_is_recreated(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC)
    os.unlink(db_path)

    assert not storage.search(MAC)
    assert storage.store(OTHER_MAC)
    assert storage.get_known() == [OTHER_MAC]
    storage.close()


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_read_only_database(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    writer = DatabaseStorage(db_path)
    writer.store(MAC)
    writer.close()
    os.chmod(db_path, 0o444)

    storage = DatabaseStorage(db_path)
    assert storage.search(MAC)
    with pytest.raises(StorageError, match='readonly'):
        storage.store(OTHER_MAC)
    assert not storage.conn.in_transaction  # no lock left behind

    os.chmod(db_path, 0o644)
    assert storage.store(OTHER_MAC)  # connection opened read-only is reopened
    storage.close()


def test_vanished_directory_is_not_recreated(tmp_path):
    """E.g. /srv unmounted while running: do not create a new database on rootfs"""
    directory = tmp_path / 'srv'
    directory.mkdir()
    db_path = directory / 'dev-detect.db'
    storage = DatabaseStorage(str(db_path))
    storage.store(MAC)
    directory.rename(tmp_path / 'detached')

    with pytest.raises(StorageError):
        storage.search(MAC)
    with pytest.raises(StorageError):
        storage.store(OTHER_MAC)
    assert not directory.exists()
    storage.close()


def test_corrupted_database(tmp_path):
    db_path = tmp_path / 'dev-detect.db'
    db_path.write_bytes(b'this is not a database' * 100)
    storage = DatabaseStorage(str(db_path))

    with pytest.raises(StorageError) as excinfo:
        storage.search(MAC)
    assert str(db_path) in str(excinfo.value)
    storage.close()


def create_v0_database(path, macs):
    """Database as created by dev-detect 0.3.1"""
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE known_devices (mac text UNIQUE)')
    conn.executemany('INSERT INTO known_devices (mac) VALUES (?)', [(mac,) for mac in macs])
    conn.commit()
    conn.close()


def schema_version(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute('PRAGMA user_version').fetchone()[0]
    finally:
        conn.close()


def test_new_database_has_current_schema(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC, 'br-lan')

    assert schema_version(db_path) == SCHEMA_VERSION
    (mac, name, iface, first_seen, last_seen, hostname), = storage.devices()
    assert (mac, iface) == (MAC, 'br-lan')
    assert abs(first_seen - time.time()) < 60
    assert last_seen == first_seen
    storage.close()


def test_old_database_is_upgraded(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC, OTHER_MAC])
    storage = DatabaseStorage(db_path)

    assert storage.search(MAC) and storage.search(OTHER_MAC)
    assert storage.devices() == [(MAC, None, '', None, None, None), (OTHER_MAC, None, '', None, None, None)]
    assert schema_version(db_path) == SCHEMA_VERSION
    assert not storage.store(MAC)
    storage.close()


@pytest.mark.skipif(os.geteuid() == 0, reason='file permissions do not apply to root')
def test_old_read_only_database_is_still_readable(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC])
    os.chmod(db_path, 0o444)
    storage = DatabaseStorage(db_path)

    assert storage.search(MAC)
    assert storage.search(MAC, 'br-lan')  # known everywhere
    assert storage.devices() == [(MAC, None, '', None, None, None)]
    with pytest.raises(StorageError, match='cannot be upgraded'):
        storage.store(OTHER_MAC, 'br-lan')

    os.chmod(db_path, 0o644)
    assert storage.store(OTHER_MAC, 'br-lan')  # upgraded once writable
    assert schema_version(db_path) == SCHEMA_VERSION
    assert [row[0] for row in storage.devices()] == [MAC, OTHER_MAC]
    storage.close()


def test_database_of_newer_version_is_not_downgraded(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC)
    conn = sqlite3.connect(db_path)
    conn.execute('PRAGMA user_version = 99')
    conn.close()

    storage = DatabaseStorage(db_path)
    assert storage.search(MAC)
    assert schema_version(db_path) == 99
    storage.close()


def test_upgrade_by_two_processes(tmp_path):
    """The daemon and the CLI may open an old database at the same time"""
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC])
    late = sqlite3.connect(db_path)  # decided to upgrade before the other one committed
    first = DatabaseStorage(db_path)
    first.store(OTHER_MAC, 'br-lan')

    late.execute('BEGIN IMMEDIATE')
    DatabaseStorage._upgrade(late)
    late.commit()
    late.close()

    assert [row[:3] for row in first.devices()] == [(MAC, None, ''), (OTHER_MAC, None, 'br-lan')]
    first.close()


def test_database_restored_from_dump_keeps_its_data(tmp_path):
    """An SQL dump does not contain the schema version"""
    original = DatabaseStorage(str(tmp_path / 'original.db'))
    original.store(MAC, 'br-lan')
    original.store(MAC, 'br-guest-turris')
    original.set_hostname(MAC, 'Mac')
    original.add(OTHER_MAC, 'printer')
    rows = original.devices()
    restored_path = str(tmp_path / 'restored.db')
    restored = sqlite3.connect(restored_path)
    restored.executescript('\n'.join(original.conn.iterdump()))
    restored.close()
    original.close()
    assert schema_version(restored_path) == 0

    storage = DatabaseStorage(restored_path)
    assert storage.devices() == rows
    assert schema_version(restored_path) == SCHEMA_VERSION
    storage.close()


def test_failed_upgrade_is_repeated(tmp_path):
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC])
    conn = sqlite3.connect(db_path)
    conn.execute('CREATE TABLE known_devices_v2 (blocking TEXT)')  # makes the upgrade fail
    conn.commit()
    storage = DatabaseStorage(db_path)

    assert storage.search(MAC)  # still readable
    with pytest.raises(StorageError, match='cannot be upgraded.*known_devices_v2'):
        storage.store(OTHER_MAC, 'br-lan')
    conn.execute('DROP TABLE known_devices_v2')
    conn.commit()
    conn.close()

    assert storage.store(OTHER_MAC, 'br-lan')
    assert storage.search(MAC, 'br-lan')
    assert schema_version(db_path) == SCHEMA_VERSION
    storage.close()


def test_hostname(storage):
    storage.store(MAC, 'br-lan')
    storage.set_hostname(MAC, 'Mac')

    assert [row[5] for row in storage.devices()] == ['Mac']


def test_add(storage):
    storage.store(MAC, 'br-lan')

    assert storage.add(OTHER_MAC)
    assert not storage.add(OTHER_MAC)
    assert storage.add(MAC, 'my laptop')  # seen on br-lan only so far
    assert [(row[0], row[1], row[2]) for row in storage.devices()] == [
        (MAC, 'my laptop', 'br-lan'), (OTHER_MAC, None, ''), (MAC, 'my laptop', ''),
    ]


def test_search_on_interface(storage):
    storage.store(MAC, 'br-lan')
    storage.add(OTHER_MAC)

    assert storage.search(MAC, 'br-lan')
    assert not storage.search(MAC, 'br-guest-turris')
    assert storage.search(OTHER_MAC, 'br-guest-turris')  # known on every interface


@pytest.fixture
def short_timeout(monkeypatch):
    """Do not wait 5 s for locks held by another connection"""
    connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, 'connect', lambda path, *args, **kwargs: connect(path, timeout=0.1))


def test_old_database_is_readable_while_another_process_locks_it(tmp_path, short_timeout):
    db_path = str(tmp_path / 'dev-detect.db')
    create_v0_database(db_path, [MAC])
    other = sqlite3.connect(db_path, isolation_level=None)
    other.execute('BEGIN IMMEDIATE')  # e.g. an interactive sqlite3 session
    storage = DatabaseStorage(db_path)

    assert storage.search(MAC)
    assert storage.devices() == [(MAC, None, '', None, None, None)]
    with pytest.raises(StorageError, match='cannot be upgraded'):
        storage.store(OTHER_MAC, 'br-lan')

    other.execute('ROLLBACK')
    other.close()
    assert storage.store(OTHER_MAC, 'br-lan')
    assert schema_version(db_path) == SCHEMA_VERSION
    storage.close()


def test_failed_commit_leaves_no_transaction(tmp_path, short_timeout):
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(MAC)
    reader = sqlite3.connect(db_path, isolation_level=None)
    reader.execute('BEGIN')
    reader.execute('SELECT * FROM known_devices').fetchall()  # holds a shared lock

    with pytest.raises(StorageError, match='locked'):
        storage.store(OTHER_MAC)
    assert not storage.conn.in_transaction

    reader.execute('ROLLBACK')
    reader.close()
    assert not DatabaseStorage(db_path).search(OTHER_MAC)
    storage.store('02:00:00:00:00:01')
    assert not storage.search(OTHER_MAC)  # the failed write is not committed later
    storage.close()


@pytest.mark.parametrize('damage', ['drop table', 'old table with current version'])
def test_damaged_database_is_repaired(tmp_path, damage):
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC, 'br-lan')
    conn = sqlite3.connect(db_path)
    conn.execute('DROP TABLE known_devices')
    if damage == 'old table with current version':
        conn.execute('CREATE TABLE known_devices (mac text UNIQUE)')
        conn.execute("INSERT INTO known_devices (mac) VALUES (?)", (MAC,))
    conn.commit()
    conn.close()

    storage = DatabaseStorage(db_path)
    assert storage.store(OTHER_MAC, 'br-lan')
    assert [row[0] for row in storage.devices()][-1] == OTHER_MAC
    storage.close()


def test_backup_restored_into_open_database(tmp_path):
    """sqlite3 dev-detect.db '.restore old.db' keeps the file, so the inode stays"""
    db_path = str(tmp_path / 'dev-detect.db')
    storage = DatabaseStorage(db_path)
    storage.store(OTHER_MAC, 'br-lan')
    old_path = str(tmp_path / 'old.db')
    create_v0_database(old_path, [MAC])
    old, target = sqlite3.connect(old_path), sqlite3.connect(db_path)
    old.backup(target)
    old.close()
    target.close()

    assert storage.search(MAC, 'br-lan')
    assert storage.store(OTHER_MAC, 'br-lan')
    assert schema_version(db_path) == SCHEMA_VERSION
    storage.close()


def test_database_replaced_while_being_opened(tmp_path, monkeypatch):
    db_path = str(tmp_path / 'dev-detect.db')
    DatabaseStorage(db_path).store(MAC)
    replacement = str(tmp_path / 'replacement.db')
    DatabaseStorage(replacement).store(OTHER_MAC)
    prepare = DatabaseStorage._prepare.__func__

    def prepare_and_replace(cls, conn):
        prepare(cls, conn)
        if os.path.exists(replacement):
            os.replace(replacement, db_path)
    monkeypatch.setattr(DatabaseStorage, '_prepare', classmethod(prepare_and_replace))
    storage = DatabaseStorage(db_path)

    storage.get_known()  # opened the file being replaced
    assert storage.get_known() == [OTHER_MAC]
    storage.close()
