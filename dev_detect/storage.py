import logging
import os
import sqlite3
import time

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = '/srv/dev-detect/dev-detect.db'

# Upgrades of the database created by older versions of dev-detect, applied in
# order: (version, column added by the step, statements). Version 0 is the
# original table with a mac column only. A step runs only when its column is
# missing, so that e.g. a database restored from an SQL dump, which carries no
# version, keeps its data.
MIGRATIONS = [
    # a device is known on the interface it was seen on, '' means anywhere
    (2, 'iface', [
        "CREATE TABLE known_devices_v2 ("
        " mac TEXT NOT NULL, iface TEXT NOT NULL DEFAULT '', first_seen INTEGER,"
        " PRIMARY KEY (mac, iface))",
        "INSERT OR IGNORE INTO known_devices_v2 (mac)"
        " SELECT mac FROM known_devices WHERE mac IS NOT NULL ORDER BY rowid",
        "DROP TABLE known_devices",
        "ALTER TABLE known_devices_v2 RENAME TO known_devices",
    ]),
    # hostname from the DHCP lease
    (3, 'hostname', ["ALTER TABLE known_devices ADD COLUMN hostname TEXT"]),
    # when the device was seen last time (approximately)
    (4, 'last_seen', ["ALTER TABLE known_devices ADD COLUMN last_seen INTEGER"]),
    # name given by the user
    (5, 'name', ["ALTER TABLE known_devices ADD COLUMN name TEXT"]),
]
SCHEMA_VERSION = MIGRATIONS[-1][0]


class StorageError(Exception):
    """The database of known devices cannot be read or written."""


def _describe(exc):
    """Return SQLite error as precise as the Python version allows."""
    name = getattr(exc, 'sqlite_errorname', None)  # Python 3.11+
    return '{}: {}'.format(name, exc) if name else str(exc)


def _schema_changed(exc):
    """Was the table changed behind our back, e.g. by restoring a backup into the file?"""
    message = str(exc)
    return 'no such column' in message or 'has no column named' in message or 'no such table' in message


class DatabaseStorage:
    """Database storage of known devices

    The file at db_path is the source of truth. The connection is reopened
    when that file is no longer the one that was opened (it was deleted,
    replaced or another filesystem was mounted over its directory), and once
    after a write failed because the database was read-only or its table
    changed. The directory of db_path is never created, so that a database is
    not created in an empty mount point (e.g. unmounted /srv) behind the
    user's back.

    A database of an older version that cannot be upgraded now (read-only,
    locked by another process, disk full) can still be read; the upgrade is
    tried again before each write.

    All failures are reported as StorageError.
    """
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self._file_id = None
        self._columns = set()
        self._upgrade_error = None

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def _current_file_id(self):
        try:
            st = os.stat(self.db_path)
        except OSError:
            return None
        return st.st_dev, st.st_ino

    def _error(self, exc):
        return StorageError('{}: {}'.format(self.db_path, _describe(exc)))

    def _open(self):
        self.close()
        file_id = self._current_file_id()  # before connecting, so that a replacement meanwhile is noticed
        try:
            conn = sqlite3.connect(self.db_path)
        except sqlite3.DatabaseError as e:
            raise self._error(e) from e

        self._upgrade_error = None
        try:
            self._prepare(conn)
        except sqlite3.DatabaseError as e:
            if not self._table_columns(conn):
                conn.close()
                raise self._error(e) from e
            self._upgrade_error = _describe(e)
            logger.warning('%s cannot be upgraded now: %s', self.db_path, self._upgrade_error)

        self.conn = conn
        self._file_id = file_id or self._current_file_id()
        self._columns = self._table_columns(conn)

    @staticmethod
    def _table_columns(conn):
        try:
            return {row[1] for row in conn.execute('PRAGMA table_info(known_devices)')}
        except sqlite3.DatabaseError:
            return set()

    @staticmethod
    def _missing_columns(conn):
        columns = {row[1] for row in conn.execute('PRAGMA table_info(known_devices)')}
        return [column for _, column, _ in MIGRATIONS if column not in columns]

    @classmethod
    def _prepare(cls, conn):
        """Create the table or upgrade it to the current schema"""
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version > SCHEMA_VERSION:
            return  # created by a newer version of dev-detect
        if version == SCHEMA_VERSION and not cls._missing_columns(conn):
            return
        isolation_level = conn.isolation_level
        conn.isolation_level = None  # explicit transaction, not mixed with the implicit ones
        try:
            conn.execute('BEGIN IMMEDIATE')  # the daemon and the CLI may open it at the same time
            try:
                cls._upgrade(conn)
                conn.execute('COMMIT')
            except BaseException:
                if conn.in_transaction:
                    conn.execute('ROLLBACK')
                raise
        finally:
            conn.isolation_level = isolation_level

    @classmethod
    def _upgrade(cls, conn):
        conn.execute('CREATE TABLE IF NOT EXISTS known_devices (mac TEXT UNIQUE)')
        for _, column, statements in MIGRATIONS:
            if column in cls._missing_columns(conn):
                for statement in statements:
                    conn.execute(statement)
        conn.execute('PRAGMA user_version = {:d}'.format(SCHEMA_VERSION))

    def _connection(self):
        """Return connection to the database file that is currently at db_path."""
        if self.conn is not None and self._current_file_id() == self._file_id:
            return self.conn
        if self.conn is not None:
            logger.warning('%s was replaced or removed, reopening it', self.db_path)
        self._open()
        return self.conn

    def _read(self, query, params=()):
        """Return rows of the query; query can be a function returning (query, params)"""
        for attempt in (1, 2):
            conn = self._connection()
            sql, args = query() if callable(query) else (query, params)
            try:
                return conn.execute(sql, args).fetchall()
            except sqlite3.DatabaseError as e:
                if attempt == 1 and _schema_changed(e):
                    logger.warning('%s: %s, reopening it', self.db_path, _describe(e))
                    self._open()
                    continue
                raise self._error(e) from e

    def _write(self, query, params=()):
        """Execute modifying query and return number of affected rows."""
        for attempt in (1, 2):
            conn = self._connection()
            if self._upgrade_error:
                self._open()  # the upgrade may be possible now
                conn = self.conn
                if self._upgrade_error:
                    raise StorageError('{}: cannot be upgraded: {}'.format(self.db_path, self._upgrade_error))
            try:
                with conn:  # commit, or roll back so that no lock is left behind
                    return conn.execute(query, params).rowcount
            except sqlite3.DatabaseError as e:
                self._rollback(conn)
                if attempt == 1 and ('READONLY' in _describe(e).upper() or _schema_changed(e)):
                    # It might have been opened while it was not writable.
                    logger.warning('%s: %s, reopening it', self.db_path, _describe(e))
                    self._open()
                    continue
                raise self._error(e) from e

    @staticmethod
    def _rollback(conn):
        """Python < 3.9.7 leaves the transaction open when COMMIT fails"""
        try:
            if conn.in_transaction:
                conn.rollback()
        except sqlite3.Error:
            pass

    def store(self, mac, iface=''):
        """Store MAC address seen on the interface. Return False if it was already stored."""
        now = int(time.time())
        return self._write(
            'INSERT OR IGNORE INTO known_devices (mac, iface, first_seen, last_seen) VALUES (?, ?, ?, ?)',
            (mac, iface, now, now),
        ) == 1

    def get_known(self):
        return [row[0] for row in self._read('SELECT mac FROM known_devices GROUP BY mac ORDER BY MIN(rowid)')]

    def add(self, mac, name=None):
        """Mark device as known on every interface. Return False if it already was."""
        added = self._write("INSERT OR IGNORE INTO known_devices (mac, iface) VALUES (?, '')", (mac,)) == 1
        if name is not None:
            self.set_name(mac, name)
        return added

    def set_name(self, mac, name):
        self._write('UPDATE known_devices SET name=? WHERE mac=?', (name, mac))

    def touch(self, mac):
        """Record that the device is present now"""
        self._write('UPDATE known_devices SET last_seen=? WHERE mac=?', (int(time.time()), mac))

    def set_hostname(self, mac, hostname):
        self._write('UPDATE known_devices SET hostname=? WHERE mac=?', (hostname, mac))

    def devices(self):
        """Return (mac, name, iface, first_seen, last_seen, hostname) of all known devices"""
        def query():  # only the columns the file has
            columns = (
                column if column in self._columns else "''" if column == 'iface' else 'NULL'
                for column in ('mac', 'name', 'iface', 'first_seen', 'last_seen', 'hostname')
            )
            return 'SELECT {} FROM known_devices ORDER BY rowid'.format(', '.join(columns)), ()
        return self._read(query)

    def is_empty(self):
        return not self._read('SELECT 1 FROM known_devices LIMIT 1')

    def search(self, mac, ifaces=None):
        """Is the device known (on one of the interfaces, if given)?"""
        def query():
            if ifaces is None or 'iface' not in self._columns:  # older databases know devices everywhere
                return 'SELECT 1 FROM known_devices WHERE mac=?', (mac,)
            names = ((ifaces,) if isinstance(ifaces, str) else tuple(ifaces)) + ('',)
            return (
                'SELECT 1 FROM known_devices WHERE mac=? AND iface IN ({})'.format(', '.join('?' * len(names))),
                (mac,) + names,
            )
        return bool(self._read(query))

    def remove(self, mac):
        """Remove MAC address. Return False if it was not known."""
        return self._write('DELETE FROM known_devices WHERE mac=?', (mac,)) > 0

    def clear(self):
        """Remove all MAC addresses. Return how many were removed."""
        return self._write('DELETE FROM known_devices')
