#!/usr/bin/python3
# -*- coding: utf-8 -*-
# must install:
# pip3 install lz4
# pip3 install --upgrade keyrings.alt
# pip3 install secretstorage
# pip3 install psutil
__doc__ = 'Load browser cookies and clean it'

import os
import sys
import time
import glob
from contextlib import contextmanager
import tempfile
try:
    import json
except ImportError:
    import simplejson as json
try:
    import ConfigParser as configparser
except ImportError:
    import configparser

try:
    # should use pysqlite2 to read the cookies.sqlite on Windows
    # otherwise will raise the "sqlite3.DatabaseError: file is encrypted or is not a database" exception
    from pysqlite2 import dbapi2 as sqlite3
except ImportError:
    import sqlite3

import lz4.block
import keyring
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import secretstorage
import psutil
import webbrowser

class BrowserCookieError(Exception):
    pass


@contextmanager
def create_local_copy(cookie_file):
    """Make a local copy of the sqlite cookie database and return the new filename.
    This is necessary in case this database is still being written to while the user browses
    to avoid sqlite locking errors.
    """
    # check if cookie file exists
    if os.path.exists(cookie_file):
        # copy to random name in tmp folder
        tmp_cookie_file = tempfile.NamedTemporaryFile(suffix='.sqlite').name
        open(tmp_cookie_file, 'wb').write(open(cookie_file, 'rb').read())
        yield tmp_cookie_file
    else:
        raise BrowserCookieError('Can not find cookie file at: ' + cookie_file)

    os.remove(tmp_cookie_file)


class BrowserCookieLoader(object):
    def __init__(self, cookie_files=None):
        cookie_files = cookie_files or self.find_cookie_files()
        self.cookie_files = list(cookie_files)
        self.sites = [ '.instagram.com', '.amazon.com.br' ]
        self.open_browser()

    def add_sites_to_logout(self, sites):
        if len(sites) > 0:
            self.sites.append(sites)

    def find_cookie_files(self):
        '''Return a list of cookie file locations valid for this loader'''
        raise NotImplementedError

    def get_cookies(self):
        '''Return all cookies (May include duplicates from different sources)'''
        raise NotImplementedError

    def logout_from_sites(self):
        '''Logout from sites included in self.sites'''
        raise NotImplementedError

    # TODO: both methods
    def open_browser(self):
        '''Open a new browser process'''
        url = "http://www.google.com"
        webbrowser.get(using=self.__str__()).open(url,new=2)
        # raise NotImplementedError

    def close_browser(self):
        '''Open all browser processes'''
        raise NotImplementedError

class Chrome(BrowserCookieLoader):
    def __str__(self):
        return 'google-chrome'

    # TODO: return process name

    def close_browser(self):
        for proc in psutil.process_iter():
            proc_name = proc.name()
            if 'chrome' in proc_name:
                # print ('Closing browser')
                proc.kill()

    def find_cookie_files(self):
        for pattern in [
            os.path.expanduser('~/Library/Application Support/Google/Chrome/Default/Cookies'),
            os.path.expanduser('~/Library/Application Support/Vivaldi/Default/Cookies'),
            os.path.expanduser('~/.config/chromium/Default/Cookies'),
            os.path.expanduser('~/.config/chromium/Profile */Cookies'),
            os.path.expanduser('~/.config/google-chrome/Default/Cookies'),
            os.path.expanduser('~/.config/google-chrome/Profile */Cookies'),
            os.path.expanduser('~/.config/vivaldi/Default/Cookies'),
            os.path.join(os.getenv('APPDATA', ''), r'..\Local\Google\Chrome\User Data\Default\Cookies'),
            os.path.join(os.getenv('APPDATA', ''), r'..\Local\Vivaldi\User Data\Default\Cookies'),
        ]:
            for result in glob.glob(pattern):
                yield result

    def get_cookies(self):
        salt = b'saltysalt'
        length = 16
        if sys.platform == 'darwin':
            # running Chrome on OSX
            my_pass = keyring.get_password('Chrome Safe Storage', 'Chrome')
            my_pass = my_pass.encode('utf8')
            iterations = 1003
            key = PBKDF2(my_pass, salt, length, iterations)

        elif sys.platform.startswith('linux'):
            # running Chrome on Linux
            bus = secretstorage.dbus_init()
            collection = secretstorage.get_default_collection(bus)
            for item in collection.get_all_items():
                if item.get_label() == 'Chrome Safe Storage':
                    my_pass = item.get_secret()
                    break
            else:
                raise Exception('Chrome password not found!')

            print ('pass: ', my_pass)
            iterations = 1
            key = PBKDF2(my_pass, salt, length, iterations)

        elif sys.platform == 'win32':
            key = None
        else:
            raise BrowserCookieError('Unsupported operating system: ' + sys.platform)

        for cookie_file in self.cookie_files:
            with create_local_copy(cookie_file) as tmp_cookie_file:
                con = sqlite3.connect(tmp_cookie_file)
                con.row_factory = sqlite3.Row
                cur = con.cursor()
                cur.execute('SELECT value FROM meta WHERE key = "version";')
                version = int(cur.fetchone()[0])
                query = 'SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value FROM cookies;'
                if version < 10:
                    query = query.replace('is_', '')
                cur.execute(query)
                for item in cur.fetchall():
                    host, path, secure, expires, name = item[:5]
                    value = self._decrypt(item[5], item[6], key=key)
                    # if item[0] == '.instagram.com':
                    #     print ('domain: ' + item[0] + ' name: ' + name + ' value: ' + value)
                    yield create_cookie(host, path, secure, expires, name, value)
                con.close()

    def logout_from_sites(self):
        self.close_browser()
        for cookie_file in self.cookie_files:
            con = sqlite3.connect(cookie_file)
            cur = con.cursor()

            for site in self.sites:
                # query = 'SELECT * FROM cookies WHERE host_key = ? and name LIKE ?;'
                # cur.execute(query, (site, '%session%'))
                # for item in cur.fetchall():
                #     print(item)

                query = 'SELECT * FROM cookies WHERE host_key = ?;'
                cur.execute(query, (site, ))
                for item in cur.fetchall():
                    print(item)

                query = 'DELETE FROM cookies WHERE host_key = ?;'
                cur.execute(query, (site, ))

            con.commit()
            con.close()
        self.open_browser()

    def _decrypt(self, value, encrypted_value, key):
        """Decrypt encoded cookies
        """
        if (sys.platform == 'darwin') or sys.platform.startswith('linux'):
            # Encrypted cookies should be prefixed with 'v10' according to the
            # Chromium code. Strip it off.
            encrypted_value = encrypted_value[3:]

            # Strip padding by taking off number indicated by padding
            # eg if last is '\x0e' then ord('\x0e') == 14, so take off 14.
            def clean(x):
                if len(x) > 0:
                    last = x[-1]
                    if isinstance(last, int):
                        return x[:-last].decode('utf8')
                    else:
                        return x[:-ord(last)].decode('utf8')
                else:
                    return ''

            iv = b' ' * 16
            cipher = AES.new(key, AES.MODE_CBC, IV=iv)
            decrypted = cipher.decrypt(encrypted_value)
            return clean(decrypted)
        else:
            # Must be win32 (on win32, all chrome cookies are encrypted)
            try:
                import win32crypt
            except ImportError:
                raise BrowserCookieError('win32crypt must be available to decrypt Chrome cookie on Windows')
            return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode("utf-8")


class Firefox(BrowserCookieLoader):
    def __str__(self):
        return 'firefox'

    def parse_profile(self, profile):
        cp = configparser.ConfigParser()
        cp.read(profile)
        path = None
        for section in cp.sections():
            try:
                if cp.getboolean(section, 'IsRelative'):
                    path = os.path.dirname(profile) + '/' + cp.get(section, 'Path')
                else:
                    path = cp.get(section, 'Path')
                if cp.has_option(section, 'Default'):
                    return os.path.abspath(os.path.expanduser(path))
            except configparser.NoOptionError:
                pass
        if path:
            return os.path.abspath(os.path.expanduser(path))
        raise BrowserCookieError('No default Firefox profile found')

    def find_default_profile(self):
        if sys.platform == 'darwin':
            return glob.glob(os.path.expanduser('~/Library/Application Support/Firefox/profiles.ini'))
        elif sys.platform.startswith('linux'):
            return glob.glob(os.path.expanduser('~/.mozilla/firefox/profiles.ini'))
        elif sys.platform == 'win32':
            return glob.glob(os.path.join(os.getenv('APPDATA', ''), 'Mozilla/Firefox/profiles.ini'))
        else:
            raise BrowserCookieError('Unsupported operating system: ' + sys.platform)

    def find_cookie_files(self):
        profile = self.find_default_profile()
        if not profile:
            raise BrowserCookieError('Could not find default Firefox profile')
        path = self.parse_profile(profile[0])
        if not path:
            raise BrowserCookieError('Could not find path to default Firefox profile')
        cookie_files = glob.glob(os.path.expanduser(path + '/cookies.sqlite'))
        if cookie_files:
            return cookie_files
        else:
            raise BrowserCookieError('Failed to find Firefox cookies')

    def get_cookies(self):
        for cookie_file in self.cookie_files:
            with create_local_copy(cookie_file) as tmp_cookie_file:
                con = sqlite3.connect(tmp_cookie_file)
                cur = con.cursor()
                cur.execute('select host, path, isSecure, expiry, name, value from moz_cookies')

                for item in cur.fetchall():
                    yield create_cookie(*item)
                con.close()

                # current sessions are saved in sessionstore.js/recovery.json/recovery.jsonlz4
                session_files = (os.path.join(os.path.dirname(cookie_file), 'sessionstore.js'),
                    os.path.join(os.path.dirname(cookie_file), 'sessionstore-backups', 'recovery.json'),
                    os.path.join(os.path.dirname(cookie_file), 'sessionstore-backups', 'recovery.jsonlz4'))
                for file_path in session_files:
                    if os.path.exists(file_path):
                        if file_path.endswith('4'):
                            try:
                                session_file = open(file_path, 'rb')
                                # skip the first 8 bytes to avoid decompress failure (custom Mozilla header)
                                session_file.seek(8)
                                json_data = json.loads(lz4.block.decompress(session_file.read()).decode())
                            except IOError as e:
                                print('Could not read file:', str(e))
                            except ValueError as e:
                                print('Error parsing Firefox session file:', str(e))
                        else:
                            try:
                                json_data = json.loads(open(file_path, 'rb').read().decode('utf-8'))
                            except IOError as e:
                                print('Could not read file:', str(e))
                            except ValueError as e:
                                print('Error parsing firefox session JSON:', str(e))

                if 'json_data' in locals():
                    expires = str(int(time.time()) + 3600 * 24 * 7)
                    for window in json_data.get('windows', []):
                        for cookie in window.get('cookies', []):
                            yield create_cookie(cookie.get('host', ''), cookie.get('path', ''), False, expires, cookie.get('name', ''), cookie.get('value', ''))
                else:
                    print('Could not find any Firefox session files')


def chrome(cookie_file=None):
    """Returns a cookiejar of the cookies used by Chrome
    """
    return Chrome(cookie_file)#.load()


def firefox(cookie_file=None):
    """Returns a cookiejar of the cookies and sessions used by Firefox
    """
    return Firefox(cookie_file).load()


def _get_cookies():
    '''Return all cookies from all browsers'''
    for klass in [Chrome, Firefox]:
        try:
            for cookie in klass().get_cookies():
                yield cookie
        except BrowserCookieError:
            pass