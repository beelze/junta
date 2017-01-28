#!/usr/bin/env python3

import sys
import os
import logging
import logging.handlers
import configparser
import re
import ipaddress
import threading
import pwd
import subprocess
import stat
import signal
import csv
from shutil import which, chown
from pathlib import Path
from collections import OrderedDict
from string import Template
from random import sample
from time import sleep
from socket import AF_INET, AF_INET6, SOCK_STREAM, SOCK_DGRAM
from importlib.util import find_spec

MINVER = (3, 3)
DAEMON = 'dnscrypt-proxy'
MYNAME = 'dnscrypt-proxies'
DEFAULT_LOGFILE = '/var/log/dnscrypt-proxy/'+MYNAME+'.log'
DEFAULT_CONFIG_INSTANCE = '/etc/dnscrypt-proxy/${name}.conf'
DEFAULT_LOGFILE_INSTANCE = '/var/log/dnscrypt-proxy/${name}.log'
LOGFILE_INSTANCE_PERMISSIONS = 0o640
CONFIG_LOCATIONS = [str(Path(__file__).parent / (MYNAME+'.conf')),
                    '/etc/'+MYNAME+'.conf',
                    '/etc/dnscrypt-proxy/'+MYNAME+'.conf']
CONFIG_BOOLEANS = {'yes': True, 'true': True, 'on': True, 'no': False, 'false': False, 'off': False}
CONFIG_MODES = ('config', 'list', 'manual', 'random')
INSTANCE_OPTS = ('mode', 'nrandom', 'blocklist', 'config', 'logfile', 'loglevel', 'localaddress',
                 'resolverslist', 'providerkey', 'resolveraddress',
                 'ephemeralkeys', 'tcponly', 'maxactiverequests', 'ednspayloadsize', 'user')

PROCESS_POLL_TIMEOUT = 1
SERVICE_THREADS_DELAY = 30
INSTANCE_CHECK_CONNECTIONS_DELAY = 3

ERR_GETSOCK = 'failed to get listening socket: '
ERR_NOTBOOLEAN = 'not a boolean'
ERR_UNEXPECTEDOPTS = "unexpected options in [{}]: {}"
MSG_USAGE = """
options: --help    | -h (help)
         --verbose | -v (verbose)
         --config  | -f <config_file>"""
ERR_CONFFILE = 'Failed to find config file'
ERR_NOTFILE = 'file not exists/not a file'

if sys.hexversion < (MINVER[0] * 0x100 + MINVER[1]) * 0x10000:
    print("We need at least python {0[0]}.{0[1]}".format(MINVER), file=sys.stderr)
    sys.exit(1)

psutil = None
if find_spec('psutil'):
    import psutil
else:
    print("Failed to find psutil module, advanced functionality is disabled\n"
          "Consider installing psutil in your package manager or just run 'pip install psutil,'\n"
          "...but ensure you're installing psutil for python3!\n", file=sys.stderr)


def _get_pwname(name_or_uid):
    pwname = None
    try:
        pwname = pwd.getpwnam(name_or_uid).pw_name
    except KeyError:
        pass
    try:
        pwname = pwd.getpwuid(int(name_or_uid)).pw_name
    except (KeyError, ValueError):
        pass
    return pwname


def _template_subst(text, **kwargs):
    return Template(text).safe_substitute(**kwargs)


def _boolean_opt(value):
    return CONFIG_BOOLEANS.get(value.lower(), None)


def _isfile(filename):
    if not isinstance(filename, Path):
        filename = Path(filename)
    return filename.exists() and filename.is_file()


def _load_opt(option, value):
    if option == 'mode':
        v = value.lower()
        if v in CONFIG_MODES:
            return True, v
        else:
            return False, "valid modes are: {}".format(', '.join(CONFIG_MODES))

    elif option == 'blocklist':
        v = []
        try:
            for item in [f.strip() for f in value.split(',')]:
                fld, sep, regex = item.partition(':')
                fld, regex = fld.strip(), regex.strip()
                if not fld or not regex:
                    raise ValueError()
                else:
                    v.append((fld, re.compile(regex, re.I)))
            return True, v

        except Exception as e:
            return False, str(e)+' (expected comma-delimited list of field:regexp)'

    elif option in ('localaddress', 'resolveraddress'):
        try:
            return True, IPPort(value)
        except ValueError as e:
            return False, str(e)

    elif option == 'resolverslist':
        if _isfile(value):
            return True, value
        else:
            return False, ERR_NOTFILE

    elif option in ['ephemeralkeys', 'tcponly']:
        v = _boolean_opt(value)
        if v is None:
            return False, ERR_NOTBOOLEAN
        else:
            return True, v

    elif option in ['maxactiverequests', 'ednspayloadsize', 'loglevel', 'nrandom']:
        try:
            v = int(value)
        except ValueError:
            v = -1
        if option == 'loglevel':
            if 0 <= v <= 7:
                return True, v
            else:
                return False, 'valid values are 0..7'
        elif option == 'nrandom':
            if 1 <= v <= 10:
                return True, v
            else:
                return False, 'valid values are 1..10'
        else:
            if v > 0:
                return True, v
            else:
                return False, 'not a positive integer'
    elif option == 'user':
        v = _get_pwname(value)
        if v is not None:
            return True, v
        else:
            return False, 'not a valid username or uid'
    else:
        return True, value


def _load_opts(config, section, setter):
    s = section
    od = dict(config.items(s))

    for o in INSTANCE_OPTS:
        v = od.pop(o, None)
        if v is not None and v != '':
            res, value = _load_opt(o, v)
            if res:
                if _check_opt(section, o, value):
                    setter(o, value)
            else:
                raise MyConfigValueError(value, s, o, v)
    if od:
        raise MyConfigUnexpectedOpts(s, od)


def _check_opt(section, option, value):
    if section != 'common':
        if option in ('blocklist', 'nrandom'):
            raise MyConfigNotAllowedError('allowed only in [common]', section, option)
        if option == 'mode' and value == 'random':
            raise MyConfigNotAllowedError('allowed only in [common]', section, option, value)
    if section == 'common':
        if option in ('providerkey', 'resolveraddress'):
            raise MyConfigNotAllowedError('allowed only in instance sections', section, option, value)
    return True


class IPPort(str):
    def __new__(cls, ipport, optional_port=True):
        ip, port = None, None
        try:
            if isinstance(ipport, (tuple, list)):
                if 1 <= len(ipport) <= 2:
                    ip = ipaddress.ip_address(ipport[0])
                    if len(ipport) == 2:
                        if ipport[1] is not None:
                            port = cls._check_port(ipport[1])
                    if not optional_port and port is None:
                        raise ValueError('port is mandatory')
                else:
                    raise ValueError('expected tuple or list of: ip, port')
            else:
                # [ipv6]:port
                _ip, sep, _port = ipport.partition(']:')
                if sep:
                    if _ip and _port and _ip[0] == '[':
                        ip, port = ipaddress.IPv6Address(_ip[1:]), cls._check_port(_port)
                    else:
                        raise ValueError()
                else:
                    # ipv4:port
                    _ip, sep, _port = ipport.partition(':')
                    if sep:
                        if _ip and _port:
                            ip, port = ipaddress.IPv4Address(_ip), cls._check_port(_port)
                        else:
                            raise ValueError()
                    else:
                        # [ipv6] or ipv4
                        if optional_port:
                            ip = ipaddress.ip_address(_ip)
                        else:
                            raise ValueError('port is mandatory')

        except ValueError as ipport_err:
            msg = str(ipport_err)
            if not msg:
                msg = 'not a valid ipv4[:port] or \[ipv6\][:port]'
            raise ValueError(msg)

        o = super().__new__(cls, cls._to_str(ip, port))
        o._initialized = False
        o.ip, o.port = ip, port
        o._initialized = True
        return o

    def __setattr__(self, key, value):
        if key in ('ip', 'port') and self._initialized:
            raise AttributeError('{}().{} is not mutable'.format(self.__class__.__name__, key))
        else:
            super().__setattr__(key, value)

    @staticmethod
    def _check_port(port):
        # noinspection PyBroadException
        try:
            port = int(port)
            if 0 < port < 65535:
                return port
        except:
            pass
        raise ValueError('invalid port value: ' + str(port))

    @staticmethod
    def _to_str(ip, port):
        if ip:
            str_ip = str(ip)
            if isinstance(ip, ipaddress.IPv6Address):
                str_ip = '[' + str_ip + ']'
            if port:
                str_ip += ':' + str(port)
            return str_ip
        else:
            return 'None:None'

    def next_address(self):
        return IPPort((self.ip + 1, self.port))

    def __str__(self):
        return self._to_str(self.ip, self.port)


class MyError(Exception):
    def __init__(self, msg, exitcode=1, logerror=True):
        self.msg, self.exitcode, self.logerror = msg, exitcode, logerror
        super().__init__(msg)


class MyCmdlineError(MyError):
    def __init__(self, msg=None):
        super().__init__(msg="Invalid command line{}\n".format(': '+msg if msg is not None else '')+MSG_USAGE.strip(),
                         logerror=False)


class MyUsageException(MyError):
    def __init__(self):
        super().__init__(msg=MSG_USAGE.strip(), exitcode=0, logerror=False)


class MyConfigValueError(MyError):
    def __init__(self, msg, section, option, value):
        super().__init__("Invalid value '{}' for [{}].{}: {}".format(value, section, option, msg))


class MyConfigUniqueError(MyError):
    def __init__(self, section, option, value):
        super().__init__("Value '{}' for [{}].{} is not unique".format(value, section, option))


class MyConfigNotAllowedError(MyError):
    def __init__(self, msg, section, option, value=None):
        super().__init__("[{}]: {}{} {}".format(section, option, '' if value is None else '='+str(value), msg))


class MyConfigUnexpectedOpts(MyError):
    def __init__(self, section, options):
        super().__init__(ERR_UNEXPECTEDOPTS.format(section, ', '.join(options)))


class MyTerminateException(MyError):
    def __init__(self):
        super().__init__('Terminated')


class MetaInstance(type):
    def __new__(mcs, name, bases, namespace, config, section):
        for o in INSTANCE_OPTS:
            namespace[o] = None
        if section in config:
            _load_opts(config, section, namespace.__setitem__)
        namespace['nextip'] = namespace['localaddress']
        namespace['uniques'] = set()

        return super().__new__(mcs, name, bases, namespace)

    # noinspection PyUnusedLocal
    def __init__(cls, name, bases, namespace, **kwargs):
        super().__init__(name, bases, namespace)


# noinspection PyUnresolvedReferences
class InstanceBase(threading.Thread):
    def __init__(self, config, section):
        self.instance_name = section

        self.real_localaddress = None
        self.process = None
        self.binary = None
        self.logger = None
        self._instance_logfile = None

        la, is_config = 'localaddress', isinstance(config, configparser.ConfigParser)
        if is_config:
            od = dict(config.items(section))
        else:
            od = config
        laddr = od.get(la, None)

        if laddr is None:
            self.__setattr__(la, self._allocate_ip())

        if is_config:
            _load_opts(config, section, self.__setattr__)
        else:
            self.__dict__.update(config)

        self._prepare()

        super().__init__(name=self.instance_name, daemon=False)

    def _allocate_ip(self):
        n = self.__class__.nextip
        if n:
            self.__class__.nextip = self.__class__.nextip.next_address()
            return n
        else:
            return None

    def _check_unique(self, domain, value):
        l = len(self.__class__.uniques)
        self.__class__.uniques |= {hash((domain, value))}
        return len(self.__class__.uniques) > l

    def _prepare(self):
        if self.mode == 'config':
            if not self.config:
                self.config = DEFAULT_CONFIG_INSTANCE
            self.config = _template_subst(self.config, name=self.instance_name)
            if not self._check_unique('config', self.config):
                raise MyConfigUniqueError(self.instance_name, 'config', self.config)
            if not _isfile(self.config):
                raise MyConfigValueError(ERR_NOTFILE, self.instance_name, 'config', self.config)
            return

        if self.mode == 'list':
            if not _isfile(self.resolverslist):
                raise MyConfigValueError(ERR_NOTFILE, self.instance_name, 'resolverslist', self.resolverslist)

        elif self.mode == 'manual':
            if not self.providerkey:
                raise configparser.Error("[{}].providerkey is mandatory for manual mode".format(self.instance_name))
            if not self.resolveraddress:
                raise configparser.Error("[{}].resolveraddress is mandatory for manual mode".format(self.instance_name))

        else:
            raise configparser.Error("[{}].mode is mandatory".format(self.instance_name))

        if not self.localaddress:
            raise configparser.Error("[{}].localaddress is mandatory for non-config modes".format(self.instance_name))

        if not self._check_unique('localaddress', self.localaddress):
            raise MyConfigUniqueError(self.instance_name, 'localaddress', self.localaddress)

    def _correct_logfile_permissions(self):
        if self.user is not None and self.user != 'root' and self._instance_logfile is not None:
            try:
                p = Path(self._instance_logfile)
                if not p.exists():
                    self.logger.info("Creating " + str(p))
                    p.touch(mode=LOGFILE_INSTANCE_PERMISSIONS)

                if p.owner() != self.user:
                    self.logger.info("Correcting user for "+str(p))
                    chown(str(p), self.user)
                mode = p.stat().st_mode
                if not stat.S_ISREG(mode):
                    raise PermissionError("Not a regular file")
                mode = stat.S_IMODE(mode)
                if mode & LOGFILE_INSTANCE_PERMISSIONS != LOGFILE_INSTANCE_PERMISSIONS:
                    self.logger.info("Correcting mode for "+str(p))
                    p.chmod(LOGFILE_INSTANCE_PERMISSIONS)
            except (OSError, PermissionError) as e:
                self.logger.error("Failed to create or access/set logfile permissions: {}".format(e))
                return False
        return True

    def info(self):
        txt = self.mode + ' mode'
        if self.mode != 'config':
            txt += ', local ' + self.localaddress
        if self.mode == 'manual':
            txt += ', resolver ' + self.resolveraddress
        return txt

    def is_process_alive(self):
        return self.process is not None and self.process.returncode is None

    # noinspection PyMethodOverriding
    def start(self, binary, logger):
        self.binary, self.logger = binary, logger
        super().start()

    def _get_real_localaddress(self):
        sleep(INSTANCE_CHECK_CONNECTIONS_DELAY)
        self.real_localaddress, conns = tuple(), None
        if self.is_process_alive():
            try:
                conns = psutil.Process(self.process.pid).connections()
            except psutil.NoSuchProcess:
                self.logger.warning(ERR_GETSOCK +
                                    'no process with pid {} exists'.format(self.process.pid))
            except Exception as e:
                self.logger.warning(ERR_GETSOCK +
                                    'unexpected {}'.format(str(e)))
            if conns:
                self.real_localaddress = tuple(set([IPPort(conn.laddr) for conn in conns if
                                                    conn.family in (AF_INET, AF_INET6) and
                                                    (conn.type == SOCK_STREAM and conn.status == 'LISTEN') or
                                                    (conn.type == SOCK_DGRAM and conn.status == 'NONE')
                                                    ]))
                nconns = len(self.real_localaddress)
                if nconns == 1:
                    self.logger.info('detected listening socket: {}'.format(self.real_localaddress[0]))
                elif nconns > 1:
                    self.logger.warning('more than one listening socket detected: {}'.format(
                        ', '.join(self.real_localaddress)))
                else:
                    self.logger.warning('unexpected: no listening sockets detected')

    def run(self):
        args = [self.binary] + self.cmdline_args()
        if self._correct_logfile_permissions():
            self.logger.debug("Starting '{}'".format(' '.join(args)))
            try:
                self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                bufsize=1, universal_newlines=True)
                self.logger.info("Started <{}>".format(self.process.pid))
                if psutil:
                    threading.Thread(name=self.name, target=self._get_real_localaddress).start()
                while self.process.returncode is None:
                    try:
                        self.process.wait(PROCESS_POLL_TIMEOUT)
                    except subprocess.TimeoutExpired:
                        pass
                    for line in self.process.stdout:
                        self.logger.info('> '+line.strip())
                    for line in self.process.stderr:
                        self.logger.info('>> '+line.strip())

                self.logger.info('Exited with code '+str(self.process.returncode))
            except (OSError, subprocess.SubprocessError) as e:
                self.logger.error('Error executing process: '+str(e))

    def cmdline_args(self):
        if self.mode == 'config':
            return [self.config]
        if self.mode == 'list':
            args = ['-L', self.resolverslist, '-R', self.instance_name]
        else:
            args = ['-N', self.instance_name, '-k', self.providerkey, '-r', self.resolveraddress]

        args += ['-a', self.localaddress]
        logfile = self.logfile or ''
        if logfile.lower() != 'none':
            if logfile.lower() == 'syslog':
                args += ['-S', '-Z', '[{}]'.format(self.instance_name)]
            else:
                if logfile == '':
                    logfile = DEFAULT_LOGFILE_INSTANCE
                logfile = _template_subst(logfile, name=self.instance_name)
                args += ['-l', logfile]
                self._instance_logfile = logfile
            if self.loglevel is not None:
                args += ['-m', str(self.loglevel)]
        if self.user is not None:
            args += ['-u', self.user]
        return args


class MyLevelFilter:
    def __init__(self, exclusive_maximum):
        self.max_level = exclusive_maximum

    def filter(self, record):
        # non-zero return means we log this message
        return 1 if record.levelno < self.max_level else 0


class MyLogger(logging.Logger):
    def _log(self, level, msg, args, exc_info=None, extra=None, stack_info=False):
        for line in str(msg).split('\n'):
            super()._log(level, line, args, exc_info, extra, stack_info)


class App:
    def __init__(self, argv):
        threading.main_thread().name = ''
        self._argv = argv
        self._break = False
        self._ss_lock = threading.Lock()

        self._file_formatter = logging.Formatter(
            fmt='${asctime} [' + MYNAME + '${threadName}] ${levelname}:${lineno} ${message}',
            datefmt='%Y-%m-%d %H:%M:%S', style='$')
        self._syslog_formatter = logging.Formatter(
            fmt=MYNAME + '${threadName} ${levelname}:${lineno} ${message}', style='$')
        self.logger = logging.getLogger('main')
        log_hnd_out = logging.StreamHandler(sys.stdout)
        log_hnd_out.setLevel(logging.DEBUG)
        log_hnd_out.addFilter(MyLevelFilter(logging.WARNING))
        log_hnd_out.setFormatter(self._file_formatter)
        self.logger.addHandler(log_hnd_out)

        log_hnd_err = logging.StreamHandler(sys.stderr)
        log_hnd_err.setLevel(logging.WARNING)
        log_hnd_err.setFormatter(self._file_formatter)
        self.logger.addHandler(log_hnd_err)

        self._is_syslog = False
        self._old_record_factory = logging.getLogRecordFactory()
        logging.setLogRecordFactory(self._record_factory)

        self._daemon = None
        self._statinterval = None

        self._config_file = None
        self.config = configparser.ConfigParser(strict=True, inline_comment_prefixes=(';',))
        self.config.SECTCRE = re.compile(r"\[\s*(?P<header>[^]]+?)\s*\]", re.I)

        self.instances = OrderedDict()
        self.instances_started = False

    def initialize(self):
        if self._break:
            raise MyTerminateException()

        self._parse_cmdline(self._argv)
        self._find_config_file()
        try:
            self._load_config()
        except configparser.Error as e:
            raise MyError('Parsing config: '+str(e))

        if os.geteuid() != 0:
            self.logger.warning('This script is supposed to run as superuser')
        self._daemon = which(DAEMON)
        if not self._daemon:
            raise MyError("executable '{}' not found".format(DAEMON), logerror=False)
        self.logger.info('Initialized')

    def _load_config(self):
        self.logger.debug('Reading config '+str(self._config_file))
        self.config.read(str(self._config_file))
        s = 'settings'
        od = dict(self.config.items(s))
        if od:
            o = 'loglevel'
            isdebug = (self.logger.getEffectiveLevel() == logging.DEBUG)
            ll = od.pop(o, None)
            if ll is not None:
                try:
                    _ll = int(ll)
                except ValueError:
                    _ll = ll.upper()
                try:
                    self.logger.setLevel(_ll)
                    if isdebug and not self.logger.isEnabledFor(logging.DEBUG):
                        self.logger.setLevel(logging.DEBUG)
                except ValueError:
                    raise MyConfigValueError('invalid logging level name/value', s, o, ll)

            o = 'log'
            log = od.pop(o, '')
            try:
                if not log:
                    tgt = DEFAULT_LOGFILE
                    hnd = logging.handlers.WatchedFileHandler(DEFAULT_LOGFILE)
                    hnd.setFormatter(self._file_formatter)
                elif log.lower() == 'syslog':
                    tgt = 'syslog'
                    hnd = logging.handlers.SysLogHandler('/dev/log', logging.handlers.SysLogHandler.LOG_DAEMON)
                    hnd.setFormatter(self._syslog_formatter)
                elif log.lower() == 'console':
                    tgt = 'console'
                else:
                    tgt = log
                    hnd = logging.handlers.WatchedFileHandler(log)
                    hnd.setFormatter(self._file_formatter)

                if tgt != 'console':
                    self.logger.debug('Switching logging to '+tgt)
                    oldhandlers = list(self.logger.handlers)
                    self.logger.addHandler(hnd)

                    if tgt == 'syslog':
                        self._is_syslog = True

                    for h in oldhandlers:
                        self.logger.removeHandler(h)

            except (FileNotFoundError, PermissionError) as e:
                # noinspection PyUnboundLocalVariable
                self.logger.warning("Failed to access/create logfile {}: {}".format(tgt, str(e)))

            o = 'statinterval'
            statinterval = od.pop(o, '')
            if statinterval:
                try:
                    self._statinterval = int(statinterval)
                    if self._statinterval <= 0:
                        raise ValueError
                    if self._statinterval < 10*60:
                        self.logger.warning("[settings].statinterval seems too short ({}s)".format(self._statinterval))
                except ValueError:
                    raise MyConfigValueError('not a valid positive integer', s, o, statinterval)

            if od:
                raise MyConfigUnexpectedOpts(s, od)

    def _record_factory(self, *args, **kwargs):
        record = self._old_record_factory(*args, **kwargs)
        thn = record.threadName
        if thn != '':
            thn = (' [' + thn + ']' if self._is_syslog else ':' + thn)
            record.threadName = thn
        return record

    def _parse_cmdline(self, _argv):
        argv = list(_argv)

        # noinspection PyPep8,PyShadowingNames
        def _eat_option(option, loption=None):
            found, first, last, left, idx = False, None, None, None, None
            try:
                idx = argv.index('-' + option)
            except ValueError:
                try:
                    if loption is not None:
                        idx = argv.index('--' + loption)
                except ValueError:
                    pass
            if idx is not None:
                found, first, last, left = True, idx==0, idx==len(argv)-1, len(argv)-1
                del argv[idx]
            return found, first, last, left

        found, first, last, left = _eat_option('h', 'help')
        if found:
            if not left:
                raise MyUsageException()
            else:
                raise MyCmdlineError()

        found, first, last, left = _eat_option('v', 'verbose')
        if found:
            if first or last:
                self.logger.setLevel(logging.DEBUG)
            else:
                raise MyCmdlineError()

        found, first, last, left = _eat_option('f', 'config')
        if found:
            if first and left == 1:
                self._config_file = argv[0]
                del argv[0]
            else:
                raise MyCmdlineError()

        if len(argv):
            raise MyCmdlineError('unexpected '+', '.join(["'"+a+"'" for a in argv]))

    def _find_config_file(self):
        if self._config_file:
            locs = [self._config_file]
        else:
            locs = list(CONFIG_LOCATIONS)

        for loc in locs:
            p = Path(loc)
            if _isfile(p):
                self._config_file = p
                self.logger.debug('Config file found: '+str(p))
                return
            else:
                self.logger.debug('Config file not found: '+str(p))
        else:
            raise MyError(ERR_CONFFILE)

    def _random_resolvers(self, cnt, file, blocklist):
        def in_blocklist(dct):
            for f, regex in blocklist:
                if f in dct and regex.search(dct[f]):
                    return True
            return False

        resolvers, filtered = set(), 0
        self.logger.debug('Trying to parse (csv) resolvers list from '+file)
        try:
            with open(file) as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if not in_blocklist(row):
                        resolvers.add(row['Name'])
                    else:
                        filtered += 1
        except Exception as e:
            raise configparser.Error('Error when parsing resolvers list: '+str(e))

        lr = len(resolvers)
        self.logger.debug("{} suitable resolvers found, {} filtered out".format(lr, filtered))
        if lr < cnt:
            self.logger.warning("There aren't enough resolvers: {}, but {} requested".format(lr, cnt))
            cnt = lr
        return sample(resolvers, cnt)

    def init_instances(self, klass):
        if self._break:
            raise MyTerminateException()
        instance_sections = tuple([s for s in self.config if s not in ('DEFAULT', 'settings', 'common')])

        if klass.mode == 'random':
            if instance_sections:
                self.logger.warning(
                    "Random mode selected ({} instances), all defined instance sections are ignored: {}".format(
                        klass.nrandom, ", ".join(instance_sections)))

            if not klass.resolverslist or not klass.localaddress:
                raise MyError('[common].ResolversList/LocalAddress are mandatory in random mode')
            for resolver in self._random_resolvers(klass.nrandom, klass.resolverslist, klass.blocklist):
                self.instances[resolver] = klass({'mode': 'list'}, resolver)

        else:
            if 'common' not in self.config:
                self.logger.warning('Config: no [common] section; all instance options need to be defined explicitly')

            for section in instance_sections:
                self.instances[section] = klass(config=self.config, section=section)

        if not self.instances:
            raise MyError('No instances configured')

        for i in self.instances.values():
            self.logger.debug("Configured [{}]: {}".format(i.instance_name, i.info()))

    def run_instances(self):
        with self._ss_lock:
            if self._break:
                raise MyTerminateException()
            for i in self.instances.values():
                i.start(self._daemon, self.logger)
            self.instances_started = True
        for i in self.instances.values():
            if i.is_alive():
                i.join()

    def rearm_timer(self, interval=-1):
        if self._statinterval:
            signal.setitimer(signal.ITIMER_REAL, interval if interval > 0 else self._statinterval, 0)

    def logstat(self):
        if self.instances_started:
            active, inactive = [], []
            for i in self.instances.values():
                if i.is_alive():
                    active.append((i.instance_name, i.process.pid))
                else:
                    inactive.append((i.instance_name, i.process.returncode if i.is_process_alive() else '-'))

            txt = "{} active instance(s) <pid>: {}".format(
                len(active),
                ', '.join(["{} <{}>".format(*i) for i in active]))
            if len(inactive):
                txt += "\n{} crashed instance(s) <exit code>: {}".format(
                    len(inactive),
                    ', '.join(["{} <{}>".format(*i) for i in inactive]))
            self.logger.info(txt)
        self.rearm_timer()

    def terminate(self):
        with self._ss_lock:
            self.logger.info('Caught signal, terminating')
            self._break = True

            for i in self.instances.values():
                if i.is_process_alive():
                    self.logger.info('Sending SIGTERM to ' + i.instance_name)
                    try:
                        os.kill(i.process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    logging.setLoggerClass(MyLogger)
    app = None

    # noinspection PyUnusedLocal
    def signal_handler(signum, frame):
        if app is not None:
            if signum in (signal.SIGINT, signal.SIGTERM):
                app.terminate()
            elif signum == signal.SIGALRM:
                app.logstat()
        else:
            print('Signal caught too early', file=sys.stderr)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGALRM, signal_handler)

    try:
        app = App(sys.argv[1:])
        app.initialize()

        class Instance(InstanceBase, metaclass=MetaInstance, config=app.config, section='common'):
            pass

        app.logger.debug('Default instance parameters: ' +
                         ', '.join(['{}={}'.format(n, v) for n, v in
                                    [(o, getattr(Instance, o)) for o in
                                    set(INSTANCE_OPTS) - {'blocklist', 'nrandom'}]
                                    if v is not None]))
        # noinspection PyTypeChecker
        app.init_instances(Instance)
        app.rearm_timer(SERVICE_THREADS_DELAY)
        app.run_instances()
        app.logger.info('Clean exit')
        sys.exit(0)

    except MyError as myerr:
        if myerr.logerror:
            app.logger.error(myerr.msg)
        else:
            print(myerr.msg)
        sys.exit(myerr.exitcode)
