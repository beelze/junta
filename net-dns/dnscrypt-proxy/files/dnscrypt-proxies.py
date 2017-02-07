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
from getopt import gnu_getopt, GetoptError
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
INSTANCE_OPTS = ('mode', 'nrandom', 'filter', 'config', 'logfile', 'loglevel', 'localaddress',
                 'resolverslist', 'providerkey', 'resolveraddress',
                 'ephemeralkeys', 'tcponly', 'maxactiverequests', 'ednspayloadsize', 'user')

PROCESS_POLL_TIMEOUT = 1
SERVICE_THREADS_DELAY = 30
INSTANCE_CHECK_CONNECTIONS_DELAY = 3

ERR_GETSOCK = 'failed to get listening socket: '
ERR_NOTBOOLEAN = 'not a boolean'
ERR_UNEXPECTEDOPTS = "unexpected options in [{}]: {}"
MSG_USAGE = """
options: --help          | -h (help)
         --verbose       | -v (verbose)
         --check-config  | -c (check config and exit; console logging)
         --config <file> | -f <file> (config file)"""
ERR_CONFFILE = 'Failed to find config file'
ERR_NOTFILE = 'file not exists/not a file'

if sys.hexversion < (MINVER[0] * 0x100 + MINVER[1]) * 0x10000:
    print("We need at least python {0[0]}.{0[1]}".format(MINVER), file=sys.stderr)
    sys.exit(1)

psutil = None
if find_spec('psutil'):
    import psutil
# else:
#     print("Failed to find psutil module, advanced functionality is disabled\n"
#           "Consider installing psutil in your package manager or just run 'pip install psutil,'\n"
#           "...but ensure you're installing psutil for python3!\n", file=sys.stderr)


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

    elif option == 'filter':
        try:
            return True, ResolverFilter(value)
        except ValueError as e:
            return False, str(e)

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
        if option in ('filter', 'nrandom'):
            raise MyConfigNotAllowedError('allowed only in [common]', section, option)
        if option == 'mode' and value == 'random':
            raise MyConfigNotAllowedError('allowed only in [common]', section, option, value)
    if section == 'common':
        if option in ('providerkey', 'resolveraddress'):
            raise MyConfigNotAllowedError('allowed only in instance sections', section, option, value)
    return True


class ResolverFilter:
    RE_COND = re.compile(r'(?:(?P<fld>\w+)|\[(?P<lfld>[\w ]+)\])\s*(?P<op>=~|==|!~|!=)\s*'
                         r'(?:"(?P<q>(?:[^"]|(?<=\\)")*)"|\'(?P<dq>(?:[^\']|(?<=\\)\')*)\')')
    RE_OTHER = re.compile(r'(?:(?:^|[\s()]+?)(?:and|or|not)[\s()]+?|[\s()]+?)+', re.I)

    FLDS_DEF = 'Name:name,Full name:fullname,Description:desc,Location:loc,' \
               'Coordinates:coords,URL:url,Version:ver,DNSSEC validation:dnssec,' \
               'No logs:nologs,Namecoin:ncoin,Resolver address:addr,Provider name:fqdn,' \
               'Provider public key:pubkey,Provider public key TXT record:txt'

    STR_OP = {'==': 'EQ', '!=': 'NE', '=~': 'LK', '!~': 'UL'}

    _flds = dict({s.lower(): l.lower() for l, s in [d.split(':') for d in FLDS_DEF.split(',')]})
    _r_flds = dict({l: f for f, l in _flds.items()})

    def __init__(self, fdef):
        self._test_names = set()
        self._globals = {'__builtins__': None}
        self._match_mode = True

        fdef = re.sub(r'\s*\n', ' ', fdef.strip())
        m = re.match(r'^(|!)(?:match):\s*', fdef)
        if m:
            fdef = fdef[m.end():]
            if m.group(1) == '!':
                self._match_mode = False

        if fdef == '':
            raise ValueError('empty filter expression')

        self._expr, self._need_fields = self._prepare(fdef)
        try:
            self._code = compile(self._expr, '<filter>', 'eval')
        except (SyntaxError, TypeError) as c_err:
            raise ValueError("failed to compile filter expression: " + str(c_err))

    def _new_test_name(self, fld, op, rval):
        name = '_{}_{}_{}'.format(self.STR_OP[op], fld, re.sub(r'\W', '_', rval if rval else '_'))

        def safename(index):
            return name + ('' if index == 0 else '_' + str(i))

        i = 0
        while safename(i) in self._test_names:
            i += 1
        name = safename(i)
        self._test_names.add(name)
        return name

    @staticmethod
    def _new_test_func(op, rval):
        if op in ('==', '!='):
            def f_eq(fld):
                _fld = fld.lower()
                return _fld == rval if op == '==' else not _fld == rval

            return f_eq

        else:
            def f_like(fld):
                m = rval.search(fld) is not None
                return m if op == '=~' else not m

            return f_like

    def _get_fldname(self, name=None, longname=None, silent=False):
        if name is not None:
            _name = name.lower()
            if _name in self._flds:
                return _name
            else:
                if silent:
                    return None
                else:
                    raise ValueError("unexpected field (short): '{}'".format(name))
        else:
            sname = self._r_flds.get(longname.lower(), None)
            if sname is not None:
                return sname
            else:
                if silent:
                    return None
                else:
                    raise ValueError("unexpected field: '{}'".format(longname))

    def _prepare(self, fdef):
        used_fields = set()
        regexs, fails = (self.RE_OTHER, self.RE_COND), 0
        lfdef, i, pos = len(fdef), 0, 0
        accum = ''

        while True:
            m = regexs[i % 2].match(fdef, pos)
            if m:
                fails = 0
                d = m.groupdict()
                if d:
                    fld = self._get_fldname(d['fld'], d['lfld'])
                    used_fields.add(fld)
                    op, rval = d['op'], d['q'] or d['dq']

                    if op in ('==', '!='):
                        rval_arg = rval.lower()
                    else:
                        if rval == '':
                            raise ValueError("empty regular expression for '{} {}'".format(fld, op))
                        try:
                            rval_arg = re.compile(rval, re.I)
                        except re.error as reerr:
                            raise ValueError("invalid regular expression ({}): {!r}".format(reerr, rval))

                    fname = self._new_test_name(fld, op, rval)
                    func = self._new_test_func(op, rval_arg)

                    accum += '{}({})'.format(fname, fld)
                    self._globals[fname] = func

                else:
                    accum += m.group(0).lower()
                pos = m.end()
                if pos == lfdef:
                    break
            else:
                fails += 1

            if fails == 2:
                break

            i += 1

        residue = fdef[pos:]
        if residue == '':
            return accum, used_fields
        else:
            raise ValueError('failed to parse from position {}: {!r}'.format(pos, residue))

    @classmethod
    def fields_dict(cls):
        return dict(cls._r_flds)

    def filter(self, row):
        _row = dict({f: v for f, v in
                     [(self._get_fldname(longname=lf, silent=True), v) for lf, v in row.items()] if f is not None})
        rset = set(_row)
        if not self._need_fields <= rset:
            raise ValueError("expected more field(s): " +
                             ', '.join(['{}({})'.format(self._flds[f], f) for f in self._need_fields - rset]))
        try:
            res = eval(self._code, self._globals, _row)
        except Exception as evalerr:
            raise ValueError('failed to eval filter expression: ' + str(evalerr))
        return res if self._match_mode else not res


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
    def __init__(self, msg, exitcode=1, logerror=True, fold_line=False):
        if fold_line:
            msg = re.sub(r'\s*\n', ' ', msg)
        self.msg, self.exitcode, self.logerror = msg, exitcode, logerror
        super().__init__(msg)


class MyCmdlineError(MyError):
    def __init__(self, msg=None):
        super().__init__(msg="Invalid command line{}\n".format(': '+msg if msg is not None else '')+MSG_USAGE.strip(),
                         logerror=False)


class MyUsageException(MyError):
    def __init__(self):
        flds = ResolverFilter.fields_dict()
        mlen = max([len(l) for l in flds])
        ftext = '\n'.join(('{:' + str(mlen+2) + '} | {}').format('[' + l + ']', flds[l]) for l in sorted(flds))
        fhdr = 'List of resolvers list fields (for use in filter): [native long name] | short_alias'
        super().__init__(msg='{}\n\n{}\n\n{}'.format(MSG_USAGE.strip(), fhdr, ftext), exitcode=0, logerror=False)


class MyConfigValueError(MyError):
    def __init__(self, msg, section, option, value, fold_line=True):
        super().__init__("Invalid value '{}' for [{}].{}: {}".format(value, section, option, msg), fold_line=fold_line)


class MyConfigUniqueError(MyError):
    def __init__(self, section, option, value, fold_line=True):
        super().__init__("Value '{}' for [{}].{} is not unique".format(value, section, option), fold_line=fold_line)


class MyConfigNotAllowedError(MyError):
    def __init__(self, msg, section, option, value=None, fold_line=True):
        super().__init__("[{}]: {}{} {}".format(section, option, '' if value is None else '='+str(value), msg),
                         fold_line=fold_line)


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

        self.only_check_config = False
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

                if tgt != 'console' and not self.only_check_config:
                    self.logger.debug('Switching logging to '+tgt)
                    oldhandlers = list(self.logger.handlers)
                    # noinspection PyUnboundLocalVariable
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
        lopts = {'help': ('h', False), 'verbose': ('v', False),
                 'config': ('f', True), 'check-config': ('c', False)}
        try:
            ov, left = gnu_getopt(_argv, ''.join([v[0] + (':' if v[1] else '') for k, v in lopts.items()]),
                                  [k + ('=' if v[1] else '') for k, v in lopts.items()])
        except GetoptError as geterr:
            raise MyCmdlineError(str(geterr))

        if left:
            raise MyCmdlineError('unexpected '+', '.join(["'"+a+"'" for a in left]))

        od = dict()
        for o, v in ov:
            o = o.lstrip('-')
            opt = lopts.get(o, None)
            if opt is None:
                opt, sopt = o, '-' + o
            else:
                opt, sopt = opt[0], '--' + o
            if opt in od:
                raise MyCmdlineError("recurring '{}'".format(sopt))
            od[opt] = v

        if 'h' in od:
            if len(od) > 1:
                raise MyCmdlineError()
            else:
                raise MyUsageException()
        if 'v' in od and 'c' in od:
            raise MyCmdlineError()
        if 'f' in od:
            f = od['f']
            if f == '' or f.startswith('-'):
                raise MyCmdlineError("seems '{}' is not valid config file".format(f))
        if 'c' in od and 'f' not in od:
            raise MyCmdlineError('no config file to check, consider -f|--config option')

        if 'v' in od:
            self.logger.setLevel(logging.DEBUG)
        if 'f' in od:
            self._config_file = od['f']
        if 'c' in od:
            self.only_check_config = True

    def _find_config_file(self):
        if self._config_file:
            locs = [self._config_file]
        else:
            locs = CONFIG_LOCATIONS

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

    def _check_resolver_list_fields(self, row, resolverfilter):
        r_s, f_s = set([f.lower() for f in row]), set(resolverfilter.fields_dict())
        if r_s != f_s:
            msg = 'seems resolvers list record format has been changed ' \
                  'and no longer matches internal representation:\n' \
                  '[+] fields: {}\n' \
                  '[-] fields: {}\n' \
                  'please file a bug to https://github.com/beelze/junta/issues'.format(', '.join(sorted(r_s - f_s)),
                                                                                       ', '.join(sorted(f_s - r_s)))
            self.logger.warning(msg)

    def _random_resolvers(self, cnt, file, resolverfilter):
        fmt = 'filter[{{}}]: {0[Name]} ({0[Full name]}) {0[Resolver address]}'
        resolvers, filtered, firstpass = set(), 0, True

        self.logger.debug('Trying to parse (csv) resolvers list from '+file)
        try:
            with open(file) as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if firstpass:
                        firstpass = False
                        self._check_resolver_list_fields(row, resolverfilter)
                    add = True
                    if resolverfilter:
                        msg = fmt.format(row)
                        if resolverfilter.filter(row):
                            msg = msg.format('+')
                        else:
                            add = False
                            filtered += 1
                            msg = msg.format('-')
                        self.logger.debug(msg)

                    if add:
                        resolvers.add(row['Name'])
        except Exception as e:
            raise MyError('Error reading/filtering resolvers list: '+str(e))

        lr = len(resolvers)
        if resolverfilter:
            self.logger.debug("{} suitable resolvers found, {} filtered out".format(lr, filtered))
        else:
            self.logger.debug("{} resolvers found".format(lr))

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
                        klass.nrandom, ', '.join(instance_sections)))

            if not klass.resolverslist or not klass.localaddress:
                raise MyError('[common].ResolversList/LocalAddress are mandatory in random mode')
            for resolver in self._random_resolvers(klass.nrandom, klass.resolverslist, klass.filter):
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
                    self.logger.debug('Sending SIGTERM to ' + i.instance_name)
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
                                    set(INSTANCE_OPTS) - {'filter', 'nrandom'}]
                                    if v is not None]))
        # noinspection PyTypeChecker
        app.init_instances(Instance)

        if app.only_check_config:
            app.logger.debug('Seems config is valid, exiting')
            sys.exit(0)

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
