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

MINVER = (3, 3)
DAEMON = 'dnscrypt-proxy'
MYNAME = 'dnscrypt-proxies'
DEFAULT_LOGFILE = '/var/log/dnscrypt-proxy/'+MYNAME+'.log'
DEFAULT_CONFIG_INSTANCE = '/etc/dnscrypt-proxy/${name}.conf'
DEFAULT_LOGFILE_INSTANCE = '/var/log/dnscrypt-proxy/${name}.log'
LOGFILE_INSTANCE_MODE = 0o640
CONFIG_LOCATIONS = ['/etc/'+MYNAME+'.conf', str(Path(__file__).parent / (MYNAME+'.conf'))]
CONFIG_BOOLEANS = {'yes': True, 'true': True, 'on': True, 'no': False, 'false': False, 'off': False}
CONFIG_MODES = ('config', 'list', 'manual', 'random')
INSTANCE_OPTS = ('mode', 'nrandom', 'blocklist', 'config', 'logfile', 'loglevel', 'localaddress',
                 'resolverslist', 'providerkey', 'resolveraddress',
                 'ephemeralkeys', 'tcponly', 'maxactiverequests', 'ednspayloadsize', 'user')

RE_IP4PORT = re.compile(r'([0-9.]+):([\d]+)')
RE_IP6PORT = re.compile(r'\[([0-9A-F:]+)\]:([\d]+)', re.I)
PROCESS_POLL_TIMEOUT = 0.5

ERR_NOTBOOLEAN = 'not a boolean'
ERR_UNEXPECTEDOPTS = "unexpected options in [{}]: {}"
ERR_CMDLINE = "Invalid command line: {}\navailable options: -v (verbose), -f file (config file)"
MSG_USAGE = """
options: -h (help)
         -v (verbose)
         -f config_file"""
ERR_CONFFILE = 'Failed to find config file'
ERR_NOTFILE = 'file not exists/not a file'

if sys.hexversion < (MINVER[0] * 0x100 + MINVER[1]) * 0x10000:
    print("We need at least python {0[0]}.{0[1]}".format(MINVER), file=sys.stderr)
    sys.exit(1)


def _format_address(addr_tuple):
    ip, port = addr_tuple
    str_ip = str(ip)
    if isinstance(ip, ipaddress.IPv6Address):
        str_ip = '[' + str_ip + ']'
    if port:
        str_ip += ':' + str(port)
    return str_ip


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
        m = RE_IP4PORT.fullmatch(value) or RE_IP6PORT.fullmatch(value)
        try:
            if m:
                g = m.groups()
                return True, (ipaddress.ip_address(g[0]), int(g[1]))
            else:
                v = ipaddress.ip_address(value)
                return True, (v, None)
        except ValueError:
            return False, 'not a valid ip[:port]'

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
    return True


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

        super().__init__(name=MYNAME+':'+self.instance_name, daemon=False)

    def _allocate_ip(self):
        n = self.__class__.nextip
        if n:
            self.__class__.nextip = (self.__class__.nextip[0] + 1, self.__class__.nextip[1])
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
            raise MyConfigUniqueError(self.instance_name, 'localaddress', _format_address(self.localaddress))

    def _correct_logfile_permissions(self):
        if self.user is not None and self.user != 'root' and self._instance_logfile is not None:
            try:
                p = Path(self._instance_logfile)
                if not p.exists():
                    self.logger.info("Creating " + str(p))
                    p.touch(mode=LOGFILE_INSTANCE_MODE)

                if p.owner() != self.user:
                    self.logger.info("Correcting user for "+str(p))
                    chown(str(p), self.user)
                mode = p.stat().st_mode
                if not stat.S_ISREG(mode):
                    raise PermissionError("Not a regular file")
                mode = stat.S_IMODE(mode)
                if mode & LOGFILE_INSTANCE_MODE != LOGFILE_INSTANCE_MODE:
                    self.logger.info("Correcting mode for "+str(p))
                    p.chmod(LOGFILE_INSTANCE_MODE)
            except (OSError, PermissionError) as e:
                self.logger.error("Failed to create or access/set logfile permissions: {}".format(e))
                return False
        return True

    def info(self):
        txt = "{} mode".format(self.mode)
        if self.mode != 'config':
            txt += ", local {}".format(_format_address(self.localaddress))
        if self.mode == 'manual':
            txt += ", remote {}".format(_format_address(self.resolveraddress))
        return txt

    def is_process_alive(self):
        return self.process is not None and self.process.returncode is None

    # noinspection PyMethodOverriding
    def start(self, binary, logger):
        self.binary, self.logger = binary, logger
        super().start()

    def run(self):
        args = [self.binary] + self.cmdline_args()
        if self._correct_logfile_permissions():
            self.logger.debug("Starting '{}'".format(' '.join(args)))
            try:
                self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                                bufsize=1, universal_newlines=True)
                self.logger.info("Started <{}>".format(self.process.pid))
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
            args = ['-N', self.instance_name, '-k', self.providerkey, '-r', _format_address(self.resolveraddress)]

        args += ['-a', _format_address(self.localaddress)]
        logfile = self.logfile or ''
        if logfile.lower() != 'none':
            if logfile.lower() == 'syslog':
                args += ['-S', '-Z', '[{}]'.format(self.instance_name)]
            else:
                if logfile == '':
                    logfile = _template_subst(DEFAULT_LOGFILE_INSTANCE, name=self.instance_name)
                args += ['-l', logfile]
                self._instance_logfile = logfile
            if self.loglevel is not None:
                args += ['-m', self.loglevel]
        if self.user is not None:
            args += ['-u', self.user]
        return args


class MyFilter(logging.Filter):
    def __init__(self, exclusive_maximum, name=""):
        super().__init__(name)
        self.max_level = exclusive_maximum

    def filter(self, record):
        # non-zero return means we log this message
        return 1 if record.levelno < self.max_level else 0


class MyLogger(logging.Logger):
    def _log(self, level, msg, args, exc_info=None, extra=None, stack_info=False):
        for line in str(msg).split('\n'):
            super()._log(level, line, args, exc_info=None, extra=None, stack_info=False)


class App:
    def __init__(self, argv):
        threading.main_thread().name = MYNAME
        self._argv = argv
        self._break = False
        self._ss_lock = threading.Lock()

        self._file_formatter = logging.Formatter(fmt='${asctime} [${threadName}] ${levelname}:${lineno} ${message}',
                                                 datefmt='%Y-%m-%d %H:%M:%S', style='$')
        self._syslog_formatter = logging.Formatter(fmt='${threadName} ${levelname}:${lineno} ${message}', style='$')
        self.logger = logging.getLogger('main')
        log_hnd_out = logging.StreamHandler(sys.stdout)
        log_hnd_out.setLevel(logging.DEBUG)
        log_hnd_out.addFilter(MyFilter(logging.WARNING))
        log_hnd_out.setFormatter(self._file_formatter)
        self.logger.addHandler(log_hnd_out)

        log_hnd_err = logging.StreamHandler(sys.stderr)
        log_hnd_err.setLevel(logging.WARNING)
        log_hnd_err.setFormatter(self._file_formatter)
        self.logger.addHandler(log_hnd_err)

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
                else:
                    tgt = log
                    hnd = logging.handlers.WatchedFileHandler(log)
                    hnd.setFormatter(self._file_formatter)

                self.logger.debug('Switching logging to '+tgt)
                oldhandlers = list(self.logger.handlers)
                self.logger.addHandler(hnd)
                for h in oldhandlers:
                    self.logger.removeHandler(h)

            except FileNotFoundError as e:
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

    def _parse_cmdline(self, _argv):
        argv = list(_argv)

        # noinspection PyPep8,PyShadowingNames
        def _eat_option(option):
            found, first, last, left, idx = False, None, None, None, None
            try:
                idx = argv.index(option)
            except ValueError:
                pass
            if idx is not None:
                found, first, last, left = True, idx==0, idx==len(argv)-1, len(argv)-1
                del argv[idx]
            return found, first, last, left

        found, first, last, left = _eat_option('-h')
        if found:
            if not left:
                raise MyUsageException()
            else:
                raise MyCmdlineError()

        found, first, last, left = _eat_option('-v')
        if found:
            if first or last:
                self.logger.setLevel(logging.DEBUG)
            else:
                raise MyCmdlineError()

        found, first, last, left = _eat_option('-f')
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
        self.logger.debug('Trying to parse (csv) resolvers list '+file)
        try:
            with open(file) as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if not in_blocklist(row):
                        resolvers.add(row['Name'])
                    else:
                        filtered += 1
        except Exception as e:
            raise configparser.Error('Error when parsing resolverslist: '+str(e))

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
            config = {'mode': 'list'}
            for resolver in self._random_resolvers(klass.nrandom, klass.resolverslist, klass.blocklist):
                self.instances[resolver] = klass(config, resolver)

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
            print('Signal caught too early')

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGALRM, signal_handler)

    try:
        app = App(sys.argv[1:])
        app.initialize()

        class Instance(InstanceBase, metaclass=MetaInstance, config=app.config, section='common'):
            pass

        app.logger.debug('Default instance configured')
        # noinspection PyTypeChecker
        app.init_instances(Instance)
        app.rearm_timer(30)
        app.run_instances()
        app.logger.info('Clean exit')
        sys.exit(0)

    except MyError as myerr:
        if myerr.logerror:
            app.logger.error(myerr.msg)
        else:
            print(myerr.msg)
        sys.exit(myerr.exitcode)

