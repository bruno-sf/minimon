#!/usr/bin/env python3
# -*- coding: utf-8 -*-
__AUTHOR__ = 'Bruno Ferreira'
__VERSION__ = 6
'''
Name: minimon.py
Author: Bruno Fereira / https://github.com/bruno-sf
Released at: Jan 2019
Purpose: Check if a service/host is up (green), down(red) and shows when status changes(yellow).
License: This project is licensed under the MIT License - see the LICENSE.md file for details.
'''

try:
    import os
    import time
    import socket as skt
    import argparse as ap
    from contextlib import closing
    from urllib import request as rq
    from urllib.error import HTTPError, URLError

except ImportError as e_msg:
    raise SystemExit(e_msg)

class MinimonExp(Exception):
    '''MinimonExp Class - To proper handle internal exceptions, message and exit.'''
    def __init__(self, message):
        super().__init__(message)
        print(style('RED'), style('BOLD'), f'[ERROR]: ', style(), f'{message}', sep='')
        raise SystemExit(255)

class Service():
    '''Service class - Is the Main class. Set the basics to monitor the services.

    Attributes:
        idx: The index of service in the list/dict;
        name: The name of the service being monitored. ex.: My router;
        addr: The address of the service ex.: www.test.com or 192.168.1.100;
        prot: The protocol used to monitor. ex.: HTTP, HTTPS, ICMP or TCP ports;
    '''

    __slots__ = ('idx', 'name', 'addr', 'prot', '_status', '_last_status', '_timeout')

    def __init__(self, idx, name, addr, prot):
        '''Construct the Service class and set the attribs.'''

        self.idx, self.name, self.addr, self.prot = idx, name, addr, prot
        self._status: bool = False
        self._last_status: bool = False
        self._timeout: int = 5

    def __repr__(self):
        '''Method to return a brief description of this class.'''

        return f'Host/Service {self.name} : {self.addr} : {self.prot}'

    def chk_icmp(self):
        '''Method chk_icmp() - Checks ICMP response.

        Use the own system ping tool to determine if a host is alive.'''

        try:
            _cmd_win = f'ping -n 1 -w {self._timeout*1000} {self.addr} > {os.devnull}'
            _cmd_nix = f'ping -q -c 1 -W {self._timeout} {self.addr} > {os.devnull}'
            _cmd_mac = f'ping -q -c 1 {self.addr} > {os.devnull}'
            _cmd_unkwon = _cmd_nix
            _os_name = os.name.lower()
            _os_type = {'nix': ['posix', 'linux', 'java'],
                        'win': ['nt', 'win32', 'win', 'windows'],
                        'mac': ['darwin', 'ce']}

            if _os_name in _os_type['nix']:
                _ret = os.system(_cmd_nix)

            elif _os_name in _os_type['win']:
                _ret = os.system(_cmd_win)

            elif _os_name in _os_type['mac']:
                _ret = os.system(_cmd_mac)

            else:
                # Will use nix cmds
                _ret = os.system(_cmd_unkwon)

        except OSError:
            raise MinimonExp("Can't determine your OS.")

        else:
            if _ret == 0:
                return self._online()
            return self._offline()

    def chk_sock(self):
        '''Method chk_sock() - Generic method for port checking with sockets.'''

        try:
            with closing(skt.socket(skt.AF_INET, skt.SOCK_STREAM)) as _skt:
                _skt.settimeout(self._timeout)
                conn = _skt.connect_ex((self.addr, int(self.prot)))
                _skt.close()

        except skt.error:
            return self._offline()

        else:
            if conn == 0:
                return self._online()

            return self._offline()

    def chk_web(self):
        '''Method chk_web() - Web checking HTTP/HTTPS Urls.

        Do basic requests for checking web service availability.'''

        try:
            _url = f'{self.prot}://{self.addr}'
            _ret_code = rq.urlopen(_url, None, timeout=self._timeout).getcode()

        except (HTTPError, URLError):
            # Warning: Python compiled without ssl will enter here on any https request.
            return self._offline()

        else:
            if 200 >= _ret_code <= 299:
                return self._online()
            return self._offline()

    def chk_srv(self) -> bool:
        '''Method chk_srv() - Call the designated protocol function.'''

        try:
            _protocol = self.prot.lower()

            if _protocol in ['http', 'https']:
                self.chk_web()

            elif _protocol == 'icmp':
                self.chk_icmp()

            elif int(_protocol) >= 1 or int(_protocol) <= 65535:
                self.chk_sock()

            else:
                raise ValueError

        except ValueError:
            raise MinimonExp(f'''Invalid protocol "{_protocol}". Please, use
                             http https, icmp or a valid tcp port (1-65535) 
                             as argument.''')

        else:
            return True

    def _online(self):
        '''Internal Method online() - Set the status attribute to True.'''

        self._last_status = self._status
        self._status = True

    def _offline(self):
        '''Internal  Method offline() - Set the status attribute to False.'''

        self._last_status = self._status
        self._status = False

    @property
    def timeout(self) -> int:
        '''Property timeout() - Set the global timeout for checks.'''

        return self._timeout

    @timeout.setter
    def timeout(self, seconds):
        '''Property timeout() - Set the timeout using property decorator.'''

        self._timeout = seconds

    @property
    def status(self) -> bool:
        '''Property status() - Set the status property.'''

        return self._status

    @property
    def last_status(self) -> bool:
        '''Property status() - Set the last_status property.'''

        return self._last_status


def ascii_fmt(code: int) -> str:
    '''ascii_fmt() - Returns the ascii formated string'''

    return f'\033[{code}m'

def args_to_service():
    '''args_to_service() - Returns the list_services, count, interval and timeout.'''

    try:
        _args = parse_args()
        _cnt, _itv, _tmt = _args['count'], _args['interval'], _args['timeout']

        if _args['mode'] == 'hosts_file':
            list_services = parse_hosts_file(_args['hostsfile'])

        else:
            list_services = parse_hosts_args(_args)

    except RuntimeError as e_msg:
        raise MinimonExp(e_msg)

    else:
        return list_services, _cnt, _itv, _tmt

def counting():
    '''counting() - Generator function counting().'''

    count = 1
    while True:
        yield count
        count += 1

def hostsfile_exist(file: str) -> bool:
    '''hostsfile_exist() - Make sure the hosts file exists.'''

    try:
        return bool(os.path.isfile(file))

    except OSError:
        raise MinimonExp(f'Please check hostsfile provided: {file}')


def instance_service(_list_srvs: list) -> list:
    '''instance_service() - Do a list with instances of Service Class.

    Get the values needed to instance the Service Class.
    Each host/service inside the list provided will be append to a final list.'''
    _ret_list: list = []
    _idx: int = 1
    try:
        for host in _list_srvs:
            host_val = host.split(':')
            name = host_val[0]
            addr = host_val[1]
            prot = host_val[2].rstrip('\n')
            _ret_list.append(Service(_idx, name, addr, prot))
            _idx += 1

    except EOFError as e_msg:
        raise MinimonExp(e_msg)

    return _ret_list


def loop_services(services, count, interval, timeout):
    '''loop_services() - Loop through each service, and check the service'''

    turn = counting()
    _turn = next(turn, count)

    while True:
        for service in services:
            service.timeout = timeout
            if _turn == 1:
                if service.chk_srv():
                    print_status(service, True)

            elif service.chk_srv():
                print_status(service)

        if count != 0:
            if _turn == count:
                _msg = f'Your count ({count}) is over. Tchau!'
                print(style('YELLOW'), style('BOLD'), _msg, sep='')
                break

        _turn = next(turn, count)
        time.sleep(interval)

def parse_args() -> dict:
    '''parse_args - Check and parse args, and finally atribute vals'''

    parser = ap.ArgumentParser(description='Usage: minimon.py -i 5 -t 5 -c 10 8.8.8.8')

    parser.add_argument('-i', '--interval', type=int, action='store',
                        dest='interval', default=5,
                        help='''The interval in seconds minimon will
                            make another check. Default: 5.''')

    parser.add_argument('-t', '--timeout', type=int, action='store',
                        dest='timeout', default=5,
                        help='''Set a global timeout in seconds for
                        each check. Default: 5 (1-30).''')

    parser.add_argument('-c', '--count', type=int, action='store',
                        dest='count', default=0,
                        help='''How many checks minimon will do.
                        Default: 0 (infinite loop).''')

    my_exc_grp = parser.add_mutually_exclusive_group()

    my_exc_grp.add_argument('-f', '--hostsfile', type=str, action='store',
                            dest='hostsfile', default='minimon.txt',
                            help='''The hosts file should content:
                            NAME:ADDRESS:PROTOCOL line by line.
                            Default: minimon.txt''')

    my_exc_grp.add_argument('-p', '--protocol', type=str, action='store',
                            dest='protocol', default='icmp',
                            help='''Use -p only if you are not using hostsfile
                            Protocols avaiable: http, https, icmp, or tcp port
                            (1-65535). Default: icmp''')

    parser.add_argument('--version', action='version', version=f'''%(prog)s
                        Version: {__VERSION__} - Author: {__AUTHOR__}''')

    parser.add_argument('pos_arg', default=None, metavar='Target(s)',
                        type=str, nargs='*',
                        help='''If you pass a target host(s) as a positional
                        arg the hostsfile will be ignored. Ex: minimon.py
                        -p https www.lpi.org webserver.intranet 8.8.8.8''')

    args = parser.parse_args()

    try:
        assert args.count >= 0 and args.count <= 99999
        assert args.interval >= 1 and args.interval <= 3600
        assert args.timeout >= 1 and args.timeout <= 30

        if args.protocol.lower() not in ['http', 'https', 'icmp']:
            if int(args.protocol) < 1 or int(args.protocol) > 65535:
                raise ValueError

    except ValueError:
        raise MinimonExp(f'Invalid protocol {args.protocol}.'+
                         '''\nPlease use http, https, icmp or a valid tcp port (1-65535) as argument.''')

    except AssertionError:
        raise MinimonExp('''Please, use values in allowed range: count(0-99999), interval(1-3600) and timeout (1-30).''')

    if args.pos_arg:
        args_attr = {'mode': 'pos_arg', 'interval': args.interval,
                     'hostsarg': args.pos_arg, 'count': args.count,
                     'timeout': args.timeout, 'protocol': args.protocol}

    else:
        if hostsfile_exist(args.hostsfile):
            args_attr = {'mode': 'hosts_file', 'hostsfile': args.hostsfile,
                         'interval': args.interval, 'count': args.count,
                         'timeout': args.timeout}
        else:
            raise MinimonExp(f'Can\'t find hosts file: {args.hostsfile}.')

    return args_attr

def parse_hosts_args(ret_args: dict) -> list:
    '''parse_hosts_args() - Parse hosts passed by arguments in CLI

    returns a list like: ['Target[1]:8.8.8.8:icmp\n', 'Target[2]:1.1.1.1:icmp\n']'''

    _idx = 1
    _list_hosts = list()

    for host in ret_args['hostsarg']:
        _list_hosts.append(f'Target[{_idx}]:{host}:{ret_args["protocol"]}')
        _idx += 1
    return _list_hosts

def parse_hosts_file(file: str) -> list:
    '''parse_hosts_file() - Parses the content of hostsfile
    (-f argument or default with no hosts provided ./minimon.py).

    returns a list like: ['Teste 123 :8.8.8.8:icmp\n', 'Host 2:1.1.1.1:http\n']'''

    _list_hosts = []
    try:
        with open(file, 'rt') as in_file:
            for line in in_file:
                _list_hosts.append(line)

    except FileNotFoundError:
        raise MinimonExp(f'Can\'t find the hosts file provided: {file}')

    except PermissionError:
        raise MinimonExp(f'No permissions to read the file: {file}')

    return _list_hosts

def print_banner():
    '''print_banner() - Prints the main banner.'''

    _banner = f'''
     __  __ _       _
    |  \/  (_)     (_)
    | \  / |_ _ __  _ _ __ ___   ___  _ __  
    | |\/| | | '_ \| | '_ ` _ \ / _ \| '_ \ 
    | |  | | | | | | | | | | | | (_) | | | |
    |_|  |_|_|_| |_|_|_| |_| |_|\___/|_| |_|
    
        Version: {__VERSION__} - Author: {__AUTHOR__}
    '''

    return  print(style('YELLOW'), _banner, style(), sep='')

def print_header():
    '''print_header() - prints the header accordly with the chosen mode. '''

    _hdr = f'[ STATUS ] - [ TIME ] - [ ADDRESS ]'
    return print(style('WHITE'), style('BOLD'), _hdr, style(), sep='')

def print_status(_service: Service, first_run: bool = False):
    '''print_status() - Print each service status.'''

    _utf8_balls = {
                'GREEN': '\U0001F7E2',
                'YELLOW': '\U0001F7E1',
                'RED': '\U0001F534'
    }
    _current_time = time.localtime()
    _fmt_time = time.strftime('%H:%M:%S', _current_time)

    def _status(_condition: str) -> str:
        return f"{_utf8_balls[_condition]:>5}"+ f"{' - ' :>7}" + f"{_fmt_time} - {_service.addr}"

    ONLINE = _status('GREEN')
    OFFLINE = _status('RED')
    FLOP = _status('YELLOW')

    if first_run:
        _ret_msg = f"{ONLINE if _service.status else OFFLINE}"

    elif _service.status and _service.last_status:
        _ret_msg = f"{ONLINE}"

    elif _service.last_status != _service.status:
        _ret_msg = f"{FLOP}"
    else:
        _ret_msg = f"{OFFLINE}"

    return print(_ret_msg)

def style(name='RESET'):
    '''style() - Defines the ascii style.'''

    ASCII_COLORS = {'RESET': 0, 'RED': 31, 'GREEN': 32,
                    'YELLOW': 33, 'BLUE': 34, 'MAGENTA': 35, 'WHITE': 37}
    ASCII_FX = {'RESET': 0, 'BOLD': 1, 'UNDERLINE': 4, 'BLINK': 5}

    if name in ASCII_COLORS:
        code = ASCII_COLORS[name]
        ret_style = ascii_fmt(code)

    elif name in ASCII_FX:
        code = ASCII_FX[name]
        ret_style = ascii_fmt(code)
    else:
        ret_style = ascii_fmt(0)

    return ret_style

def main():
    '''main() - The main function.

    Parse the values from list list_services and create a dict of objects
    from Service class, after that, check and report services one by one.'''

    try:
        args_parsed, count, interval, timeout = args_to_service()
        services = instance_service(args_parsed)
        print_banner()
        print_header()
        loop_services(services, count, interval, timeout)

    except KeyError as e_msg:
        raise MinimonExp(e_msg)

    except (KeyboardInterrupt, EOFError):
        _msg = f'\nOuch! That\'s an interruption...'
        print(style('YELLOW'), style('BOLD'), _msg, sep='')
        raise SystemExit(130)

    else:
        SystemExit(0)

if __name__ == '__main__':
    main()
