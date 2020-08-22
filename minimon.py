#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Name: minimon.py
Author: Bruno Fereira / https://github.com/bruno-sf
Released at: Jan 2019
Purpose: Check if a service/host is up (green), down(red) and shows when status changes(yellow).
License: This project is licensed under the MIT License - see the LICENSE.md file for details.
"""
VERSION = 3
DATE = "Ago 2020"
AUTHOR = "Bruno Ferreira"

try:
    import os
    import time
    import socket
    import argparse
    from contextlib import closing
    from urllib import request
    from urllib.error import HTTPError, URLError

except ImportError as e_msg:
    print(e_msg)
    exit(2)


class Service():
    """Service class - Is the Main class. Set the basics to monitor the services.

    Attributes:
        idx: The index of service in the list/dict
        name: The name of the service being monitored. ex.: My router
        addr: The address of the service. ex.: www.test.com or 192.168.1.100
        prot: The protocol used to monitor. ex.: HTTP, HTTPS, ICMP, All TCP pts
        status: The status of the service. ex.: ONLINE, OFFLINE...
    """

    PROTOCOLS = ("http", "https", "icmp")
    __slots__ = ('idx', 'name', 'addr', 'prot',
                 'status', 'last_status', '_timeout')

    def __init__(self, idx, name, addr, prot):
        """Construct the Service class and set the attribs."""
        self.idx, self.name, self.addr, self.prot = idx, name, addr, prot
        self.status, self.last_status, self._timeout = "", "", 5

    def __repr__(self):
        """Method to return a brief description of this class."""
        return "Host/Service {name} : {addr} : {prot}".format(name=self.name,
                                                              addr=self.addr, prot=self.prot)

    def chk_web(self):
        """Method chk_web() - Web checking HTTP/HTTPS.

        Do basic requests for checking web service availability."""

        try:
            _url = "{prot}://{addr}".format(prot=self.prot, addr=self.addr)
            _ret_code = request.urlopen(
                _url, None, timeout=self.timeout).getcode()

        except (HTTPError, URLError):
            # Warning: Python compiled without ssl will enter here on any https requests.
            return self.offline()

        else:
            success = lambda http_st: http_st >= 200 and http_st <= 299
            if success(_ret_code):
                return self.online()
            return self.offline()

    def chk_icmp(self):
        """Method chk_icmp() - Checks ICMP response.

        Use the own system ping tool to determine if a host is alive."""

        try:
            _cmd_win = "ping -n 1 -w {timeout} {addr} > {devnull}"\
                .format(timeout=self.timeout*1000, addr=self.addr, devnull=os.devnull)
            _cmd_nix = "ping -q -c 1 -W {timeout} {addr} > {devnull} 2>&1".format(
                timeout=self.timeout, addr=self.addr, devnull=os.devnull)
            _cmd_mac = "ping -q -c 1 {addr} > {devnull}".format(
                addr=self.addr, devnull=os.devnull)
            _cmd_unkwon = _cmd_nix
            _os_name = os.name.lower()
            _os_type = {"nix": ["posix", "linux", "java"],
                        "win": ["nt", "win32", "win", "windows"],
                        "mac": ["darwin", "ce"]}

            if _os_name in _os_type["nix"]:
                _ret = os.system(_cmd_nix)

            elif _os_name in _os_type["win"]:
                _ret = os.system(_cmd_win)

            elif _os_name in _os_type["mac"]:
                _ret = os.system(_cmd_mac)

            else:
                _ret = os.system(_cmd_unkwon)

        except OSError as e_msg:
            #[ERROR]: Can't determine your OS.
            return e_msg

        except BaseException as e_msg:
            return e_msg

        else:
            if _ret == 0:
                return self.online()
            return self.offline()

    def chk_sock(self, _prt):
        """Method chk_sock() - Generic method for port checking with sockets."""

        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as _sock:
                _sock.settimeout(self.timeout)
                conn = _sock.connect_ex((self.addr, _prt))

        except socket.error:
            print("Socket Error!")
            return 1

        else:
            if conn == 0:
                return self.online()
            return self.offline()

    def chk_srv(self):
        """Method chk_srv() - The core Method.

        Do the basic checks and call the designated protocol function."""
        try:
            _protocol = self.prot.lower()
            #in_range = filter(lambda x: int(x), list(range(1, 65536)))

            if _protocol in self.PROTOCOLS:
                if _protocol in ["http", "https"]:
                    self.chk_web()

                if _protocol == "icmp":
                    self.chk_icmp()

            #elif int(_protocol) in in_range:
            elif int(_protocol) in list(range(1, 65536)):
                self.chk_sock(int(_protocol))

        except ValueError:
            return fail_exit(
                "Invalid protocol: {}. Please, use http, https, icmp or a valid tcp port (1-65535) as argument.".format(_protocol))

        except BaseException as e_msg:
            return fail_exit(e_msg)

        else:
            return 0

    def online(self):
        """Method online() - Set the status attribute to "ONLINE "."""

        self.last_status = self.status
        self.status = "ONLINE "

    def offline(self):
        """Method offline() - Set the status attribute to "OFFLINE" ."""

        self.last_status = self.status
        self.status = "OFFLINE"

    @property
    def timeout(self):
        """Property timeout() - Set the global timeout for checks."""

        return self._timeout

    @timeout.setter
    def timeout(self, seconds):
        """Property timeout() - Set the timeout using property decorator ;)."""

        self._timeout = seconds


class Counter():
    """Class to handle counting ops"""

    def __init__(self, final_count, count=1, initial=1):
        """Construct the Counter class"""

        self.initial = initial
        self.count = count
        self.final_count = final_count

    def __repr__(self):
        """Method to return a brief description of this class."""

        return "Class to handle counting. Initial:{} - Current:{} - Final:{}".format(self.initial, self.count, self.final_count)

    def finish(self):
        """Method finish - Make sure to exit when the count is over.

        If using the argument "-c or --count" and the count is over!"""

        _msg = "Your count ({}) is over. Tchau!".format(self.final_count)
        print_std("HEADER", _msg)

    def add_one(self):
        """Method add_one - Add one for variable count."""

        self.count += 1
        return 0


def fail_exit(_msg):
    """Funtion fail_exit() - Called if things goes wrong and show custom msg."""

    _msg = "[ERROR]: {} - Sorry about that, exiting...".format(_msg)
    print_std("DOWN", _msg)
    exit(4)


def print_std(_type, _msg):
    """ Function print_std() - Standard print with color / type of message."""

    COLORS = {"UP": '\033[92m', "DOWN": '\033[91m', "NORMAL": '\033[0m',
              "HEADER": '\033[95m', "ALERT": '\033[93m'}
    if _type.upper() in COLORS:
        print(COLORS[_type]+_msg+COLORS["NORMAL"])
    else:
        print(_msg)


def print_header():
    """Function print_header() - print the header to help visualize the values """

    _header_str = "[STATUS ] : (TURN:ID) - TIME - [PROT] - NAME - ADDRESS"
    print_std("HEADER", _header_str)


def print_status(_service, turns):
    """Function print_status() - Print the service status."""

    COLORS = {"UP": '\033[92m', "DOWN": '\033[91m',
              "NORMAL": '\033[0m', "HEADER": '\033[95m', "ALERT": '\033[93m'}
    _cstatus = {
        "ONLINE ": COLORS["UP"]+_service.status+COLORS["NORMAL"],
        "OFFLINE": COLORS["DOWN"]+_service.status+COLORS["NORMAL"],
        "ALERT": COLORS["ALERT"]+_service.status+COLORS["NORMAL"]
    }

    _current_time = time.localtime()
    _f_time = time.strftime('%H:%M:%S', _current_time)
    _status_msg = "[{status}] : ({cnt}:{idx}) - {time} - [{prot}] - {name} - {addr}".format(name=_service.name, addr=_service.addr,
                                                                                            prot=_service.prot.upper(), status=_cstatus[_service.status], time=_f_time, idx=_service.idx, cnt=turns.count)

    _alert_msg = "[{status}] : ({cnt}:{idx}) - {time} - [{prot}] - {name} - {addr}".format(name=_service.name, addr=_service.addr,
                                                                                           prot=_service.prot.upper(), status=_cstatus["ALERT"], time=_f_time, idx=_service.idx, cnt=turns.count)

    if _service.last_status:
        if _service.last_status == _service.status:
            print(_status_msg)
        else:
            print(_alert_msg)
    else:
        print(_status_msg)


def print_banner():
    """Function print_banner() - print the banner with Version and Author."""
    _banner = """
     __  __ _       _
    |  \/  (_)     (_)
    | \  / |_ _ __  _ _ __ ___   ___  _ __  
    | |\/| | | '_ \| | '_ ` _ \ / _ \| '_ \ 
    | |  | | | | | | | | | | | | (_) | | | |
    |_|  |_|_|_| |_|_|_| |_| |_|\___/|_| |_|
    """
    print("")
    print_std("ALERT", _banner)
    print_std("ALERT", "    Version: {ver} {date} - Author: {author}"
              .format(ver=VERSION, date=DATE, author=AUTHOR))
    print("")


def hostsfile_exist(file):
    """Function hostsfile_exist() - Make sure the hosts file exists.

    Can be "minimon.txt" or the defined file on "-f or --hostsfile" args.
    """
    try:
        exists = os.path.isfile(file)

    except BaseException as e_msg:
        fail_exit(e_msg)

    else:
        if exists:
            return True

        return False


def parse_hostsfile(file) -> list:
    """Function parse_hostsfile() - Simple function to parse the content of hostsfile.

    return a list like: ['Teste 123 :8.8.8.8:icmp\n', 'Host 2:1.1.1.1:http\n']
    """
    _list_hosts = []
    try:
        with open(file, 'rt') as in_file:
            for line in in_file:
                _list_hosts.append(line)

    except FileNotFoundError:
        fail_exit("Can't find the hosts file provided:{}".format(file))

    except PermissionError:
        fail_exit("No permission to read file provided:{}".format(file))

    except BaseException as e_msg:
        fail_exit(e_msg)

    else:
        return _list_hosts


def parse_hostsargs(ret_args) -> list:
    """Function parse_hostsargs() - Parse hosts passed by arguments in CLI

    return a list like: ['Target[1]:8.8.8.8:icmp\n', 'Target[2]:1.1.1.1:icmp\n']"""
    _idx = 1
    _list_hosts = list()
    for host in ret_args["hostsarg"]:
        _list_hosts.append("Target[{_idx}]:{addr}:{prot}".format(
            _idx=_idx, addr=host, prot=ret_args["protocol"]))
        _idx += 1
    return _list_hosts


def parse_args() -> dict:
    """Function parse_args - Check and parse args, and finally atribute vals"""

    parser = argparse.ArgumentParser(description="""Usage: minimon.py -i 5 -t 5 -c 10 8.8.8.8""")

    parser.add_argument("-i", "--interval", type=int, action="store",
                        dest="interval", default=10, help="The interval in seconds minimon will make another check. Default: 10 seconds (1-3600)")

    parser.add_argument("-t", "--timeout", type=int, action="store",
                        dest="timeout", default=5, help="Set a global timeout in seconds for checks. Default: 5 (1-30).")

    parser.add_argument("-c", "--count", type=int, action="store",
                        dest="count", default=0, help="How many checks minimon will do. Default: 0 (infinite loop) - (0-99999).")

    my_exc_grp = parser.add_mutually_exclusive_group()

    my_exc_grp.add_argument("-f", "--hostsfile", type=str, action="store",
                            dest="hostsfile", default="minimon.txt", help="The hosts file should content: NAME:ADDRESS:PROTOCOL line by line. Default: minimon.txt")

    my_exc_grp.add_argument("-p", "--protocol", type=str, action="store",
                            dest="protocol", default="icmp", help="Use only if not using hostsfile. Default=icmp")

    parser.add_argument(
        '--version', action='version', version='%(prog)s - Minimon - Version: {ver} - {date} - Author: {author}'.format(ver=VERSION, date=DATE, author=AUTHOR))

    parser.add_argument('pos_arg', default=None, metavar="Target(s)", type=str, nargs='*',
                        help="If you pass a target host(s) as a positional arg the hostsfile will be ignored. Ex: minimon.py -p https www.lpi.org webserver.intranet 8.8.8.8")

    args = parser.parse_args()

    if args.interval < 1 or args.interval > 3600:
        fail_exit("Invalid interval value, use something between 1-3600 seconds.")

    if args.count < 0 or args.count > 99999:
        fail_exit("Invalid count value, use something between 0-99999")

    if args.timeout < 1 or args.timeout > 30:
        fail_exit("Invalid timeout value, use an interval between 1-30 seconds.")

    if args.pos_arg:
        args_attr = {"mode": "pos_arg", "interval": args.interval,
                     "hostsarg": args.pos_arg, "count": args.count, "timeout": args.timeout,
                     "protocol": args.protocol}

    else:
        if hostsfile_exist(args.hostsfile):
            args_attr = {"mode": "hosts_file", "hostsfile": args.hostsfile,
                         "interval": args.interval, "count": args.count,
                         "timeout": args.timeout}
        else:
            print_std("ALERT", "Can't find default hosts file: {}. Specify a valid file with -f or just pass the hosts as args. See -h for help".format(args.hostsfile))
            exit(5)

    return args_attr


def instance_service(_list_srvs) -> list:
    """Function instance_service() - Do a list with instances of Service Class.

    Get the values needed to instance the Service Class.
    Each host/service inside the list provided will be append to a final list."""
    _ret_list = []
    _idx = 1
    try:
        for host in _list_srvs:
            host_val = host.split(':')
            name = host_val[0]
            addr = host_val[1]
            prot = host_val[2].rstrip("\n")
            _ret_list.append(Service(_idx, name, addr, prot))
            _idx += 1
        return _ret_list

    except BaseException as e_msg:
        fail_exit(e_msg)


def main():
    """Function main() - The main function.

    Parse the values from list list_services and create a dict of objects
    from Service class, after that, check and report services one by one."""
    try:
        ret_args = parse_args()
        if ret_args["mode"] == "hosts_file":
            list_services = parse_hostsfile(ret_args["hostsfile"])

        else:
            list_services = parse_hostsargs(ret_args)

        print_banner()
        print_header()

        turns = Counter(ret_args["count"])
        services = instance_service(list_services)

    except BaseException as e_msg:
        fail_exit(e_msg)

    try:
        while True:
            for service in services:
                service.timeout = ret_args["timeout"]
                service.chk_srv()
                print_status(service, turns)

            if turns.count == turns.final_count:
                turns.finish()
                break

            turns.add_one()
            time.sleep(ret_args["interval"])

    except KeyboardInterrupt:
        print("")
        print_std("ALERT", "Ouch! That's an interruption...")
        exit(130)

    else:
        exit(0)

if __name__ == '__main__':
    main()
