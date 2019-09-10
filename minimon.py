#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Author: Bruno Fereira / https://github.com/bruno-sf
Date: Ago 2019
Name: minimon.py
Purpose: Check if a service/host is up (green), down(red) and shows when status
changes(yellow).
License: This project is licensed under the MIT License - see the LICENSE.md
file for details.
"""
try:
    import os
    import time
    import socket
    from contextlib import closing
    import urllib.request
    from urllib.error import HTTPError, URLError
    import argparse

except ImportError as e_msg:
    print(e_msg)
    exit(1)

VERSION = 2
DATE = "Ago 2019"
AUTHOR = "Bruno Ferreira"
LIMIT = 50
COLORS = {"UP": '\033[92m', "DOWN": '\033[91m', "NORMAL": '\033[0m',
          "HEADER": '\033[95m', "ALERT": '\033[93m'}


class Service():
    """Service class - Is the Main class. Set the basics to monitor the services.

    Attributes:
        idx: The index of service in the list/dict
        name: The name of the service being monitored. ex.: My router
        addr: The address of the service. ex.: www.test.com or 192.168.1.100
        prot: The protocol used to monitor. ex.: HTTP, HTTPS, ICMP..,
        status: The status of the service. ex.: ONLINE, OFFLINE...
    """
    #Protocols beside ICMP and HTTP(S) here are just Alias for default service ports.
    PROTOCOLS = ["http", "https", "icmp", "ssh", "ftp", "ftps", "telnet"]    
    __slots__ = ['idx', 'name', 'addr', 'prot', 'status', 'last_status', '_timeout']
    def __init__(self, idx, name, addr, prot):
        """Construct the Service class and set the attribs."""
        self.idx = idx
        self.name = name
        self.addr = addr
        self.prot = prot
        self.status = ""
        self.last_status = ""
        self._timeout = 5

    def __repr__(self):
        """Method to return a brief description of this class."""
        return "Host/Service {name} : {addr} : {prot}".format(name=self.name, \
        addr=self.addr, prot=self.prot)


    def chk_web(self):
        """Method chk_web() - Do basic requests for checking web service availability."""
        try:
            _url = "{prot}://{addr}".format(prot=self.prot, addr=self.addr)
            _ret_code = urllib.request.urlopen(_url, None, timeout=self.timeout).getcode()

        except (HTTPError, URLError):
            #Warning: Python compiled without ssl will enter here on https requests.
            self.offline()
            return 1

        else:
            if _ret_code == 200:
                self.online()
                return 0

            self.offline()
            return 1


    def chk_icmp(self):
        """Method chk_icmp() - Checks ICMP response.

        Use the own system ping utility to determine if a host is alive.
        """
        try:
            _cmd_win = "ping -n 1 -w {timeout} {addr} > {devnull}"\
                        .format(timeout=self.timeout*1000, addr=self.addr, devnull=os.devnull)
            _cmd_nix = "ping -q -c 1 -W {timeout} {addr} > {devnull} 2>&1"\
                        .format(timeout=self.timeout, addr=self.addr, devnull=os.devnull)
            _cmd_mac = "ping -q -c 1 {addr} > {devnull}".format(addr=self.addr, devnull=os.devnull)
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

        except OSError:
            print("[ERROR]: Can't determine your OS.")
            return 1

        except BaseException:
            print("[ERROR]: Can't check ICMP.")
            return 1

        else:
            if _ret == 0:
                self.online()
                return 0

            self.offline()
            return 1


    def chk_sock(self):
        """Method chk_sock() - Generic method for port checking with sockets."""
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as _sock:
                _sock.settimeout(self.timeout)

                if _sock.connect_ex((self.addr, 22)) == 0:
                    self.online()
                    return 0

                self.offline()
                return 1

        except socket.error:
            self.offline()
            return 1


    def chk_srv(self):
        """Method chk_srv() - Aux. Method internally called by term_report().

        Do the basic checks and call the designated protocol function ;)
        """
        _protocol = self.prot.lower()

        if _protocol not in self.PROTOCOLS:
            fail_exit("Invalid protocol")

        if _protocol in ["http", "https"]:
            _ret = self.chk_web()

        if _protocol == "icmp":
            _ret = self.chk_icmp()
        
        return _ret


    def print_status(self):
        """Method print_status() - Aux. Method called by term_report()."""
        _cstatus = {
            "ONLINE ": COLORS["UP"]+self.status+COLORS["NORMAL"],
            "OFFLINE": COLORS["DOWN"]+self.status+COLORS["NORMAL"],
            "ALERT": COLORS["ALERT"]+self.status+COLORS["NORMAL"]
        }

        _current_time = time.localtime()
        _f_time = time.strftime('%H:%M:%S', _current_time)
        _status_msg = "[{status}] : ({cnt}:{idx}) - {time} - [{prot}] - {name} - {addr}"\
                .format(name=self.name, addr=self.addr, prot=self.prot.upper(), \
                status=_cstatus[self.status], time=_f_time, idx=self.idx, \
                cnt=TURNS.count)
        _alert_msg = "[{status}] : ({cnt}:{idx}) - {time} - [{prot}] - {name} - {addr}"\
                .format(name=self.name, addr=self.addr, prot=self.prot.upper(), \
                status=_cstatus["ALERT"], time=_f_time, idx=self.idx, \
                cnt=TURNS.count)

        if self.last_status:
            if self.last_status == self.status:
                print(_status_msg)
            else:
                print(_alert_msg)
        else:
            print(_status_msg)


    def term_report(self):
        """Method term_report() - The core method. Do terminal reporting."""
        try:
            _ret = self.chk_srv()

        except BaseException as e_msg:
            fail_exit(e_msg)

        else:
            if _ret == 0:
                self.print_status()

            else:
                self.print_status()


    def online(self):
        """Method online() - Set the status attribute to "ONLINE " ."""
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
    """Class to handle counting"""
    def __init__(self, final_count, count=1, initial=1):
        """Construct the Counter class"""
        self.initial = initial
        self.count = count
        self.final_count = final_count


    def __repr__(self):
        """Method to return a brief description of this class."""
        return "Class to handle counting. Initial:{} - Current:{} - Final:{}".\
        format(self.initial, self.count, self.final_count)


    def finish(self):
        """Method finish - Make sure to exit when the count is over.

        If using the argument "-c or --count" and the count is over!
        """
        _msg = "Finally! Your count ({}) is over. Have a good one!"\
        .format(self.final_count)
        print(COLORS["HEADER"]+_msg+COLORS["NORMAL"])


    def add_one(self):
        """Method add_one - Add one for variable count."""
        self.count += 1
        return 0


def fail_exit(_msg):
    """Funtion fail_exit() - Called if things goes wrong and show custom msg."""
    _msg = "[ERROR]: {} - Sorry about that, exiting...".format(_msg)
    print(COLORS["HEADER"]+_msg+COLORS["NORMAL"])
    exit(1)

def print_header():
    """Function print_header() - print the header to help visualize the values."""
    _header_str = "[STATUS ] : (TURN:ID) - TIME - [PROT] - NAME - ADDRESS"
    print(COLORS["HEADER"]+_header_str+COLORS["NORMAL"])

def print_banner():
    """print_banner - print a banner and information about Version and Author."""
    _banner = """
     __  __ _       _
    |  \/  (_)     (_)
    | \  / |_ _ __  _ _ __ ___   ___  _ __  
    | |\/| | | '_ \| | '_ ` _ \ / _ \| '_ \ 
    | |  | | | | | | | | | | | | (_) | | | |
    |_|  |_|_|_| |_|_|_| |_| |_|\___/|_| |_|
    """
    print("")
    print(COLORS["ALERT"]+_banner)
    print("    Version: {ver} {date} - Author: {author}"\
        .format(ver=VERSION, date=DATE, author=AUTHOR))
    print(""+COLORS["NORMAL"])

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

    except BaseException:
        fail_exit("Can't read the hosts file provided:{}".format(file))
    else:
        return _list_hosts

def parse_hostsargs() -> list:
    """Function parse_hostsargs() - Parse hosts passed by arguments in CLI

    return a list like: ['Target[1]:8.8.8.8:icmp\n', 'Target[2]:1.1.1.1:icmp\n']"""
    _idx = 1
    _list_hosts = list()
    for host in RET_ARGS["hostsarg"]:
        _list_hosts.append("Target[{_idx}]:{addr}:{prot}".format(\
        _idx=_idx, addr=host, prot=RET_ARGS["protocol"]))
        _idx += 1
    return _list_hosts

def parse_args() -> dict:
    """Function parse_args - Check and parse args, and finally atribute vals"""
    parser = argparse.ArgumentParser(description="""Complete Usage:""", )

    parser.add_argument("-i", "--interval", type=int, action="store", \
        dest="interval", default=10, help="The interval in \
        seconds minimon will make another check. Default: 10 seconds (1-3600)")

    parser.add_argument("-t", "--timeout", type=int, action="store", \
        dest="timeout", default=5, help="Set a global timeout in \
        seconds for checks. Default: 5 (1-30).")
    parser.add_argument("-c", "--count", type=int, action="store", \
        dest="count", default=0, help="How many checks minimon will do. \
        Default: 0 (infinite loop) - (0-99999).")

    my_exc_grp = parser.add_mutually_exclusive_group()

    my_exc_grp.add_argument("-f", "--hostsfile", type=str, action="store", \
        dest="hostsfile", default="minimon.txt", help="The hosts file \
        should content: NAME:ADDRESS:PROTOCOL line by line. \
        Default: minimon.txt")

    my_exc_grp.add_argument("-p", "--protocol", type=str, action="store", \
        dest="protocol", default="icmp", help="Use only if not using hostsfile.\
        Default=icmp")

    parser.add_argument(
        '--version', action='version', version='%(prog)s - Minimon - Version: \
        {ver} - {date} - Author: {author}'.format(ver=VERSION, date=DATE, \
        author=AUTHOR))

    parser.add_argument('pos_arg', metavar="Target(s)", type=str, nargs='*', \
        help="If you pass a target host(s) as a positional arg the hostsfile \
        will be ignored. Ex: minimon.py -p https www.lpi.org webserver.intranet")

    args = parser.parse_args()

    if args.interval < 1 or args.interval > 3600:
        fail_exit("Invalid interval value, use something between 1-3600 seconds.")

    if args.count < 0 or args.count > 99999:
        fail_exit("Invalid count value, use something between 0-99999")

    if args.timeout < 1 or args.timeout > 30:
        fail_exit("Invalid timeout value, use an interval between 1-30 seconds.")

    if args.pos_arg:
        args_attr = {"mode": "pos_arg", "interval": args.interval, \
        "hostsarg": args.pos_arg, "count": args.count, "timeout": args.timeout,\
        "protocol": args.protocol}

    else:
        if hostsfile_exist(args.hostsfile):
            args_attr = {"mode": "hosts_file", "hostsfile": args.hostsfile, \
            "interval": args.interval, "count": args.count, \
            "timeout": args.timeout}
        else:
            fail_exit("Can't find hosts file: {}".format(args.hostsfile))

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

def chk_list_limit(_list):
    """chk_limit() - Check if the list of services is below the limit."""
    if len(_list) > LIMIT:
        fail_exit("I am no Zabbix...Too many hosts to verify at once...")

def main():
    """Function main() - The main function.

    Parse the values from list LIST_SERVICES and create a dict of objects
    from Service class, after that, check and report services one by one."""
    try:
        while True:
            for service in SERVICES:
                service.timeout = RET_ARGS["timeout"]
                service.term_report()

            if TURNS.count == TURNS.final_count:
                TURNS.finish()
                break

            TURNS.add_one()
            time.sleep(RET_ARGS["interval"])

    except KeyboardInterrupt:
        print("")
        print(COLORS["HEADER"]+"Ouch! That's an interruption..."+COLORS["NORMAL"])
        exit(2)

    except BaseException as e_msg:
        fail_exit(e_msg)

    else:
        exit(0)

try:
    RET_ARGS = parse_args()

    if RET_ARGS["mode"] == "hosts_file":
        LIST_SERVICES = parse_hostsfile(RET_ARGS["hostsfile"])

    else:
        LIST_SERVICES = parse_hostsargs()

    chk_list_limit(LIST_SERVICES)

    print_banner()
    print_header()

    TURNS = Counter(RET_ARGS["count"])
    SERVICES = instance_service(LIST_SERVICES)

except BaseException as e_msg:
    fail_exit(e_msg)

if __name__ == '__main__':
    main()
