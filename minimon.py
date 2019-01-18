#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Author: Bruno Fereira / brunosilvaferreira@protonmail.com
Date: Jan 2019
Name: minimon.py
Purpose: Check if a service/host is up (green), down(red) and show when status
change(yellow).
License: This project is licensed under the MIT License - see the LICENSE.md
file for details
"""
try:
    import os
    import time
    import urllib.request
    import argparse

except ImportError as e_msg:
    print(e_msg)
    exit(1)

VERSION = 1
DATE = "Jan 2019"
AUTHOR = "Bruno Ferreira"
LIMIT = 50
COLORS = {"UP": '\033[92m', "DOWN": '\033[91m', "NORMAL": '\033[0m',
          "HEADER": '\033[95m', "ALERT": '\033[93m'}

class Service():
    """Main class - Set the basics to monitor the service.

    Attributes:
        idx: The index of service in the list/dict
        name: The name of the service being monitored. ex.: My router
        addr: The address of the service. ex.: www.test.com or 192.168.1.100
        prot: The protocol used to monitor. ex.: HTTP, HTTPS, ICMP..,
        status: The status of the service. ex.: ONLINE, OFFLINE...
    """
    PROTOCOLS = ["http", "https", "icmp"]
    TIMEOUT = 5

    def __init__(self, idx, name, addr, prot, status="", last_status=""):
        """Construct the Service class and set the attribs."""
        self.idx = idx
        self.name = name
        self.addr = addr
        self.prot = prot
        self.status = status
        self.last_status = last_status


    def __repr__(self):
        """Method to return a brief description of this class."""
        return "Service class is the main class of minimon."


    def chk_web(self):
        """Method chk_web() - Do basic requests checking web service

        Basically waits for 200 response code, so make sure the URL is correct.
        """
        try:
            _req = "{prot}://{addr}".format(prot=self.prot, addr=self.addr)
            _get_code = urllib.request.urlopen(_req, None, self.TIMEOUT).getcode()

        except BaseException:
            self.is_offline()
            return 1

        else:
            if _get_code == 200:
                self.is_online()
                return 0

            self.is_offline()
            return 1


    def chk_icmp(self):
        """Method chk_icmp() - Checks ICMP response.

        Use the own system ping utility to determine if a host is alive.
        """
        try:
            _cmd_win = "ping -n 1 -w {timeout} {addr} > {devnull}"\
                        .format(timeout=self.TIMEOUT*1000, addr=self.addr, devnull=os.devnull)
            _cmd_nix = "ping -q -c 1 -W {timeout} {addr} > {devnull} 2>&1"\
                        .format(timeout=self.TIMEOUT, addr=self.addr, devnull=os.devnull)
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
                self.is_online()
                return 0

            self.is_offline()
            return 1


    def chk_srv(self):
        """Method chk_srv() - Aux. Method insternally called by term_report().

        Do the basic checks and call the designated protocol function ;)
        """
        _protocol = self.prot.lower()

        if _protocol in self.PROTOCOLS:
            if _protocol == "http":
                _ret = self.chk_web()

            elif _protocol == "https":
                _ret = self.chk_web()

            elif _protocol == "icmp":
                _ret = self.chk_icmp()
        else:
            fail_exit("Invalid protocol")

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
                cnt=TURNS.current)
        _alert_msg = "[{status}] : ({cnt}:{idx}) - {time} - [{prot}] - {name} - {addr}"\
                .format(name=self.name, addr=self.addr, prot=self.prot.upper(), \
                status=_cstatus["ALERT"], time=_f_time, idx=self.idx, \
                cnt=TURNS.current)

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


    def is_online(self):
        """Method is_online() - Set the status attribute to "ONLINE " ."""
        self.last_status = self.status
        self.status = "ONLINE "


    def is_offline(self):
        """Method is_offline() - Set the status attribute to "OFFLINE" ."""
        self.last_status = self.status
        self.status = "OFFLINE"


class Counter():
    """Class to handle count"""
    def __init__(self, final_count, initial=1, current=1):
        """Construct the Counter class"""
        self.initial = initial
        self.current = current
        self.final_count = final_count


    def __repr__(self):
        """Method to return a brief description of this class."""
        return "Class to handle counting."


    def finish(self):
        """Method finish - Make sure to exit when the count is over.

        If using the argument "-c or --count" and the count is over!
        """
        _msg = "Finally! Your count ({}) is over. Have a good one!"\
        .format(self.final_count)
        print(COLORS["HEADER"]+_msg+COLORS["NORMAL"])


    def add_one(self):
        """Method add_one - Add one for variable current."""
        self.current += 1
        return 0


def fail_exit(_msg):
    """Funtion fail_exit() - Called if things goes wrong and show custom msg."""
    _msg = "[ERROR]: {}. Sorry about that, exiting...".format(_msg)
    print(COLORS["HEADER"]+_msg+COLORS["NORMAL"])
    exit(1)

def print_header():
    """Function print_header() - print the header to help visualize the values."""
    _header_str = "[STATUS ] : (TURN:ID) - TIME - [PROT] - NAME - ADDRESS"
    print(COLORS["HEADER"]+_header_str+COLORS["NORMAL"])

def print_banner():
    """print_banner - print a banner and information about version and author"""
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

    Can be "minimon.txt" or the define file on "-f or --hostsfile" args.
    """
    try:
        exists = os.path.isfile(file)

    except BaseException as e_msg:
        fail_exit(e_msg)

    else:
        if exists:
            return True

        fail_exit("Can't find {}".format(file))
        return False

def parse_hostsfile(file):
    """Function parse_hostsfile() - Simple function to parse the content of hostsfile.

    return a list like: ['Teste 123 :8.8.8.8:icmp\n', 'Host 2:1.1.1.1:http\n']
    """
    _list_hosts = []
    try:
        with open(file, 'rt') as in_file:
            for line in in_file:
                _list_hosts.append(line)

    except BaseException:
        fail_exit("""Can't read the hosts file provided.
            Please, provide a file with contents like:
            Host ABC:192.168.1.100:http""")
    else:
        return _list_hosts

def parse_args():
    """Function parse_args - Check args, realize some checks, and finally atribute vals"""
    try:
        usage = '''usage: %(prog)s [-f hostsfile] [-i interval ] [-c count] \
            [--version] [-h --help]'''
        parser = argparse.ArgumentParser(usage=usage)
        parser.add_argument("-f", "--hostsfile", type=str, action="store", \
            dest="hostsfile", default="minimon.txt", help="OPTIONAL -\
            The hosts file should content: NAME:ADDRESS:PROTOCOL line by line.\
            Default: minimon.txt")
        parser.add_argument("-i", "--interval", type=int, action="store", \
            dest="interval", default=60, help="OPTIONAL - The interval in \
            seconds minimon will make a query. Default: 1 minute")
        parser.add_argument("-c", "--count", type=int, action="store", \
            dest="count", default=0, help="OPTIONAL - How many checks \
            minimon will do. Default: 0 (loop).")
        parser.add_argument(
            '--version', action='version', version='%(prog)s {ver} - {date} -\
            {author}'.format(ver=VERSION, date=DATE, author=AUTHOR))

        args = parser.parse_args()

    except BaseException as e_msg:
        fail_exit(e_msg)

    else:
        hostsfile_exist(args.hostsfile)

        if args.interval < 1:
            fail_exit("Please, raise this interval to 1 sec, at least.")

        if args.count < 0 or args.count > 99999:
            fail_exit("Invalid count value. Provide something between 0-99999")

        args_attr = {
            "hostsfile": args.hostsfile, "interval": args.interval,
            "count": args.count}

        return args_attr

def parse_list(_list_srvs):
    """Function parse_list() - Parse the attributes.

    Get the value of each server inside the list and append to another list."""
    _ret_list = []
    _idx = 1
    for host in _list_srvs:
        host_val = host.split(':')
        name = host_val[0]
        addr = host_val[1]
        prot = host_val[2].rstrip("\n")
        _ret_list.append(Service(_idx, name, addr, prot))
        _idx += 1
    return _ret_list

def chk_limit(_list):
    """chk_limit() - Check if the list of services is below the limit."""
    if len(_list) > LIMIT:
        fail_exit("I am no Zabbix...Too many hosts to verify at once")

def main():
    """Function main() - The famous main func.

    Parse the values from LIST_SERVICES and create a dict of objects
    from Service class, after that check and report services one by one."""
    try:
        while True:
            for service in SERVICES:
                service.term_report()

            if TURNS.current == TURNS.final_count:
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

RET_ARGS = parse_args()
LIST_SERVICES = parse_hostsfile(RET_ARGS["hostsfile"])

chk_limit(LIST_SERVICES)
print_banner()
print_header()

TURNS = Counter(RET_ARGS["count"])
SERVICES = parse_list(LIST_SERVICES)

if __name__ == '__main__':
    main()
