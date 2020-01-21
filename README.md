What is ``minimon``?
-----------------------
Well, if you are a CLI guy like me, and just need a quick and reliable status of a network device/link/host/service you should give a chance on minimon!

### Prerequisites

- Just Python 3 (No external libs needed)! :snake:

### Usage

A step by step series of examples that show you how to use minimon.

Default behavior: loop indefinitely, checking every minute hosts/service inside minimon.txt file.

```
python3 minimon.py
```
![gif](https://i.imgur.com/XkMGVnT.gif)


Using hosts file:
Create a hosts file or edit minimon.txt with your hosts/services.
The hosts file must use the following structure:
[NAME/DESCRIPTION]:[ADDRESS]:[PROTOCOL/TCPPORT]
```
Name/Description of host 1:8.8.8.8:icmp
Name/Description of host 2:www.bigwebprovider.com/somestaticpage.html:http
Name/Description of host 3:www.lpi.org:https
Name/Description of host 4:ftp.qubes-os.org:ftps
Name/Description of host 5:somealternativepage.net:8080
```

Passing hosts without Hosts file.
Check it every 30 secs for 5 times:
```
python3 minimon.py -i 30 -c 5 8.8.8.8 8.8.4.4 1.1.1.1
```

Check it every 30 secs for 5 times:
```
python3 minimon.py -i 30 -c 5
```

Check at every 10 secs for 10 times using other hosts file:
```
python3 minimon.py --hostsfile /tmp/temp.txt --interval 10 --count 10 
```
If you want to check just a single host/service bypassing the hosts file:
```
python3 minimon.py -i 10 -p http localhost
or
python3 minimon.py -i 10 localhost (default protocol is icmp)
```
### All Available Parameters
| Name | Description |
|------|-------------|
| -f / --hostsfile | The hosts file should content: NAME:ADDRESS:PROTOCOL line by line. Default: minimon.txt |
| -p / --protocol | Use only if not using hostsfile. Default=icmp |
| -i / --interval | The interval in seconds minimon will make another check. Default: 10 seconds (1-3600) |
| -c / --count | How many checks minimon will do. Default: 0 (infinite loop) - (0-99999) |
| -t / --timeout | Set a global timeout in seconds for checks. Default: 5 (1-30). |
| -h / --help | show the help message and exit |
| --version | show program's version number and exit |

### Color Status Code:
| Color | Description |
|------|-------------|
| GREEN | Service/Host is up |
| YELLOW | Service/Host status changed since the last check |
| RED | Service/Host is down |

### Protocols supported:
HTTP/HTTPS, ICMP, and generic (Socks) TCP Open port(1-65535).

![screenshot](https://i.imgur.com/QGzBWzQ.png)

### TODO and Thoughts :thought_balloon:
For the sake of keeping things simple, I think the program is what it is, of course a few features can come here and there but  nothing in mind now. Any new fancy feature would probably require external libs or deceived from the original purpose.

- [ ] - Finish generic TCP/UDP port check via socks

:warning: ***Warning:*** HTTPS support is only available if Python was compiled with SSL support (through the SSL module).
If your HTTPS checks are alway getting OFFLINE, maybe that's the problem. 
Check with: python3 -m ssl 

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

