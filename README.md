# Minimon

A tiny program to check if a Host/Service is online.

## Getting Started

Well, if you are a CLI guy like me, and need a quick and reliable status of a network device/host/service you should give a chance on Minimon!

### Color Status Code:
| Color | Description |
|------|-------------|
| GREEN | Service/Host is up |
| YELLOW | Service/Host status changed since last check |
| RED | Service/Host is down |

Protocols supported:
HTTP/HTTPS, ICMP, and generic (Socks) TCP Open port(1-65535).

### Prerequisites

Just Python 3 (No external libs needed)!

### Usage

A step by step series of examples that tell you how to use minimon.

Default behavior: loop indefinitely, checking every minute hosts/service inside minimon.txt file.
```
python3 minimon.py
```
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
Check at every 30 secs for 5 times:
```
python3 minimon.py -i 30 -c 5 8.8.8.8 8.8.4.4 1.1.1.1
```

Check at every 30 secs for 5 times:
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
| -f / --hostsfile | The ARN assigned by AWS to this policy |
| -p / --protocol | The description of the policy |
| -i / --interval | The policy ID |
| -t / --timeout | The name of the policy |
| -h / --help | The path of the policy in IAM |
| --version | The policy document |

![screenshot](https://i.imgur.com/QGzBWzQ.png)

### Todos and Thoughs
For the sake of keeping things simple, I think the program is what it is. Any new feature would probabbly require external libs or disvitue from the original purpose.

Warning: HTTPS support is only available if Python was compiled with SSL support (through the ssl module).
If your HTTPS checks are alway getting OFFLINE, maybe that's the problem. 
Check with: python3 -m ssl 

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
