# Minimon

A very very simple program to check if a service/host is online.

## Getting Started

Well if you are a CLI(command line interface) guy like me and sometimes need to do simple and temporary checks on your nerwork or some external site give a chance on Minimon! 

If a service/host is up (green), down(red) and show when status change(yellow).

### Prerequisites

Create a hosts file or edit minimon.txt with your services.
Verify if you have file with the following values:
```
Name/Description of host 1:8.8.8.8:icmp
Name/Description of host 2:1.1.1.1:http
Name/Description of host 3:www.bb.com.br:https
Name/Description:www.uifyiufydsi.com:http
```
No external libs!
Just run Python 3 and nothing else!

### Usage

A step by step series of examples that tell you how to use minimon.

Do the default monitor: loop indefinitely, checking every minute hosts/service inside minimon.txt file)
```
python3 minimon.py
```

Do the monitor at every 30 secs for 5 times!
```
python3 minimon.py -i 30 -c 5
```

Do the monitor at every 10 secs for 10 times using an alternate hosts file!
```
python3 minimon.py --hostsfile /tmp/temp.txt --interval 10 --count 10 
```

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.