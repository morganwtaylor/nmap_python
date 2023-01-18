import nmap, csv, re

nm=nmap.PortScanner()

cidr_list=[]
cidr_regex = '(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?'

host_count = 0
up_count = 0

def check_cidr(cidr):
    if(re.search(cidr_regex, cidr)):
        return "Valid CIDR"
    else:
        pass

def get_ip_list():
    with open('ip_ranges.csv', newline='') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',')
        for row in csvreader:
            for cidr_range in row:
                if check_cidr(cidr_range) == "Valid CIDR":
                    cidr_list.append(cidr_range)
                else:
                    pass

def discovery_scan(cidr):
    global host_count, up_count
    nm.scan(hosts=cidr, arguments='-PE -PU')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    host_count += len(hosts_list)
    for host, status in hosts_list:
        if status == 'up':
            up_count +=1
    with open('output.csv', 'w', newline='') as output:
            output.write(nm.csv())

if __name__ == "__main__":
    get_ip_list()
    for cidr in cidr_list:
        print(f"Scanning range {cidr}")
        discovery_scan(cidr)
    print(f"Scanned {host_count} IPs, there are {up_count} up")
