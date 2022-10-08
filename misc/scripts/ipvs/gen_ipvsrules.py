t = """
ipvsadm -A -t 20.20.{a}.{b}:8080 -s rr
ipvsadm -a -t 20.20.{a}.{b}:8080 -r 172.18.1.3:8080 -m
ipvsadm -a -t 20.20.{a}.{b}:8080 -r 172.18.1.4:8080 -m
ipvsadm -a -t 20.20.{a}.{b}:8080 -r 172.18.1.5:8080 -m
"""

for a in range(1,101):
    for b in range(1, 101):
        print t.format(a=a, b=b)
