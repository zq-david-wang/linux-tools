# iptables -t nat -N myservice
# iptables -t nat -A myservice  -m statistic --mode random --probability 0.3333 -j DNAT --to-destination 172.18.1.3
# iptables -t nat -A myservice  -m statistic --mode random --probability 0.5 -j DNAT --to-destination 172.18.1.4
# iptables -t nat -A myservice  -j DNAT --to-destination 172.18.1.5



# iptables -t nat -A OUTPUT -d 10.10.0.0/16 -j myservice

for a in range(1, 100):
    for b in range(1, 100):
        print "iptables -t nat -D OUTPUT -d 10.10.%d.%d/32 -j myservice" % (a, b)

