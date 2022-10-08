# iptables -t nat -N myservice
# iptables -t nat -N services
# iptables -t nat -A myservice  -m statistic --mode random --probability 0.3333 -j DNAT --to-destination 172.18.1.3
# iptables -t nat -A myservice  -m statistic --mode random --probability 0.5 -j DNAT --to-destination 172.18.1.4
# iptables -t nat -A myservice  -j DNAT --to-destination 172.18.1.5



# iptables -t nat -A OUTPUT -d 10.10.0.0/16 -j services
print "*nat"
print ":services - [0:0]"
for a in range(1, 101):
    for b in range(1, 101):
        print "-A services -d 10.10.%d.%d/32 -j myservice" % (a, b)

print "COMMIT"

