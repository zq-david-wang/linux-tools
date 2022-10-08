vip = "10.10.0.1"
ss = [
    "172.18.1.3",
    "172.18.1.4",
    "172.18.1.5",
]

print "*nat"
print ":myservice - [0:0]"

# iptables -t nat -A myservice -d 10.10.0.1 -m statistic --mode random --probability 0.3333 -j DNAT --to-destination 172.18.1.3
x, n = 0, 10000
m = n
for _ in range(n-1):
    p = 1.0/m
    print "-A myservice -d %s -m statistic --mode random --probability %.16f -j DNAT --to-destination %s" % (vip, p, ss[x])
    m-=1
    x+=1
    x%=len(ss)
print "-A myservice -d %s -j DNAT --to-destination %s" % (vip, ss[x])

print "COMMIT"
