vip = "10.10.0.1"
ss = [
    "172.18.1.3",
    "172.18.1.4",
    "172.18.1.5",
]

# iptables -t nat -A myservice -d 10.10.0.1 -m statistic --mode random --probability 0.3333 -j DNAT --to-destination 172.18.1.3
x, n = 0, 10000
def build(s, e, p):
    n = e-s+1
    if n<=16:
        m = n
        for i in range(s, e):
            pp = 1.0/m
            print "iptables -t nat -A %s -d %s -m statistic --mode random --probability %.16f -j DNAT --to-destination %s" % (p, vip, pp, ss[i%len(ss)])
            m-=1
        print "iptables -t nat -A %s -d %s -j DNAT --to-destination %s" % (p, vip, ss[i%len(ss)])
    else:
        # split
        m = (s+e)/2
        x = "myservice%d_%d" % (s, m)
        print "iptables -t nat -N %s" % x
        pp = (m-s+1)*1.0/n
        print "iptables -t nat -A %s -m statistic --mode random --probability %.16f -j %s" % (p, pp, x)
        build(s, m, x)
        x = "myservice%d_%d" % (m+1, e)
        print "iptables -t nat -N %s" % x
        print "iptables -t nat -A %s -j %s" % (p, x)
        build(m+1, e, x)

build(0, n-1, "myservice")
