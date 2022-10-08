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
        pass
    else:
        # split
        m = (s+e)/2
        x = "myservice%d_%d" % (s, m)
        print "iptables -t nat -F %s" % x
        print "iptables -t nat -X %s" % x
        build(s, m, x)
        x = "myservice%d_%d" % (m+1, e)
        print "iptables -t nat -F %s" % x
        print "iptables -t nat -X %s" % x
        build(m+1, e, x)

print "iptables -t nat -F myservice"
build(0, n-1, "myservice")
