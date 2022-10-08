for a in range(1, 101):
    for b in range(1, 101):
        print "ip add add 20.20.%d.%d dev lo" % (a, b)
