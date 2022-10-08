#!/bin/bash


iptables -t raw -I PREROUTING -p tcp --dport 8080 -j LOG --log-prefix "target in raw.prerouting>"
iptables -t mangle -I PREROUTING -p tcp --dport 8080 -j LOG --log-prefix "target in mangle.prerouting>"
iptables -t nat -I PREROUTING -p tcp --dport 8080 -j LOG --log-prefix "target in nat.prerouting>"
iptables -t mangle -I INPUT -p tcp --dport 8080 -j LOG --log-prefix "target in mangle.input>"
iptables -t filter -I INPUT -p tcp --dport 8080 -j LOG --log-prefix "target in filter.input>"
iptables -t raw -I OUTPUT -p tcp --dport 8080 -j LOG --log-prefix "target in raw.output>"
iptables -t mangle -I OUTPUT -p tcp --dport 8080 -j LOG --log-prefix "target in mangle.output>"
iptables -t nat -I OUTPUT -p tcp --dport 8080 -j LOG --log-prefix "target in nat.output>"
iptables -t filter -I OUTPUT -p tcp --dport 8080 -j LOG --log-prefix "target in filter.output>"
iptables -t mangle -I FORWARD -p tcp --dport 8080 -j LOG --log-prefix "target in mangle.forward>"
iptables -t filter -I FORWARD -p tcp --dport 8080 -j LOG --log-prefix "target in filter.forward>"
iptables -t mangle -I POSTROUTING -p tcp --dport 8080 -j LOG --log-prefix "target in mangle.postrouting>"
iptables -t nat -I POSTROUTING -p tcp --dport 8080 -j LOG --log-prefix "target in nat.postrouting>"
