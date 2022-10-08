#!/bin/bash

source="172.18.1.5"

iptables -t raw -D PREROUTING -s "$source" -j LOG --log-prefix "target in raw.prerouting>"
iptables -t mangle -D PREROUTING -s "$source" -j LOG --log-prefix "target in mangle.prerouting>"
iptables -t nat -D PREROUTING -s "$source" -j LOG --log-prefix "target in nat.prerouting>"
iptables -t mangle -D INPUT -s "$source" -j LOG --log-prefix "target in mangle.input>"
iptables -t filter -D INPUT -s "$source" -j LOG --log-prefix "target in filter.input>"
iptables -t raw -D OUTPUT -s "$source" -j LOG --log-prefix "target in raw.output>"
iptables -t mangle -D OUTPUT -s "$source" -j LOG --log-prefix "target in mangle.output>"
iptables -t nat -D OUTPUT -s "$source" -j LOG --log-prefix "target in nat.output>"
iptables -t filter -D OUTPUT -s "$source" -j LOG --log-prefix "target in filter.output>"
iptables -t mangle -D FORWARD -s "$source" -j LOG --log-prefix "target in mangle.forward>"
iptables -t filter -D FORWARD -s "$source" -j LOG --log-prefix "target in filter.forward>"
iptables -t mangle -D POSTROUTING -s "$source" -j LOG --log-prefix "target in mangle.postrouting>"
iptables -t nat -D POSTROUTING -s "$source" -j LOG --log-prefix "target in nat.postrouting>"
