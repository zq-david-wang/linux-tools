#!/bin/bash

source="172.18.1.5"

iptables -t raw -I PREROUTING -s "$source" -j LOG --log-prefix "target in raw.prerouting>"
iptables -t mangle -I PREROUTING -s "$source" -j LOG --log-prefix "target in mangle.prerouting>"
iptables -t nat -I PREROUTING -s "$source" -j LOG --log-prefix "target in nat.prerouting>"
iptables -t mangle -I INPUT -s "$source" -j LOG --log-prefix "target in mangle.input>"
iptables -t filter -I INPUT -s "$source" -j LOG --log-prefix "target in filter.input>"
iptables -t raw -I OUTPUT -s "$source" -j LOG --log-prefix "target in raw.output>"
iptables -t mangle -I OUTPUT -s "$source" -j LOG --log-prefix "target in mangle.output>"
iptables -t nat -I OUTPUT -s "$source" -j LOG --log-prefix "target in nat.output>"
iptables -t filter -I OUTPUT -s "$source" -j LOG --log-prefix "target in filter.output>"
iptables -t mangle -I FORWARD -s "$source" -j LOG --log-prefix "target in mangle.forward>"
iptables -t filter -I FORWARD -s "$source" -j LOG --log-prefix "target in filter.forward>"
iptables -t mangle -I POSTROUTING -s "$source" -j LOG --log-prefix "target in mangle.postrouting>"
iptables -t nat -I POSTROUTING -s "$source" -j LOG --log-prefix "target in nat.postrouting>"
