#!/usr/bin/env bash

set -x
set -e

# ipv4
sudo iptables -t mangle -F || true
sudo iptables -t mangle -X DIVERT || true
sudo ip rule del fwmark 1 lookup 100 || true
sudo ip route del local 0.0.0.0/0 dev lo table 100 || true

sudo iptables -t mangle -N DIVERT
sudo iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
sudo iptables -t mangle -A DIVERT -j MARK --set-mark 1
sudo iptables -t mangle -A DIVERT -j ACCEPT
sudo ip rule add fwmark 1 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100
sudo iptables -t mangle -A PREROUTING -i ens33 -s 192.168.3.0/24 -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080
sudo iptables -t mangle -A PREROUTING -i ens33 -s 192.168.3.0/24 -p udp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080

# ipv6
sudo ip6tables -t mangle -F || true
sudo ip6tables -t mangle -X DIVERT || true
sudo ip -6 rule del fwmark 1 lookup 100 || true
sudo ip -6 route del local ::/0 dev lo table 100 || true

sudo ip6tables -t mangle -N DIVERT
sudo ip6tables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
sudo ip6tables -t mangle -A DIVERT -j MARK --set-mark 1
sudo ip6tables -t mangle -A DIVERT -j ACCEPT
sudo ip -6 rule add fwmark 1 lookup 100
sudo ip -6 route add local ::/0 dev lo table 100
sudo ip6tables -t mangle -A PREROUTING -i ens33 -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080
sudo ip6tables -t mangle -A PREROUTING -i ens33 -p udp -j TPROXY --tproxy-mark 0x1/0x1 --on-port 8080

sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
go build -o /tmp/poohvpn.tproxy main.go
sudo /tmp/poohvpn.tproxy
