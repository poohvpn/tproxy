set -x
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo ip r delete default
sudo ip r add default via 192.168.3.4
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
sudo ip6tables -t nat -A POSTROUTING -j MASQUERADE
