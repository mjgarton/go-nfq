go test -c || exit -1
sudo iptables -A OUTPUT -p udp --dport 9999 --sport 9999 -j NFQUEUE --queue-num 0
sudo ./go-nfq.test
sudo iptables -D OUTPUT -p udp --dport 9999 --sport 9999 -j NFQUEUE --queue-num 0
