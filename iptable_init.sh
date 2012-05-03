IP="10.3.3.38"
LAN="10.4.38.0/27"

sudo iptables -t nat -F
sudo iptables -t filter -F
sudo iptables -t mangle -F

sudo iptables -t filter -A FORWARD -j QUEUE -p tcp -s ${LAN} ! -d ${IP}
sudo iptables -t mangle -A PREROUTING -j QUEUE -p tcp ! -s ${LAN} -d ${IP} \
        --dport 55000:56000

#sudo iptables -t nat -F
#sudo iptables -t filter -F
#sudo iptables -t mangle -F
#sudo iptables -t filter -A FORWARD \
#    -j QUEUE -p tcp -s ${LAN} ! -d ${IP}
#sudo iptables -t mangle -A PREROUTING \
#    -j QUEUE -p tcp ! -s ${LAN} -d ${IP} --dport 55000:56000
