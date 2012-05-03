echo '      == Filter ==' 
sudo iptables --list -t filter -v

#echo '      == NAT ==' 
#sudo iptables --list -t nat -v

echo '      == Mangle ==' 
sudo iptables --list -t mangle -v
