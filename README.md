# dnsmasq

http://www.thekelleys.org.uk/dnsmasq/doc.html

git remote add upstream git://thekelleys.org.uk/dnsmasq.git

make && src/dnsmasq -p 5454 -d -q --gfwlist=test/gfwlist.conf@8.8.8.8~53

#src/dnsmasq -p 5454 -d -q --gfwlist=test/gfwlist.conf@8.8.8.8~53^gfwlist

dig @127.0.0.1 -p 5454 google.com
