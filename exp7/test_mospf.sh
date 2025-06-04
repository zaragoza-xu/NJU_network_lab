py print('--- 开始 MOSPFTopo 测试 ---')

r1 tcpdump -i r1-eth0 -s0 -U -w ./pcap/r1-eth0.pcap &
r1 tcpdump -i r1-eth1 -s0 -U -w ./pcap/r1-eth1.pcap &
r1 tcpdump -i r1-eth2 -s0 -U -w ./pcap/r1-eth2.pcap &
r2 tcpdump -i r2-eth0 -s0 -U -w ./pcap/r2-eth0.pcap &
r2 tcpdump -i r2-eth1 -s0 -U -w ./pcap/r2-eth1.pcap &
r3 tcpdump -i r3-eth0 -s0 -U -w ./pcap/r3-eth0.pcap &
r3 tcpdump -i r3-eth1 -s0 -U -w ./pcap/r3-eth1.pcap &
r4 tcpdump -i r4-eth0 -s0 -U -w ./pcap/r4-eth0.pcap &
r4 tcpdump -i r4-eth1 -s0 -U -w ./pcap/r4-eth1.pcap &
r4 tcpdump -i r4-eth2 -s0 -U -w ./pcap/r4-eth2.pcap &

py print('在每个路由器上启动 mospfd...')
r1 ./mospfd > ./tmp/r1_mospfd.log 2>&1 &
r2 ./mospfd > ./tmp/r2_mospfd.log 2>&1 &
r3 ./mospfd > ./tmp/r3_mospfd.log 2>&1 &
r4 ./mospfd > ./tmp/r4_mospfd.log 2>&1 &



py print('--- MOSPFTopo 测试执行完毕 ---')