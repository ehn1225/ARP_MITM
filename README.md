# ARP - Man In The Middle Attack
### ARP Spoofing 공격을 수행하는 도구입니다.
- pcap을 이용하여 호스트로 유입되는 패킷을 캡쳐합니다.
- 피해자와 피해자 Gateway의 ARP 테이블을 변조하고, 중간자 공격을 수행합니다.
- wireshark를 이용하여 중간에서 패킷을 스니핑할 수 있습니다.
- Jumbo Frame Relay를 지원합니다.
  - 초기 IP Fragmentation으로 시도하였으나 실패
  - 이후 TCP Segmentation으로 성공
- 개발 일자 : 2022.08

## Usage
- syntax: send-arp-test NIC_name sender_ip target_ip sender_ip target_ip
- sample: send-arp-test wlan0 192.168.0.5 192.168.0.1 192.168.0.1 192.168.0.5

## Reference
[How to Calculate IP/TCP/UDP Checksum](https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a)

