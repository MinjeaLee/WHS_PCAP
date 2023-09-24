#include "whspcap.h"
// gcc -o pcap pcap.c -lpcap

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	struct sniff_ethernet *ethernet;	// ethernet header
	struct ip *ip_header;				// ip header
	struct tcphdr *tcp_header;			// tcp header
	char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];	// source ip, destination ip
	int ip_header_len;					// ip header length

	ethernet = (struct sniff_ethernet *)(packet);	// packet을 이더넷 헤더로 캐스팅
	ip_header = (struct ip *)(packet + SIZE_ETHERNET);	// packet을 ip 헤더로 캐스팅, 패킷에 이더넷 헤더의 크기를 더해주어 ip 헤더의 시작 위치를 알려줌
	ip_header_len = ip_header->ip_hl * 4;	// ip 헤더의 길이를 알려줌, ip_hl은 4바이트 단위이므로 4를 곱해줌

	if (ip_header->ip_p != IPPROTO_TCP)	// ip 헤더의 프로토콜이 TCP가 아니면 종료
	{
		return;
	}

	tcp_header = (struct tcphdr *)(packet + SIZE_ETHERNET + ip_header_len);	// packet을 tcp 헤더로 캐스팅, 패킷에 이더넷 헤더와 ip 헤더의 크기를 더해주어 tcp 헤더의 시작 위치를 알려줌

	inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);	// ip 헤더의 소스 ip를 src_ip에 저장, AF_INET은 IPv4, INET_ADDRSTRLEN은 IPv4 주소의 길이,
	inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

	printf("Ethernet Header:\n");
	printf("\tSource MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
	printf("\tDestination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

	printf("IP Header:\n");
	printf("\tSource IP: %s\n", src_ip);
	printf("\tDestination IP: %s\n", dst_ip);

	printf("TCP Header:\n");
	printf("\tSource Port: %d\n", ntohs(tcp_header->th_sport));
	printf("\tDestination Port: %d\n", ntohs(tcp_header->th_dport));

	printf("\n");
}

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		printf("Usage: %s <interface>\n", argv[0]);
		exit(1);
	}

	char *interface = argv[1];		// interface name
	char errbuf[PCAP_ERRBUF_SIZE];	// error buffer
	pcap_t *handle;				// packet capture handle

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	// interface: 네트워크 인터페이스 이름
	// BUFSIZ: 패킷을 읽어들일 버퍼의 크기
	// 1: promiscuous mode, 0: non-promiscuous mode, promiscuous mode는 네트워크 인터페이스가 받은 모든 패킷을 읽어들이는 모드
	// 1000: 읽어들일 패킷의 최대 길이
	// errbuf: 에러 메시지를 저장할 버퍼

	if (handle == NULL)
	{
		fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
		exit(2);	
	}

	pcap_loop(handle, 0, packet_handler, NULL);	// 패킷 캡처를 시작, 0은 무한 루프, packet_handler는 패킷을 처리할 함수, NULL은 사용자 정의 데이터

	pcap_close(handle);		// 패킷 캡처를 종료
	return 0;
}
