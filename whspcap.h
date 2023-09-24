#ifndef WHSPCAP_H
#define WHSPCAP_H

#include <pcap.h> // 패킷 캡쳐 
#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>	// 이더넷 프레임 정의
#include <netinet/ip.h>			// IP 해더 정의
#include <netinet/tcp.h>		// TCP 해더 정의
#include <arpa/inet.h>			// inet_ntoa() 함수 사용

#define SIZE_ETHERNET 14		// 이더넷 헤더 크기, 

/* Ethernet header */
struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN];	// 목적지 MAC 주소
	u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
	u_short ether_type;					// 프로토콜 타입, 상위 프로토콜 식별
};

# endif