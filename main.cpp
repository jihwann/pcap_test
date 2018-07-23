/*
============================================================================
Name : pcap_test.cpp

Author : JiHwan Lim 

Object : [BoB_7th_Consulting] Network Homework #2

Version : 1.0

Copyright : jhim147605@gmail.com  

Description : Print information of the packet in communication
============================================================================
*/


//MAC Address (eth.dmac) : 0~5 (6 byte)
//MAC Address (eth.smac) : 6~B (6 byte)
//IP Address (ip.sip) : 1A ~ 1D (4 byte) 
//IP Address (ip.dip) : 1E ~ 21 (4 byte) 
//Port Address (TCP.sport) : 22~23 (2 byte)
//Port Address (TCP.dport) : 24~25 (2 byte)
//data (print 16 byte) : 36~46


#include <pcap.h>
#include <stdio.h>
typedef u_char u8;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  char track[] = "컨설팅"; // "취약점", "컨설팅", "포렌식"
  char name[] = "임지환";
  int i=0;
  if (argc != 2) {
    usage(); 
    return -1;
  }

  char* dev = argv[1]; // Interface (eth0)
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // Open Handle
  // dev : eth0
  // BUFSIZ : Maximum number of the bytes to capture
  // 1 : How can operate, 1000 : millisecond Unit read timeout
  // errbuf : pcap_open_live()가 실패할 경우만 에러 메시지 저장.
  if (handle == NULL) { //If there is no handle, the packet open must have root privileges.
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header; // pcap header
    const u8* packet; // Real Packet
    int res = pcap_next_ex(handle, &header, &packet); // receive packet
	
	printf("==========================================\n");
	printf("[bob7][%s]pcap_test[%s]\n", track, name);
	///////////////////////////////////////////////////////////////////
	//Start : MAC Address (eth.dmac) : 0~5 (6 byte)
	printf("Destination MAC Address : ");
	for(i=0; i<6; i++){
		printf("%02x ", packet[i]);
	}
	printf("\n");
	//End : MAC Address (eth.dmac) : 0~5 (6 byte)
	
	//Start : MAC Address (eth.smac) : 6~B (6 byte)
	printf("Source MAC Address : ");
	for(i=6; i<12; i++){
		printf("%02x ", packet[i]);
	}
	printf("\n");
	///////////////////////////////////////////////////////////////////
	
	
	///////////////////////////////////////////////////////////////////
	//Start : IP Address (ip.sip) : 1A ~ 1D (4 byte) 
	printf("Source IP Address : ");
	for(i=26; i<30; i++){
		printf("%02x ", packet[i]);
	}
	printf("\n");
	//End : IP Address (ip.sip) : 1A ~ 1D (4 byte) 
	
	//Start : IP Address (ip.dip) : 1E ~ 21 (4 byte) 
	printf("Destination IP Address : ");
	for(i=30; i<34; i++){
		printf("%02x ", packet[i]);
	}
	printf("\n");
	//End : IP Address (ip.dip) : 1E ~ 21 (4 byte) 
	///////////////////////////////////////////////////////////////////
	
	
	///////////////////////////////////////////////////////////////////
	//Start : Port Address (TCP.sport) : 22~23 (2 byte)
	printf("Source TCP Port : ");
	for(i=34; i<36; i++){
		printf("%02x ", packet[i]);
	}
	printf("\n");
	//End : Port Address (TCP.sport) : 22~23 (2 byte)
	
	//Start : Port Address (TCP.dport) : 24~25 (2 byte)
	printf("Destination TCP Port : ");
	for(i=36; i<38; i++){
		printf("%02x ", packet[i]);
	}
	printf("\n");
	//End : Port Address (TCP.dport) : 24~25 (2 byte)
	///////////////////////////////////////////////////////////////////
	
	
	
	///////////////////////////////////////////////////////////////////
	//Start : data (print 16 byte) : 36~46
	printf("Data : ");
	for(i=54; i<70; i++){
		printf("%02x ", packet[i]);
	}
	printf("\n");
	//End : data (print 16 byte) : 36~46
	///////////////////////////////////////////////////////////////////
	
    if (res == 0) continue;
    if (res == -1 || res == -2) break; // Failure to catch packets
    printf("%u bytes captured\n", header->caplen);
	printf("==========================================");
  }

  pcap_close(handle); // Close Handle
  return 0;
}
