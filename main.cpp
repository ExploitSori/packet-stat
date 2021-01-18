#include<stdio.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include<arpa/inet.h>
#include<vector>
#include<string>
#include<map>
using namespace std;
typedef struct endpoint{
	int txCnt;
	int rxCnt;
	int txByte;
	int rxByte;

}endpoint;
std::map<std::string,endpoint*> IPv4_Endpoints(pcap_t *pc){
	struct pcap_pkthdr *header;
	std::map<std::string,endpoint*> m;
	const u_char *data;
	int packetCount = 0;
	while (int returnValue = pcap_next_ex(pc, &header, &data) >= 0){
		struct ip *ipv4_hdr;
	        ipv4_hdr = (struct ip*)(data+14);
		std::string src(inet_ntoa(ipv4_hdr->ip_src));
		if(m.find(src) == m.end()){
			endpoint* tmp1 = (endpoint*)malloc(sizeof(endpoint));
			tmp1->txCnt  = 1;
			tmp1->rxCnt  = 0;
			tmp1->txByte = header->len;
			tmp1->rxByte = 0;
			m.insert(pair<std::string, endpoint*>(src, tmp1) );
		}
		else{
			m[src]->txCnt  += 1;
			m[src]->txByte += header->len;
		}

		std::string dst(inet_ntoa(ipv4_hdr->ip_dst));
		if(m.find(dst) == m.end()){
			endpoint* tmp2 = (endpoint*)malloc(sizeof(endpoint));
			tmp2->txCnt  = 0;
			tmp2->rxCnt  = 1;
			tmp2->txByte = 0;
			tmp2->rxByte = header->len;
			m.insert(pair<std::string,endpoint*>(dst,tmp2));
		}
		else{
			m[dst]->rxCnt  += 1;
			m[dst]->rxByte += header->len;
		}
	}
	return m;
}
void printIPv4(std::map<std::string,endpoint*> tm){
	printf("ip\t\t Tx Packet\t Tx Byte\t Rx Packet\t Rx Byte\t\n");
	for(auto &kv : tm){
		printf("%s\t %d\t\t %d\t\t %d\t\t %d\t\t\n",
				kv.first.c_str(),
				kv.second->txCnt,
				kv.second->txByte,
				kv.second->rxCnt,
				kv.second->rxByte);
	}
}
void run(){
	printf("\n");
}
int main(int argv, char** args){
	if(argv < 2){
		printf("%s <pcap_file>\n",args[0]);
		return 0;
	}
	std::map<std::string,endpoint*> tm;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pc = pcap_open_offline(args[1], errbuf);
	tm = IPv4_Endpoints(pc);
	printIPv4(tm);
	return 0;
}
