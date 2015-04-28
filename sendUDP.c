#define HAVE_REMOTE

#include <pcap.h>
#pragma comment(lib, "wpcap.lib")
#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")


//typedef void(* pcap_handler)(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
void my_pcap_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);

#define ETHER_ADDR_LEN 6
//from linux's ethernet.h
#define ETHERTYPE_PUP           0x0200          /* Xerox PUP */
#define ETHERTYPE_SPRITE        0x0500          /* Sprite */
#define ETHERTYPE_IP            0x0800          /* IP */
#define ETHERTYPE_ARP           0x0806          /* Address resolution */
#define ETHERTYPE_REVARP        0x8035          /* Reverse ARP */
#define ETHERTYPE_AT            0x809B          /* AppleTalk protocol */
#define ETHERTYPE_AARP          0x80F3          /* AppleTalk ARP */
#define ETHERTYPE_VLAN          0x8100          /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX           0x8137          /* IPX */
#define ETHERTYPE_IPV6          0x86dd          /* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK      0x9000          /* used to test interfaces */

struct   ether_header{
	u_char   ether_dhost[ETHER_ADDR_LEN];
	u_char   ether_shost[ETHER_ADDR_LEN];
	u_short   ether_type;  //�����һ��ΪIPЭ�顣��ether_type��ֵ����0x0800
};

char* prase_ether_host(u_char ether_host[ETHER_ADDR_LEN], char* buffer);

struct ip_header  //С��ģʽ__LITTLE_ENDIAN
{
	unsigned   char		ihl:4;				//ip   header   length
	unsigned   char		version:4;			//version
	u_char				tos;				//type   of   service
	u_short				tot_len;			//total   length
	u_short				id;					//identification
	u_short				frag_off;			//fragment   offset
	u_char				ttl;				//time   to   live
	u_char				protocol;			//protocol   type
	u_short				check;				//check   sum
	u_int				saddr;				//source   address
	u_int				daddr;				//destination   address
};


struct tcphdr //С��ģʽ__LITTLE_ENDIAN
{
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t res1:4;
    u_int16_t doff:4;
    u_int16_t fin:1;
    u_int16_t syn:1;
    u_int16_t rst:1;
    u_int16_t psh:1;
    u_int16_t ack:1;
    u_int16_t urg:1;
    u_int16_t res2:2;
    u_int16_t window;
    u_int16_t check;
    u_int16_t urg_ptr;
};



struct udphdr
{
  u_int16_t source;         /* source port */
  u_int16_t dest;			/* destination port */
  u_int16_t len;            /* udp length */
  u_int16_t checkl;         /* udp checksum */
};

char* uint_to_addr(u_int addr);

u_int16_t in_cksum (u_int16_t * addr, int len)
{
	int     nleft = len;
	u_int32_t sum = 0;
	u_int16_t *w = addr;
	u_int16_t answer = 0;

	/*
	* Our algorithm is simple, using a 32 bit accumulator (sum), we add
	* sequential 16 bit words to it, and at the end, fold back all the
	* carry bits from the top 16 bits into the lower 16 bits.
	*/
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		* (unsigned char *) (&answer) = * (unsigned char *) w;
		sum += answer;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);     /* add carry */
	answer = ~sum;     /* truncate to 16 bits */
	return (answer);
}

struct Psd_Header {
	ULONG sourceip; //ԴIP��ַ
	ULONG destip; //Ŀ��IP��ַ
	BYTE mbz; //�ÿ�(0)
	BYTE ptcl; //Э������
	USHORT plen; //TCP/UDP���ݰ��ĳ���(����TCP/UDP��ͷ�������ݰ������ĳ��� ��λ:�ֽ�)
};

har* device = "//Device//NPF_{06864041-9387-44DC-AF44-37779B0F2E9E}";
pcap_t* adhandle = NULL;
char errbuf[PCAP_ERRBUF_SIZE] = { 0 };

void main()
{
	if((adhandle = pcap_open(device, 0x10000, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		printf("[pcap_open error] : %s/n", errbuf);
		return;
	}

	char buffer[64] = { 0 };

	ether_header* pether_header =	(ether_header*)buffer;
	ip_header* pip_herder		=	(ip_header*)(buffer + sizeof(ether_header));
	udphdr* pudp_herder			=	(udphdr*)(buffer + sizeof(ether_header) + sizeof(ip_header));

	pether_header->ether_dhost[0] = 1;		//0x0 * 16 + 0x0;;
	pether_header->ether_dhost[1] = 1;		//0x2 * 16 + 0x1;
	pether_header->ether_dhost[2] = 1;		//0x2 * 16 + 0x7;
	pether_header->ether_dhost[3] = 1;		//0x2 * 16 + 0x3;
	pether_header->ether_dhost[4] = 1;		//0x7 * 16 + 0x2;
	pether_header->ether_dhost[5] = 1;		//0xf * 16 + 0xe;

	pether_header->ether_shost[0] = 1;		//0x0 * 16 + 0x0;;
	pether_header->ether_shost[1] = 1;		//0x1 * 16 + 0xF;
	pether_header->ether_shost[2] = 1;		//0xD * 16 + 0x0;
	pether_header->ether_shost[3] = 1;		//0x1 * 16 + 0x6;
	pether_header->ether_shost[4] = 1;		//0x6 * 16 + 0x3;
	pether_header->ether_shost[5] = 1;		//0x7 * 16 + 0x1;


	pether_header->ether_type = htons(ETHERTYPE_IP);

	//����IP����ͷ
	if((sizeof(ip_header) % 4) != 0)
	{
		printf("[IP Header error]/n");
		return;
	}

	pip_herder->ihl = sizeof(ip_header) / 4;
	pip_herder->version = 4;
	pip_herder->tos = 0;
	pip_herder->tot_len = htons(sizeof(buffer) - sizeof(ether_header));
	pip_herder->id = htons(0x1000);
	pip_herder->frag_off = htons(0);
	pip_herder->ttl = 0x80;
	pip_herder->protocol = IPPROTO_UDP;
	pip_herder->check = 0;
	pip_herder->saddr = inet_addr("192.168.18.*");
	pip_herder->daddr = inet_addr("122.*.*.*");
	pip_herder->check  = in_cksum((u_int16_t*)pip_herder, sizeof(ip_header));

	//����UDP����ͷ;
	pudp_herder->dest = htons(7865);
	pudp_herder->source = htons(2834);
	pudp_herder->len = htons(sizeof(buffer) - sizeof(ether_header) - sizeof(ip_header));
	pudp_herder->checkl = 0;

	//����αUDP�ײ�

	//pudp_herder->checkl  = in_cksum((u_int16_t*)pudp_herder, 24);

	char buffer2[64] = { 0 };
	Psd_Header* psd = (Psd_Header*)buffer2;
	psd->sourceip = inet_addr("192.168.18.*");
	psd->destip = inet_addr("122.*.*.*");
	psd->ptcl = IPPROTO_UDP;
	psd->plen =  htons(sizeof(buffer) - sizeof(ether_header) - sizeof(ip_header));
	psd->mbz = 0;

	memcpy(buffer2 + sizeof(Psd_Header), (void*)pudp_herder, sizeof(buffer) - sizeof(ether_header) - sizeof(ip_header));
	pudp_herder->checkl  = in_cksum((u_int16_t *)buffer2,
		sizeof(buffer) - sizeof(ether_header) - sizeof(ip_header) + sizeof(Psd_Header));


	if(pcap_sendpacket(adhandle, (const u_char*)buffer, 64) == -1)
	{
		printf("[pcap_sendpacket error]/n");
		return;
	}
}
