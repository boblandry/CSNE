
#define WINVER 0x0501
#define HAVE_REMOTE
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include "pcap.h"
using namespace std;

#pragma pack(1)  //��һ���ֽ��ڴ����
#define IPTOSBUFFERS    12
#define ETH_ARP         0x0806  //��̫��֡���ͱ�ʾ�������ݵ����ͣ�����ARP�����Ӧ����˵�����ֶε�ֵΪx0806
#define ARP_HARDWARE    1  //Ӳ�������ֶ�ֵΪ��ʾ��̫����ַ
#define ETH_IP          0x0800  //Э�������ֶα�ʾҪӳ���Э���ַ����ֵΪx0800��ʾIP��ַ
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define HOSTNUM         255
char *iptos(u_long in);       //u_long��Ϊ unsigned long

//IP��ַ��ʽ
struct IpAddress
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

//֡ͷ���ṹ�壬��14�ֽ�
struct EthernetHeader
{
    u_char DestMAC[6];    //Ŀ��MAC��ַ 6�ֽ�
    u_char SourMAC[6];   //ԴMAC��ַ 6�ֽ�
    u_short EthType;         //��һ��Э�����ͣ���0x0800������һ����IPЭ�飬0x0806Ϊarp  2�ֽ�
};

//IPͷ���ṹ�壬��20�ֽ�
struct IpHeader
{
    unsigned char Version_HLen;   //�汾��Ϣ4λ ��ͷ����4λ 1�ֽ�
    unsigned char TOS;                    //��������    1�ֽ�
    short Length;                              //���ݰ����� 2�ֽ�
    short Ident;                                 //���ݰ���ʶ  2�ֽ�
    short Flags_Offset;                    //��־3λ��Ƭƫ��13λ  2�ֽ�
    unsigned char TTL;                   //���ʱ��  1�ֽ�
    unsigned char Protocol;          //Э������  1�ֽ�
    short Checksum;                       //�ײ�У��� 2�ֽ�
	IpAddress SourceAddr;       //ԴIP��ַ   4�ֽ�
	IpAddress DestinationAddr; //Ŀ��IP��ַ  4�ֽ�
};

//TCPͷ���ṹ�壬��20�ֽ�
struct TcpHeader
{
    unsigned short SrcPort;                        //Դ�˿ں�  2�ֽ�
    unsigned short DstPort;                        //Ŀ�Ķ˿ں� 2�ֽ�
    unsigned int SequenceNum;               //���  4�ֽ�
    unsigned int Acknowledgment;         //ȷ�Ϻ�  4�ֽ�
    unsigned char HdrLen;                         //�ײ�����4λ������λ6λ ��10λ
    unsigned char Flags;                              //��־λ6λ
    unsigned short AdvertisedWindow;  //���ڴ�С16λ 2�ֽ�
    unsigned short Checksum;                  //У���16λ   2�ֽ�
    unsigned short UrgPtr;						  //����ָ��16λ   2�ֽ�
};

//TCPα�ײ��ṹ�� 12�ֽ�
struct PsdTcpHeader
{
	IpAddress SourceAddr;                     //ԴIP��ַ  4�ֽ�
	IpAddress DestinationAddr;             //Ŀ��IP��ַ 4�ֽ�
    char Zero;                                                    //���λ  1�ֽ�
    char Protcol;                                               //Э���  1�ֽ�
    unsigned short TcpLen;                           //TCP������ 2�ֽ�
};

//���У��͵ķ���
unsigned short checksum(unsigned short *data, int length)
{
    unsigned long temp = 0;
    while (length > 1)
    {
        temp +=  *data++;
        length -= sizeof(unsigned short);
    }
    if (length)
    {
        temp += *(unsigned short*)data;
    }
    temp = (temp >> 16) + (temp &0xffff);
    temp += (temp >> 16);
    return (unsigned short)(~temp);
}


int main(){

	struct EthernetHeader ethernet;    //��̫��֡ͷ
    struct IpHeader ip;                            //IPͷ
    struct TcpHeader tcp;                      //TCPͷ
    struct PsdTcpHeader ptcp;             //TCPα�ײ�

	unsigned char SendBuffer[200];       //���Ͷ���
	char TcpData[] = "Routing Test!!!!!!!!!!!";  //��������

	pcap_if_t  * alldevs;       //��������������
	pcap_if_t  *d;					//ѡ�е�����������
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	pcap_t *adhandle;           //��׽ʵ��,��pcap_open���صĶ���
	int i = 0;                            //��������������


	//��ȡ�����������б�
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf) == -1){
		//���Ϊ-1������ֻ�ȡ�������б�ʧ��
		fprintf(stderr,"Error in pcap_findalldevs_ex:\n",errbuf);
		//exit(0)���������˳�,exit(other)Ϊ�������˳�,���ֵ�ᴫ������ϵͳ
		exit(1);
	}


	for(d = alldevs;d !=NULL;d = d->next){
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n",++i,d->name);
		if(d->description){
			//��ӡ��������������Ϣ
			printf("description:%s\n",d->description);
		}else{
			//������������������Ϣ
			printf("description:%s","no description\n");
		}
		//��ӡ���ػ��ص�ַ
		 printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");
		 /**
		 pcap_addr *  next     ָ����һ����ַ��ָ��
		 sockaddr *  addr       IP��ַ
		 sockaddr *  netmask  ��������
		 sockaddr *  broadaddr   �㲥��ַ
		 sockaddr *  dstaddr        Ŀ�ĵ�ַ
		 */
		 pcap_addr_t *a;       //�����������ĵ�ַ�����洢����
		 for(a = d->addresses;a;a = a->next){
			 //sa_family�����˵�ַ������,��IPV4��ַ���ͻ���IPV6��ַ����
			 switch (a->addr->sa_family)
			 {
				 case AF_INET:  //����IPV4���͵�ַ
					 printf("Address Family Name:AF_INET\n");
					 if(a->addr){
						 //->�����ȼ���ͬ������,����ǿ������ת��,��ΪaddrΪsockaddr���ͣ�������в�����ת��Ϊsockaddr_in����
						 printf("Address:%s\n",iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
					 }
					if (a->netmask){
						 printf("\tNetmask: %s\n",iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
					}
					if (a->broadaddr){
						   printf("\tBroadcast Address: %s\n",iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
					 }
					 if (a->dstaddr){
						   printf("\tDestination Address: %s\n",iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
					 }
        			 break;
				 case AF_INET6: //����IPV6���͵�ַ
					 printf("Address Family Name:AF_INET6\n");
					 printf("this is an IPV6 address\n");
					 break;
				 default:
					 break;
			 }
		 }
	}
	//iΪ0��������ѭ��δ����,��û���ҵ�������,���ܵ�ԭ��ΪWinpcapû�а�װ����δɨ�赽
	if(i == 0){
		printf("interface not found,please check winpcap installation");
	}

	int num;
	printf("Enter the interface number(1-%d):",i);
	//���û�ѡ��ѡ���ĸ�����������ץ��
	scanf("%d",&num);
	printf("\n");

	//�û���������ֳ�������Χ
	if(num<1||num>i){
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//��ת��ѡ�е�������
	for(d=alldevs, i=0; i< num-1 ; d=d->next, i++);

	//���е��˴�˵���û��������ǺϷ���
	if((adhandle = pcap_open(d->name,		//�豸����
														65535,       //������ݰ������ݳ���
														PCAP_OPENFLAG_PROMISCUOUS,  //����ģʽ
														1000,           //��ʱʱ��
														NULL,          //Զ����֤
														errbuf         //���󻺳�
														)) == NULL){
        //��������ʧ��,��ӡ�����ͷ��������б�
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        // �ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
	}

	//�ṹ���ʼ��Ϊ0����
    memset(&ethernet, 0, sizeof(ethernet));
    BYTE destmac[8];
	//Ŀ��MAC��ַ
    destmac[0] = 0x10;
    destmac[1] = 0xbf;
    destmac[2] = 0x48;
    destmac[3] = 0x08;
    destmac[4] = 0x7c;
    destmac[5] = 0x19;
	//��ֵĿ��MAC��ַ
    memcpy(ethernet.DestMAC, destmac, 6);
    BYTE hostmac[8];
	//ԴMAC��ַ
    hostmac[0] = 0x26;
    hostmac[1] = 0xdb;
    hostmac[2] = 0xc9;
    hostmac[3] = 0x33;
    hostmac[4] = 0xc8;
    hostmac[5] = 0xbd;
	//��ֵԴMAC��ַ
    memcpy(ethernet.SourMAC, hostmac, 6);
	//�ϲ�Э������,0x0800����IPЭ��
    ethernet.EthType = htons(0x0800);
	//��ֵSendBuffer
    memcpy(&SendBuffer, &ethernet, sizeof(struct EthernetHeader));
	//��ֵIPͷ����Ϣ
    ip.Version_HLen = 0x45;
    ip.TOS = 0;
    ip.Length = htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
    ip.Ident = htons(1);
    ip.Flags_Offset = 0;
    ip.TTL = 128;
    ip.Protocol = 6;
    ip.Checksum = 0;
	//ԴIP��ַ
	ip.SourceAddr.byte1 = 172;
	ip.SourceAddr.byte2 = 29;
	ip.SourceAddr.byte3 = 7;
	ip.SourceAddr.byte4 = 1;
	//Ŀ��IP��ַ
	ip.DestinationAddr.byte1 = 211;
	ip.DestinationAddr.byte2 = 87;
	ip.DestinationAddr.byte3 = 229;
	ip.DestinationAddr.byte4 = 11;
	//��ֵSendBuffer
    memcpy(&SendBuffer[sizeof(struct EthernetHeader)], &ip, 20);
	//��ֵTCPͷ������
    tcp.DstPort = htons(102);
    tcp.SrcPort = htons(1000);
    tcp.SequenceNum = htonl(11);
    tcp.Acknowledgment = 0;
    tcp.HdrLen = 0x50;
    tcp.Flags = 0x18;
    tcp.AdvertisedWindow = htons(512);
    tcp.UrgPtr = 0;
    tcp.Checksum = 0;
	//��ֵSendBuffer
    memcpy(&SendBuffer[sizeof(struct EthernetHeader) + 20], &tcp, 20);
	//��ֵα�ײ�
    ptcp.SourceAddr = ip.SourceAddr;//
    ptcp.DestinationAddr = ip.DestinationAddr;
    ptcp.Zero = 0;
    ptcp.Protcol = 6;
    ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(TcpData));
	//������ʱ�洢��������������У���
    char TempBuffer[65535];
    memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
    memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
    memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	//����TCP��У���
    tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
	//���°�SendBuffer��ֵ����Ϊ��ʱУ����Ѿ��ı䣬��ֵ�µ�
    memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader), &tcp, sizeof(struct TcpHeader));
    memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	//��ʼ��TempBufferΪ0���У��洢����������IPУ���
    memset(TempBuffer, 0, sizeof(TempBuffer));
    memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
	//����IPУ���
    ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
	//���°�SendBuffer��ֵ��IPУ����Ѿ��ı�
    memcpy(SendBuffer + sizeof(struct EthernetHeader), &ip, sizeof(struct IpHeader));
	//�������еĳ���
	int size1 = sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData);
	int result = pcap_sendpacket(adhandle, SendBuffer,size1);
	if (result != 0)
    {
        printf("Send Error!\n");
    }
    else
    {
        printf("Send TCP Packet.\n");
        printf("Destination Port:%d\n", ntohs(tcp.DstPort));
        printf("Source Port:%d\n", ntohs(tcp.SrcPort));
        printf("Sequence:%d\n", ntohl(tcp.SequenceNum));
        printf("Acknowledgment:%d\n", ntohl(tcp.Acknowledgment));
        printf("Header Length:%d*4\n", tcp.HdrLen >> 4);
        printf("Flags:0x%0x\n", tcp.Flags);
        printf("AdvertiseWindow:%d\n", ntohs(tcp.AdvertisedWindow));
        printf("UrgPtr:%d\n", ntohs(tcp.UrgPtr));
        printf("Checksum:%u\n", ntohs(tcp.Checksum));
		printf("Send Successfully!");
    }
	//�ͷ������������б�
	pcap_freealldevs(alldevs);

	int scan;
	scanf("%d",&scan);

	return 0;

}

/* ���������͵�IP��ַת�����ַ������͵� */
#define IPTOSBUFFERS    12
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3*4+3+1];
    static short which;
    u_char *p;

    p = (u_char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}
