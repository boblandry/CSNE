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
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
//struct tm *ltime;					//��ʱ�䴦���йصı���
// ����ԭ��
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
int SendArp(pcap_t *adhandle, char *ip, unsigned char *mac);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);
bool flag;

struct IpAddress
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

//28�ֽ�ARP֡�ṹ
struct arp_head
{
    unsigned short hardware_type; //Ӳ������
    unsigned short protocol_type; //Э������
    unsigned char hardware_add_len; //Ӳ����ַ����
    unsigned char protocol_add_len; //Э���ַ����
    unsigned short operation_field; //�����ֶ�
    unsigned char source_mac_add[6]; //Դmac��ַ
    unsigned long source_ip_add; //Դip��ַ
    unsigned char dest_mac_add[6]; //Ŀ��mac��ַ
    unsigned long dest_ip_add; //Ŀ��ip��ַ
};

//֡ͷ���ṹ�壬��14�ֽ�
struct ethernet_head
{
    unsigned char dest_mac_add[6]; //Ŀ��mac��ַ
    unsigned char source_mac_add[6]; //Դmac��ַ
    unsigned short type; //֡����
};

//arp���հ��ṹ
struct arp_packet
{
    struct ethernet_head ed;
    struct arp_head ah;
};

//IPͷ���ṹ�壬��20�ֽ�
struct IpHeader
{
    unsigned char Version_HLen;   //�汾��Ϣ4λ ��ͷ����4λ 1�ֽ�
    unsigned char TOS;                    //��������    1�ֽ�
    short Length;                              //���ݰ����� 2�ֽ�
    short Ident;                                 //���ݰ���ʶ  2�ֽ�
    short Flags_Offset;                    //��־3λ��Ƭƫ��13λ  2�ֽ�
    unsigned char TTL;                    //���ʱ��  1�ֽ�
    unsigned char Protocol;           //Э������  1�ֽ�
    short Checksum;                        //�ײ�У��� 2�ֽ�
    IpAddress SourceAddr;           //ԴIP��ַ   4�ֽ�
    IpAddress DestinationAddr;   //Ŀ��IP��ַ  4�ֽ�
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
    char Protocol;                                               //Э���  1�ֽ�
    unsigned short TcpLen;                           //TCP������ 2�ֽ�
};

struct sparam
{
    pcap_t *adhandle;
    char *ip;
    unsigned char *mac;
    char *netmask;
};
struct gparam
{
    pcap_t *adhandle;
};
struct sparam sp;
struct gparam gp;
//�������IP����ӦMAC��ַ��ӳ���
struct ip_mac_list
{
    int ip_add1;
    int ip_add2;
    int ip_add3;
    int ip_add4;
    unsigned char mac_add[6];
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
struct ip_mac_list lists[2560];
byte hostmac[6];//�Լ������MAC��ַ
int counts=0;//����ͳ�������ж�������
int main(){

	ethernet_head *ethernet;    //��̫��֡ͷ
    IpHeader *ip;                            //IPͷ
    TcpHeader *tcp;                      //TCPͷ
    PsdTcpHeader ptcp;             //TCPα�ײ�

	pcap_if_t  * alldevs;       //��������������
	pcap_if_t  *d1,*d2;					//ѡ�е�����������  d1Ϊ�������� d2Ϊ���Ͷ���
	char errbuf[PCAP_ERRBUF_SIZE];   //���󻺳���,��СΪ256
	char source[PCAP_ERRBUF_SIZE];
	unsigned char transmitbuffer[200];
	pcap_t *adhandle1,*adhandle2;           //��׽ʵ��,��pcap_open���صĶ���
	int i = 0;                            //��������������
	struct pcap_pkthdr *header;    //���յ������ݰ���ͷ��
    const u_char *pkt_data;			  //���յ������ݰ�������
	int res;                                    //��ʾ�Ƿ���յ������ݰ�
	u_int netmask;                       //����ʱ�õ���������
	char packet_filter[] = "tcp";        //�����ַ�
	struct bpf_program fcode;                     //pcap_compile�����õĽṹ��

	u_int ip_len;                                       //ip��ַ��Ч����
	u_short sport,dport;                        //�����ֽ�����
	u_char packet[100];                       //�������ݰ�Ŀ�ĵ�ַ
	pcap_dumper_t *dumpfile;         //���ļ�

	//time_t local_tv_sec;				//��ʱ�䴦���йصı���
    //char timestr[16];					//��ʱ�䴦���йصı���
    char *ip_addr;
    char *ip_netmask;
    unsigned char *ip_mac;
    HANDLE sendthread;
    HANDLE recvthread;

    ip_addr = (char *) malloc(sizeof(char) * 16); //�����ڴ���IP��ַ
	if (ip_addr == NULL)
	{
		printf("�����ڴ���IP��ַʧ��!\n");
		return -1;
	}
	ip_netmask = (char *) malloc(sizeof(char) * 16); //�����ڴ���NETMASK��ַ
	if (ip_netmask == NULL)
	{
		printf("�����ڴ���NETMASK��ַʧ��!\n");
		return -1;
	}
	ip_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //�����ڴ���MAC��ַ
	if (ip_mac == NULL)
	{
		printf("�����ڴ���MAC��ַʧ��!\n");
		return -1;
	}

	//��ȡ�����������б�
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf) == -1){
		//���Ϊ-1������ֻ�ȡ�������б�ʧ��
		fprintf(stderr,"Error in pcap_findalldevs_ex:\n",errbuf);
		//exit(0)���������˳�,exit(other)Ϊ�������˳�,���ֵ�ᴫ������ϵͳ
		exit(1);
	}
	//��ӡ�豸�б���Ϣ
	for(d1 = alldevs;d1 !=NULL;d1 = d1->next){
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n",++i,d1->name);
		if(d1->description){
			//��ӡ��������������Ϣ
			printf("description:%s\n",d1->description);
		}else{
			//������������������Ϣ
			printf("description:%s","no description\n");
		}
		//��ӡ���ػ��ص�ַ
		printf("\tLoopback: %s\n",(d1->flags & PCAP_IF_LOOPBACK)?"yes":"no");

		 pcap_addr_t *a;       //�����������ĵ�ַ�����洢����
		 for(a = d1->addresses;a;a = a->next){
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

    int num2;
	printf("������Ҫ�������ݵ�����:");
	//���û�ѡ��ѡ���ĸ�����������ץ��
	scanf("%d",&num2);
	printf("\n");

	//�û���������ֳ�������Χ
	if(num2<1||num2>i){
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//��ת��ѡ�е�������
	int j;
	for(d2=alldevs, j=0; j< num2-1 ; d2=d2->next, j++);

	//���е��˴�˵���û��������ǺϷ���
	if((adhandle2 = pcap_open(d2->name,		//�豸����
														65535,       //������ݰ������ݳ���
														PCAP_OPENFLAG_PROMISCUOUS,  //����ģʽ
														1000,           //��ʱʱ��
														NULL,          //Զ����֤
														errbuf         //���󻺳�
														)) == NULL){
        //��������ʧ��,��ӡ�����ͷ��������б�
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d2->name);
        // �ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
	}

	int num1;
	printf("������Ҫ�������ݵ�����:");
	//���û�ѡ��ѡ���ĸ�����������ץ��
	scanf("%d",&num1);
	printf("\n");

    if(num1<1||num1>i){
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//��ת��ѡ�е�������
	for(d1=alldevs, i=0; i< num1-1 ; d1=d1->next, i++);

	//���е��˴�˵���û��������ǺϷ���
	if((adhandle1 = pcap_open(d1->name,		//�豸����
														65535,       //������ݰ������ݳ���
														PCAP_OPENFLAG_PROMISCUOUS,  //����ģʽ
														1000,           //��ʱʱ��
														NULL,          //Զ����֤
														errbuf         //���󻺳�
														)) == NULL){
        //��������ʧ��,��ӡ�����ͷ��������б�
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d1->name);
        // �ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
	}


    //�û���������ֳ�������Χ

    //printf("11111111\n");

	//��ӡ���,���ڼ�����
	//printf("\nlistening on %s...\n", d1->description);

	//�������粻����̫��,�˴�ֻȡ�������
	if(pcap_datalink(adhandle1) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        //�ͷ��б�
        pcap_freealldevs(alldevs);
        return -1;
    }

	//�Ȼ�õ�ַ����������
	if(d1->addresses != NULL)
        //��ýӿڵ�һ����ַ������
        netmask=((struct sockaddr_in *)(d1->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        // ����ӿ�û�е�ַ����ô���Ǽ���һ��C�������
        netmask=0xffffff;

	//pcap_compile()��ԭ���ǽ��߲�Ĳ������˱�
	//��ʽ������ܹ����������������͵ĵͲ���ֽ���
	if(pcap_compile(adhandle1,	//�������������
										&fcode,
										packet_filter,   //����ip��UDP
										1,                       //�Ż���־
										netmask           //��������
										)<0)
	{
		//���˳�������
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        // �ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
	}

	//���ù�����
    if (pcap_setfilter(adhandle1, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        //�ͷ��豸�б�
        pcap_freealldevs(alldevs);
        return -1;
    }

    ifget(d2, ip_addr, ip_netmask); //��ȡ��ѡ�����Ļ�����Ϣ--IP��ַ--����
    GetSelfMac(adhandle2, ip_addr, ip_mac); //���������豸��������豸ip��ַ��ȡ���豸��MAC��ַ
    sp.adhandle = adhandle2;
    sp.ip = ip_addr;
    sp.mac = ip_mac;
    sp.netmask = ip_netmask;
    gp.adhandle = adhandle2;
    sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SendArpPacket,
                              &sp, 0, NULL);
    recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) GetLivePC, &gp,
                              0, NULL);
    printf("\n��ȡ����%d �ϵ�ip-macӳ���\n",num2);


    getchar();
    getchar();

    char cip[15];
    char realip[3];
    strcpy(cip,ip_addr);
    const char *mark=".";
    char *_ip;
    _ip=strtok(cip,mark);
    strcpy(realip,_ip);
    //printf("%s\n",realip);
    lists[counts].ip_add1=atoi(realip);
    //printf("byte1=%d\n",ip.SourceAddr.byte1);
    _ip=strtok(NULL,mark);
    strcpy(realip,_ip);
    lists[counts].ip_add2=atoi(realip);
    //printf("byte2=%d\n",ip.SourceAddr.byte2);
    _ip=strtok(NULL,mark);
    strcpy(realip,_ip);
    lists[counts].ip_add3=atoi(realip);
    //printf("byte3=%d\n",ip.SourceAddr.byte3);
    _ip=strtok(NULL,mark);
    strcpy(realip,_ip);
    lists[counts].ip_add4=atoi(realip);
    lists[counts].mac_add[0]=hostmac[0];
    lists[counts].mac_add[1]=hostmac[1];
    lists[counts].mac_add[2]=hostmac[2];
    lists[counts].mac_add[3]=hostmac[3];
    lists[counts].mac_add[4]=hostmac[4];
    lists[counts].mac_add[5]=hostmac[5];

    printf("����·��...\n");
    ethernet = (ethernet_head *) malloc(sizeof(char) * 14); //�����ڴ���ethernet
    if (ethernet == NULL)
    {
        printf("�����ڴ���ethernet֡ͷ��ַʧ��!\n");
        return -1;
    }

	//����pcap_next_ex���������ݰ�
	while((res = pcap_next_ex(adhandle1,&header,&pkt_data))>=0)
	{
		if(res ==0)
        {
			//����ֵΪ0����������ݰ���ʱ������ѭ����������
			printf("��ʱ...\n");
			continue;
		}
		else
        {
			//���е��˴�������ܵ����������ݰ�
			//headerΪ֡��ͷ��
			//printf("%.6ld len:%d ", header->ts.tv_usec, header->len);
			//�����̫��֡ͷ��
			ethernet=(ethernet_head *)pkt_data;
			// ���IP���ݰ�ͷ����λ��
			ip = (IpHeader *) (pkt_data +14);    //14Ϊ��̫��֡ͷ������
			//���TCPͷ����λ��
			ip_len = (ip->Version_HLen & 0xf) *4;
			//printf("ip_length:%d ",ip_len);


			tcp = (TcpHeader *)((u_char *)ip+ip_len);
			char * data;
            data = (char *)((u_char *)tcp+20);
			 //�������ֽ�����ת���������ֽ�����
			//sport = ntohs( tcp->SrcPort );
			//dport = ntohs( tcp->DstPort );
			//printf("srcport:%d desport:%d\n",sport,dport);
			//printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d\n",
			//		ip->SourceAddr.byte1,
              //  	ip->SourceAddr.byte2,
			//		ip->SourceAddr.byte3,
			//		ip->SourceAddr.byte4,
			//	    sport,
			//	    ip->DestinationAddr.byte1,
			//	    ip->DestinationAddr.byte2,
			//	    ip->DestinationAddr.byte3,
			//	    ip->DestinationAddr.byte4,
			//	    dport);
            //��ӡ����
			//printf("%s\n",data);
            u_int ip1=ip->DestinationAddr.byte1;
            u_int ip2=ip->DestinationAddr.byte2;
            u_int ip3=ip->DestinationAddr.byte3;
            u_int ip4=ip->DestinationAddr.byte4;
            int x=-1;
            boolean flag1=true;
            for (int j=counts; j>=0; j--)
            {
                if(lists[j].ip_add1==ip1 && lists[j].ip_add2==ip2 && lists[j].ip_add3==ip3 && lists[j].ip_add4==ip4)
                {
                    x=j;
                    printf("�ѷ��ָ�IP��ַ�����Ե�......\n");
                    break;
                }
                if (j==0 && x!=j)
                {
                    printf("Ŀ��IPδ����\n");
                    flag1=false;
                    break;
                }
            }
            if (flag1==false)
                continue;
            //�ṹ���ʼ��Ϊ0����

            //memset(&ethernet,0,sizeof(ethernet));
            ethernet_head eh;
            IpHeader s_ip;
            TcpHeader s_tcp;
            memset(&transmitbuffer,0,200);
            byte destmac[6];
            //����MAC��Ŀ�ĵ�ַ
            destmac[0]=lists[x].mac_add[0];
            destmac[1]=lists[x].mac_add[1];
            destmac[2]=lists[x].mac_add[2];
            destmac[3]=lists[x].mac_add[3];
            destmac[4]=lists[x].mac_add[4];
            destmac[5]=lists[x].mac_add[5];
            eh.dest_mac_add[0]=destmac[0];
            eh.dest_mac_add[1]=destmac[1];
            eh.dest_mac_add[2]=destmac[2];
            eh.dest_mac_add[3]=destmac[3];
            eh.dest_mac_add[4]=destmac[4];
            eh.dest_mac_add[5]=destmac[5];
            eh.source_mac_add[0]=hostmac[0];
            eh.source_mac_add[1]=hostmac[1];
            eh.source_mac_add[2]=hostmac[2];
            eh.source_mac_add[3]=hostmac[3];
            eh.source_mac_add[4]=hostmac[4];
            eh.source_mac_add[5]=hostmac[5];
            //memcpy(ethernet->dest_mac_add,destmac,6);
            //memcpy(ethernet->source_mac_add,hostmac,6);
            //�ϲ�Э�����ͣ�0x0800����IPЭ��
            eh.type=htons(0x0800);
            //��ֵSendBuffer
            memcpy(&transmitbuffer,&eh,sizeof(struct ethernet_head));

            s_ip.DestinationAddr.byte1=ip->DestinationAddr.byte1;
            s_ip.DestinationAddr.byte2=ip->DestinationAddr.byte2;
            s_ip.DestinationAddr.byte3=ip->DestinationAddr.byte3;
            s_ip.DestinationAddr.byte4=ip->DestinationAddr.byte4;
            s_ip.SourceAddr.byte1=ip->SourceAddr.byte1;
            s_ip.SourceAddr.byte2=ip->SourceAddr.byte2;
            s_ip.SourceAddr.byte3=ip->SourceAddr.byte3;
            s_ip.SourceAddr.byte4=ip->SourceAddr.byte4;
            s_ip.Flags_Offset=0;
            s_ip.Version_HLen=0x45;
            s_ip.Ident=htons(1);
            s_ip.Length=htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(data));
            s_ip.Protocol=6;
            s_ip.TOS=0;
            s_ip.TTL=128;
            s_ip.Checksum=0;
            memcpy(&transmitbuffer[sizeof(struct ethernet_head)], &s_ip, 20);

            s_tcp.DstPort= htons(102);
            s_tcp.SrcPort= htons(1000);
            s_tcp.SequenceNum= htonl(11);
            s_tcp.Acknowledgment=0;
            s_tcp.HdrLen=0x50;
            s_tcp.Flags=0x18;
            s_tcp.AdvertisedWindow=htons(512);
            s_tcp.UrgPtr=0;
            s_tcp.Checksum=0;
            memcpy(&transmitbuffer[sizeof(struct ethernet_head) + 20], &s_tcp, 20);
            //��ֵα�ײ�
            ptcp.SourceAddr = s_ip.SourceAddr;
            ptcp.DestinationAddr = s_ip.DestinationAddr;
            ptcp.Zero = 0;
            ptcp.Protocol = 6;
            ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(data));
            //������ʱ�洢��������������У���
            char TempBuffer[65535];
            memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
            memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
            memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), data, strlen(data));
            //����TCP��У���
            s_tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(data));
            //���°�SendBuffer��ֵ����Ϊ��ʱУ����Ѿ��ı䣬��ֵ�µ�
            memcpy(transmitbuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader), &s_tcp, sizeof(struct TcpHeader));
            memcpy(transmitbuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), data, strlen(data));
            //��ʼ��TempBufferΪ0���У��洢����������IPУ���
            memset(TempBuffer, 0, sizeof(TempBuffer));
            memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
            //����IPУ���
            s_ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
            //���°�SendBuffer��ֵ��IPУ����Ѿ��ı�
            memcpy(transmitbuffer + sizeof(struct ethernet_head), &s_ip, sizeof(struct IpHeader));

            int totalsize =sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(data);
            int result = pcap_sendpacket(adhandle2,transmitbuffer,totalsize);
            if (result != 0)
            {
                printf("Transmit Error!\n");
            }
            else
            {
                //printf("Transmit TCP Packet.\n");
                //printf("Destination Port:%d\n", ntohs(tcp.DstPort));
                //printf("Source Port:%d\n", ntohs(tcp.SrcPort));
                //printf("Sequence:%d\n", ntohl(tcp.SequenceNum));
                //printf("Acknowledgment:%d\n", ntohl(tcp.Acknowledgment));
                //printf("Header Length:%d*4\n", tcp.HdrLen >> 4);
                //printf("Flags:0x%0x\n", tcp.Flags);
                //rintf("AdvertiseWindow:%d\n", ntohs(tcp.AdvertisedWindow));
                //printf("UrgPtr:%d\n", ntohs(tcp.UrgPtr));
                //printf("Checksum:%u\n", ntohs(tcp.Checksum));
                printf("Transmit Successfully!\n");
            }
        }

	}



	//�ͷ������������б�
	pcap_freealldevs(alldevs);

	int inum;
	scanf("%d", &inum);

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
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
    socklen_t sockaddrlen;
#ifdef WIN32
    sockaddrlen = sizeof(struct sockaddr_in6);
#else
    sockaddrlen = sizeof(struct sockaddr_storage);
#endif

    if (getnameinfo(sockaddr, sockaddrlen, address, addrlen, NULL, 0,
                    NI_NUMERICHOST) != 0)
        address = NULL;
    return address;
}

void ifget(pcap_if_t *d2, char *ip_addr, char *ip_netmask)
{
    pcap_addr_t *a;
    //char ip6str[128];
    /* IP addresses */
    /*pcap_if_t��һ�������豸��һ���ṹ��
    	�������� pcap_if *  next   ָ����һ����������ָ��
    					char *  name       ������������
    					char *  description  ������������
    					pcap_addr *  addresses   ��������Ӧ��IP��ַ
    					u_int  flags              �������ı�ʶ����һ����ܵ�ֵΪPCAP_IF_LOOPBACK��
    */
    /*
    struct pcap_addr {
    	struct pcap_addr *next;    ָ����һ��Ԫ�ص�ָ��
    	struct sockaddr *addr;      IP��ַ
    	struct sockaddr *netmask;    ��������
    	struct sockaddr *broadaddr; �㲥��ַ
    	struct sockaddr *dstaddr;    P2PĿ�ĵ�ַ
    };
    */
    //�������еĵ�ַ,a����һ��pcap_addr
    for (a = d2->addresses; a; a = a->next)
    {
        switch (a->addr->sa_family)
        {
        case AF_INET:  //sa_family ����2�ֽڵĵ�ַ���壬һ�㶼�ǡ�AF_xxx������ʽ��ͨ���õĶ���AF_INET������IPV4
            if (a->addr)
            {
                char *ipstr;
                //����ַת��Ϊ�ַ���
                ipstr = iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr); //*ip_addr
                memcpy(ip_addr, ipstr,16);
            }
            if (a->netmask)
            {
                char *netmaskstr;
                netmaskstr = iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr);
                memcpy(ip_netmask, netmaskstr,16);
            }
        case AF_INET6:
            break;
        }
    }
}
/* ��ȡ�Լ�������MAC��ַ */
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac)
{
    unsigned char sendbuf[42]; //arp���ṹ��С
    int i = -1;
    int res;
    struct ethernet_head eh;
    struct arp_head ah;
    struct pcap_pkthdr * pkt_header;
    const u_char * pkt_data;
    //���ѿ����ڴ�ռ� eh.dest_mac_add ���� 6���ֽڵ�ֵ��Ϊֵ 0xff��
    memset(eh.dest_mac_add, 0xff, 6); //Ŀ�ĵ�ַΪȫΪ�㲥��ַ
    memset(eh.source_mac_add, 0x0f, 6);
    memset(ah.source_mac_add, 0x0f, 6);
    memset(ah.dest_mac_add, 0x00, 6);
    //htons��һ���޷��Ŷ����͵�������ֵת��Ϊ�����ֽ�˳��
    eh.type = htons(ETH_ARP);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_add_len = 6;
    ah.protocol_add_len = 4;
    ah.source_ip_add = inet_addr("100.100.100.100"); //����������ip
    ah.operation_field = htons(ARP_REQUEST);
    ah.dest_ip_add = inet_addr(ip_addr);
    memset(sendbuf, 0, sizeof(sendbuf));
    memcpy(sendbuf, &eh, sizeof(eh));
    memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
    if (pcap_sendpacket(adhandle, sendbuf, 42) == 0)
    {
        printf("\nPacketSend succeed\n");
    }
    else
    {
        printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
        return 0;
    }
    while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
    {
        if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP)
                && *(unsigned short*) (pkt_data + 20) == htons(ARP_REPLY)
                && *(unsigned long*) (pkt_data + 38)
                == inet_addr("100.100.100.100"))
        {
            for (i = 0; i < 6; i++)
            {
                ip_mac[i] = *(unsigned char *) (pkt_data + 22 + i);
                hostmac[i]=ip_mac[i];
            }
            printf("��ȡ�Լ�������MAC��ַ�ɹ�!\n");
            break;
        }
    }
    if (i == 6)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/* ������������п��ܵ�IP��ַ����ARP������߳� */
DWORD WINAPI SendArpPacket(LPVOID lpParameter) //(pcap_t *adhandle,char *ip,unsigned char *mac,char *netmask)
{
    sparam *spara = (sparam *) lpParameter;
    pcap_t *adhandle = spara->adhandle;
    char *ip = spara->ip;
    unsigned char *mac = spara->mac;
    char *netmask = spara->netmask;
    printf("ip_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
    printf("�����IP��ַΪ:%s\n", ip);
    printf("��ַ����NETMASKΪ:%s\n", netmask);
    printf("\n");
    unsigned char sendbuf[42]; //arp���ṹ��С
    struct ethernet_head eh;
    struct arp_head ah;
    memset(eh.dest_mac_add, 0xff, 6); //Ŀ�ĵ�ַΪȫΪ�㲥��ַ
    memcpy(eh.source_mac_add, mac, 6);
    memcpy(ah.source_mac_add, mac, 6);
    memset(ah.dest_mac_add, 0x00, 6);
    eh.type = htons(ETH_ARP);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_add_len = 6;
    ah.protocol_add_len = 4;
    ah.source_ip_add = inet_addr(ip); //���󷽵�IP��ַΪ�����IP��ַ
    ah.operation_field = htons(ARP_REQUEST);
    //��������ڹ㲥����arp��
    unsigned long myip = inet_addr(ip);
    unsigned long mynetmask = inet_addr(netmask);
    unsigned long hisip = htonl((myip & mynetmask));
    for (int i = 0; i < HOSTNUM; i++)
    {
        ah.dest_ip_add = htonl(hisip + i);
        memset(sendbuf, 0, sizeof(sendbuf));
        memcpy(sendbuf, &eh, sizeof(eh));
        memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
        if (pcap_sendpacket(adhandle, sendbuf, 42) == 0)
        {
            //printf("\nPacketSend succeed\n");
        }
        else
        {
            printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
        }
        Sleep(50);
    }
    Sleep(1000);
    flag = TRUE;
    return 0;
}

/* �������������ݰ���ȡ�������IP��ַ */
DWORD WINAPI GetLivePC(LPVOID lpParameter) //(pcap_t *adhandle)
{

    gparam *gpara = (gparam *) lpParameter;
    pcap_t *adhandle = gpara->adhandle;
    int res;
    unsigned char Mac[6];
    struct pcap_pkthdr * pkt_header;
    const u_char * pkt_data;
    while (true)
    {
        if (flag)
        {
            printf("��ȡip-macӳ���ɹ���\n");
            printf("ɨ����ϣ���������˳�!\n");
            break;
        }
        if ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0)
        {
            if (*(unsigned short *) (pkt_data + 12) == htons(ETH_ARP))
            {
                struct arp_packet *recv = (arp_packet *) pkt_data;
                if (*(unsigned short *) (pkt_data + 20) == htons(ARP_REPLY))
                {
                    printf("-------------------------------------------\n");
                    printf("IP��ַ:%d.%d.%d.%d   MAC��ַ:",
                           recv->ah.source_ip_add & 255,
                           recv->ah.source_ip_add >> 8 & 255,
                           recv->ah.source_ip_add >> 16 & 255,
                           recv->ah.source_ip_add >> 24 & 255);
                    //printf("%d",recv->ah.source_ip_add);
                    lists[counts].ip_add1=(recv->ah.source_ip_add & 255);
                    lists[counts].ip_add2=(recv->ah.source_ip_add >> 8 & 255);
                    lists[counts].ip_add3=(recv->ah.source_ip_add >> 16 & 255);
                    lists[counts].ip_add4=(recv->ah.source_ip_add >> 24 & 255);
                    //memcpy(lists[counts]->ip_add,*(unsigned long *)recv->ah.source_ip_add,sizeof(recv->ah.source_ip_add));
                    //lists[counts]->mac_add=recv->ah.source_mac_add;
                    //memcpy(lists[counts].mac_add,recv->ah.source_mac_add,sizeof(recv->ah.source_mac_add));
                    for (int i = 0; i < 6; i++)
                    {
                        Mac[i] = *(unsigned char *) (pkt_data + 22 + i);
                        //packet[i]=Mac[i];
                        lists[counts].mac_add[i]=Mac[i];
                        printf("%02x", Mac[i]);
                    }
                    printf("\n");
                    counts++;
                }
            }
        }
        Sleep(10);
    }
    return 0;
}
