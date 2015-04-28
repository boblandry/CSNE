
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
/* packet handler ����ԭ��*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                    const u_char *pkt_data);
// ����ԭ��
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
int SendArp(pcap_t *adhandle, char *ip, unsigned char *mac);
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac);
DWORD WINAPI SendArpPacket(LPVOID lpParameter);
DWORD WINAPI GetLivePC(LPVOID lpParameter);

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

//14�ֽ���̫��֡�ṹ
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
//IPͷ��
struct IpHeader
{
    unsigned char Version_HLen; //�汾��Ϣ4λ��ͷ����4Ϊ 1�ֽ�
    unsigned char TOS; //��������  1�ֽ�
    short Length; //���ݰ����� 2�ֽ�
    short Ident; //�Ǿٱ���ʾ 2�ֽ�
    short Flags_Offset; //��־3Ϊ��Ƭ����13λ 2�ֽ�
    unsigned char TTL; //����ʱ�� 1�ֽ�
    unsigned char Protocol; //Э������ 1�ֽ�
    short Checksum; //�ײ�У��� 2�ֽ�
    IpAddress SourceAddr;           //ԴIP��ַ   4�ֽ�
    IpAddress DestinationAddr;   //Ŀ��IP��ַ  4�ֽ�
};
//TCPͷ�� ��20�ֽ�
struct TcpHeader
{
    unsigned short SrcPort;  //Դ�˿ں� 2�ֽ�
    unsigned short DstPort; //Ŀ�Ķ˿ں�2�ֽ�
    unsigned int SequenceNum; // ��� 4�ֽ�
    unsigned int Acknowledgment;  //ȷ�Ϻ� 4�ֽ�
    unsigned char HdrLen; // �ײ�����4λ ����λ6λ ��10λ
    unsigned char Flags;  //��־λ6λ
    unsigned short AdvertisedWindow; //���ڴ�С15λ 2�ֽ�
    unsigned short Checksum; // У���16λ 2�ֽ�
    unsigned short UrgPtr; //����ָ�� 16λ 2�ֽ�
};
//TCPα�ײ� ��12�ֽ�
struct PsdTcpHeader
{
    IpAddress SourceAddr; //ԴIP��ַ 4�ֽ�
    IpAddress DestinationAddr; //Ŀ��IP��ַ 4�ֽ�
    char Zero; //���λ 1�ֽ�
    char Protocol; //Э��� 1�ֽ�
    unsigned short TcpLen; //TCP������ 2�ֽ�
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
bool flag;
struct sparam sp;
struct gparam gp;
//�������IP����ӦMAC��ַ��һ�ֽṹ
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

int counts=0;//����ͳ�������ж�������
//ip_mac_list *lists[256];
struct ip_mac_list lists[256];
byte hostmac[6];
int main()
{
    struct ethernet_head ethernet;    //��̫��֡ͷ
    struct IpHeader ip;                            //IPͷ
    struct TcpHeader tcp;                      //TCPͷ
    struct PsdTcpHeader ptcp;             //TCPα�ײ�

    unsigned char SendBuffer[200];       //���Ͷ���
    char TcpData[] = "send tcp packet!!!!!!!!!!!!!!!!!!!!!";  //��������

    pcap_if_t *alldevs; //��������������
    pcap_if_t *d;  //ѡ�е�����������
    int inum; //��������������
    int i = 0; //����ͳ�ƻ�ȡ�����������豸
    pcap_t *adhandle; //��׽ʵ������pcap_open�ķ��ض���
    char errbuf[PCAP_ERRBUF_SIZE];
    char *ip_addr;
    char *ip_netmask;
    unsigned char *ip_mac;
    HANDLE sendthread;
    HANDLE recvthread;
    unsigned int ip1;
    unsigned int ip2;
    unsigned int ip3;
    unsigned int ip4;
    /*
        lists=(ip_mac_list *) malloc(sizeof(ip_mac_list) * 256);
        if (lists == NULL)
        {
            printf("�����ڴ���IP-MACӳ���ʧ�ܣ�\n");
            return -1;
        }
    */
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
    /* ��ȡ�����豸�б�*/
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* ��ӡ�б�*/
    printf("[���������б�]\n");
    for (d = alldevs; d; d = d->next)
    {
        //�ƶ�����һ�������������豸��Ŀi��1
        printf("%d) %s\n", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    //i=0֤�����������豸��ĿΪ0
    if (i == 0)
    {
        printf("\n�Ҳ�����������ȷ���Ƿ��Ѱ�װWinPcap.\n");
        return -1;
    }
    printf("\n");
    printf("��ѡ��Ҫ�򿪵�������(1-%d):", i);
    //���û�����Ҫ�򿪵���������
    scanf("%d", &inum);
    //�ж��Ƿ�����Ƿ�
    if (inum < 1 || inum > i)
    {
        printf("\n�������ų�������������!�밴������˳���\n");
        //��ȡ�û����������
        getchar();
        getchar();
        /* �ͷ��豸�б�*/
        pcap_freealldevs(alldevs);
        return -1;
    }
    //���е��˴�˵���û����������豸���ź�����λ��ĳһ��������
    /* ��ת��ѡ�е�������*/
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
        ; //ע��˴���һ������ѭ����������λ��ĳһ��������֮�����

    /* ���豸*/
    if ((adhandle = pcap_open(d->name, // �豸��
                              65536, // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
                              PCAP_OPENFLAG_PROMISCUOUS, // ����ģʽ
                              1000, // ��ȡ��ʱʱ��
                              NULL, // Զ�̻�����֤
                              errbuf // ���󻺳��
                             )) == NULL) //ΪNULL˵���޷��򿪴���������
    {
        fprintf(stderr, "\n�޷���ȡ��������. ������%s ����WinPcap֧��\n", d->name);
        /* �ͷ��豸�б�*/
        pcap_freealldevs(alldevs);
        return -1;
    }
    //���е��˴�˵�����Դ򿪸��豸������adhandle�Ѿ��õ���Ч��ֵ��
    //����ѡ�е�������,�����洢ip������ı���
    ifget(d, ip_addr, ip_netmask); //��ȡ��ѡ�����Ļ�����Ϣ--IP��ַ--����
    GetSelfMac(adhandle, ip_addr, ip_mac); //���������豸��������豸ip��ַ��ȡ���豸��MAC��ַ
    sp.adhandle = adhandle;
    sp.ip = ip_addr;
    sp.mac = ip_mac;
    sp.netmask = ip_netmask;
    gp.adhandle = adhandle;
    sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SendArpPacket,
                              &sp, 0, NULL);
    recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) GetLivePC, &gp,
                              0, NULL);
    printf("\nlistening on ����%d ...\n", inum);


    getchar();
    getchar();


    printf("\n���������뷢����Ϣ��������IP��ַ(�Կո����)��");
    scanf("%d",&ip1);
    scanf("%d",&ip2);
    scanf("%d",&ip3);
    scanf("%d",&ip4);
    printf("�����IPΪ��%d.%d.%d.%d\n",ip1,ip2,ip3,ip4);
    //unsigned long k1=2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2;
    //unsigned long k2=2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2;
    //unsigned long k3=2*2*2*2*2*2*2*2;
    //printf("%d..%d..%d",k1,k2,k3);
    //real_ip=ip1*k1+ip2*k2+ip3*k3+ip4;
    //printf("�����IPΪ��%u\n",real_ip);
    /*    int x;
        for (int j=counts-1;j>=0;j--)
        {
            printf("%u\n",lists[j].ip_add);
            if(lists[j].ip_add==real_ip)
            {
                x=j;
                printf("�ѷ��ָ�IP��ַ�����Ե�......");
                break;
            }

            if (j==0)
            {
                printf("�������IP��ַ������������δ���ָ�IP��ַ��");
                return -1;
            }
        }
    */

    int x=-1;
    for (int j=counts-1; j>=0; j--)
    {
        if(lists[j].ip_add1==ip1 && lists[j].ip_add2==ip2 && lists[j].ip_add3==ip3 && lists[j].ip_add4==ip4)
        {
            x=j;
            printf("�ѷ��ָ�IP��ַ�����Ե�......\n");
            break;
        }
        if (j==0 && x!=j)
        {
            printf("�������IP��ַ������������δ���ָ�IP��ַ��\n");
            return -1;
        }
    }
    //�ṹ���ʼ��Ϊ0����
    memset(&ethernet,0,sizeof(ethernet));
    byte destmac[6];
    //����MAC��Ŀ�ĵ�ַ
    destmac[0]=lists[x].mac_add[0];
    destmac[1]=lists[x].mac_add[1];
    destmac[2]=lists[x].mac_add[2];
    destmac[3]=lists[x].mac_add[3];
    destmac[4]=lists[x].mac_add[4];
    destmac[5]=lists[x].mac_add[5];
    memcpy(ethernet.dest_mac_add,destmac,6);
    memcpy(ethernet.source_mac_add,hostmac,6);
    //�ϲ�Э�����ͣ�0x0800����IPЭ��
    ethernet.type=htons(0x0800);
    //��ֵSendBuffer
    memcpy(&SendBuffer,&ethernet,sizeof(struct ethernet_head));
    //��ֵIPͷ����Ϣ
    ip.Version_HLen=0x45;
    ip.TOS=0;
    ip.Length=htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
    ip.Ident=htons(1);
    ip.Flags_Offset=0;
    ip.TTL=128;
    ip.Protocol=6;
    ip.Checksum=0;
    //ԴIP��ַ �ָ�ip_addr Ȼ������
    printf("����%s\n",ip_addr);
    char cip[15];
    char realip[3];
    strcpy(cip,ip_addr);
    const char *mark=".";
    char *_ip;
    _ip=strtok(cip,mark);
    strcpy(realip,_ip);
    //printf("%s\n",realip);
    ip.SourceAddr.byte1=atoi(realip);
    //ip.SourceAddr.byte1=192;
    //printf("byte1=%d\n",ip.SourceAddr.byte1);
    _ip=strtok(NULL,mark);
    strcpy(realip,_ip);
    ip.SourceAddr.byte2=atoi(realip);
    //ip.SourceAddr.byte2=168;
    //printf("byte2=%d\n",ip.SourceAddr.byte2);
    _ip=strtok(NULL,mark);
    strcpy(realip,_ip);
    ip.SourceAddr.byte3=atoi(realip);
    //ip.SourceAddr.byte3=1;
    //printf("byte3=%d\n",ip.SourceAddr.byte3);
    _ip=strtok(NULL,mark);
    strcpy(realip,_ip);
    ip.SourceAddr.byte4=atoi(realip);
    //ip.SourceAddr.byte4=110;
    //printf("byte4=%d\n",ip.SourceAddr.byte4);
    //Ŀ��IP��ַ
    ip.DestinationAddr.byte1 = ip1;
    ip.DestinationAddr.byte2 = ip2;
    ip.DestinationAddr.byte3 = ip3;
    ip.DestinationAddr.byte4 = ip4;

    //��ֵSendBuffer
    memcpy(&SendBuffer[sizeof(struct ethernet_head)], &ip, 20);
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
    memcpy(&SendBuffer[sizeof(struct ethernet_head) + 20], &tcp, 20);
	//��ֵα�ײ�
    ptcp.SourceAddr = ip.SourceAddr;//
    ptcp.DestinationAddr = ip.DestinationAddr;
    ptcp.Zero = 0;
    ptcp.Protocol = 6;
    ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(TcpData));
	//������ʱ�洢��������������У���
    char TempBuffer[65535];
    memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
    memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
    memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	//����TCP��У���
    tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
	//���°�SendBuffer��ֵ����Ϊ��ʱУ����Ѿ��ı䣬��ֵ�µ�
    memcpy(SendBuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader), &tcp, sizeof(struct TcpHeader));
    memcpy(SendBuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	//��ʼ��TempBufferΪ0���У��洢����������IPУ���
    memset(TempBuffer, 0, sizeof(TempBuffer));
    memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
	//����IPУ���
    ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
	//���°�SendBuffer��ֵ��IPУ����Ѿ��ı�
    memcpy(SendBuffer + sizeof(struct ethernet_head), &ip, sizeof(struct IpHeader));
    //�������еĳ���
    int totalsize =sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData);
    int result = pcap_sendpacket(adhandle,SendBuffer,totalsize);

    if (result != 0)
    {
        printf("Send Error!\n");
    }
    else
    {
        printf("Send TCP Packet.\n");
        printf("Destination Port:%d\n", ntohs(tcp.DstPort));
        printf("Source Port:%d\n", ntohs(tcp.SrcPort));
        //printf("Sequence:%d\n", ntohl(tcp.SequenceNum));
        //printf("Acknowledgment:%d\n", ntohl(tcp.Acknowledgment));
        //printf("Header Length:%d*4\n", tcp.HdrLen >> 4);
        //printf("Flags:0x%0x\n", tcp.Flags);
        //rintf("AdvertiseWindow:%d\n", ntohs(tcp.AdvertisedWindow));
        //printf("UrgPtr:%d\n", ntohs(tcp.UrgPtr));
        //printf("Checksum:%u\n", ntohs(tcp.Checksum));
        printf("Send Successfully!");
    }

    /* �ͷ��豸�б�*/
    pcap_freealldevs(alldevs);


    return 0;
}
/* ��ȡ������Ϣ*/
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask)
{
    pcap_addr_t *a;
    char ip6str[128];
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
    for (a = d->addresses; a; a = a->next)
    {
        switch (a->addr->sa_family)
        {
        case AF_INET:  //sa_family ����2�ֽڵĵ�ַ���壬һ�㶼�ǡ�AF_xxx������ʽ��ͨ���õĶ���AF_INET������IPV4
            if (a->addr)
            {
                char *ipstr;
                //����ַת��Ϊ�ַ���
                ipstr = iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr); //*ip_addr
                memcpy(ip_addr, ipstr, 16);
            }
            if (a->netmask)
            {
                char *netmaskstr;
                netmaskstr = iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr);
                memcpy(ip_netmask, netmaskstr, 16);
            }
        case AF_INET6:
            break;
        }
    }
}

/* ���������͵�IP��ַת�����ַ������͵�*/
char *iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
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
