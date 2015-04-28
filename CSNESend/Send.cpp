
#define WINVER 0x0501
#define HAVE_REMOTE
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include "pcap.h"
using namespace std;

#pragma pack(1)  //按一个字节内存对齐
#define IPTOSBUFFERS    12
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1
#define ARP_REPLY       2
#define HOSTNUM         255
/* packet handler 函数原型*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                    const u_char *pkt_data);
// 函数原型
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
//28字节ARP帧结构
struct arp_head
{
    unsigned short hardware_type; //硬件类型
    unsigned short protocol_type; //协议类型
    unsigned char hardware_add_len; //硬件地址长度
    unsigned char protocol_add_len; //协议地址长度
    unsigned short operation_field; //操作字段
    unsigned char source_mac_add[6]; //源mac地址
    unsigned long source_ip_add; //源ip地址
    unsigned char dest_mac_add[6]; //目的mac地址
    unsigned long dest_ip_add; //目的ip地址
};

//14字节以太网帧结构
struct ethernet_head
{
    unsigned char dest_mac_add[6]; //目的mac地址
    unsigned char source_mac_add[6]; //源mac地址
    unsigned short type; //帧类型
};
//arp最终包结构
struct arp_packet
{
    struct ethernet_head ed;
    struct arp_head ah;
};
//IP头部
struct IpHeader
{
    unsigned char Version_HLen; //版本信息4位，头长度4为 1字节
    unsigned char TOS; //服务类型  1字节
    short Length; //数据包长度 2字节
    short Ident; //是举报表示 2字节
    short Flags_Offset; //标志3为，片便宜13位 2字节
    unsigned char TTL; //生存时间 1字节
    unsigned char Protocol; //协议类型 1字节
    short Checksum; //首部校验和 2字节
    IpAddress SourceAddr;           //源IP地址   4字节
    IpAddress DestinationAddr;   //目的IP地址  4字节
};
//TCP头部 共20字节
struct TcpHeader
{
    unsigned short SrcPort;  //源端口号 2字节
    unsigned short DstPort; //目的端口号2字节
    unsigned int SequenceNum; // 序号 4字节
    unsigned int Acknowledgment;  //确认号 4字节
    unsigned char HdrLen; // 首部长度4位 保留位6位 共10位
    unsigned char Flags;  //标志位6位
    unsigned short AdvertisedWindow; //窗口大小15位 2字节
    unsigned short Checksum; // 校验和16位 2字节
    unsigned short UrgPtr; //紧急指针 16位 2字节
};
//TCP伪首部 共12字节
struct PsdTcpHeader
{
    IpAddress SourceAddr; //源IP地址 4字节
    IpAddress DestinationAddr; //目的IP地址 4字节
    char Zero; //填充位 1字节
    char Protocol; //协议号 1字节
    unsigned short TcpLen; //TCP包长度 2字节
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
//存放所有IP及对应MAC地址的一种结构
struct ip_mac_list
{
    int ip_add1;
    int ip_add2;
    int ip_add3;
    int ip_add4;
    unsigned char mac_add[6];
};

//获得校验和的方法
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

int counts=0;//用来统计网内有多少主机
//ip_mac_list *lists[256];
struct ip_mac_list lists[256];
byte hostmac[6];
int main()
{
    struct ethernet_head ethernet;    //以太网帧头
    struct IpHeader ip;                            //IP头
    struct TcpHeader tcp;                      //TCP头
    struct PsdTcpHeader ptcp;             //TCP伪首部

    unsigned char SendBuffer[200];       //发送队列
    char TcpData[] = "send tcp packet!!!!!!!!!!!!!!!!!!!!!";  //发送内容

    pcap_if_t *alldevs; //所有网络适配器
    pcap_if_t *d;  //选中的网络适配器
    int inum; //适配器计数变量
    int i = 0; //用来统计获取到几个网卡设备
    pcap_t *adhandle; //捕捉实例，是pcap_open的返回对象
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
            printf("申请内存存放IP-MAC映射表失败！\n");
            return -1;
        }
    */
    ip_addr = (char *) malloc(sizeof(char) * 16); //申请内存存放IP地址
    if (ip_addr == NULL)
    {
        printf("申请内存存放IP地址失败!\n");
        return -1;
    }
    ip_netmask = (char *) malloc(sizeof(char) * 16); //申请内存存放NETMASK地址
    if (ip_netmask == NULL)
    {
        printf("申请内存存放NETMASK地址失败!\n");
        return -1;
    }
    ip_mac = (unsigned char *) malloc(sizeof(unsigned char) * 6); //申请内存存放MAC地址
    if (ip_mac == NULL)
    {
        printf("申请内存存放MAC地址失败!\n");
        return -1;
    }
    /* 获取本机设备列表*/
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    /* 打印列表*/
    printf("[本机网卡列表：]\n");
    for (d = alldevs; d; d = d->next)
    {
        //移动到下一个网卡，网卡设备数目i加1
        printf("%d) %s\n", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    //i=0证明所有网卡设备数目为0
    if (i == 0)
    {
        printf("\n找不到网卡！请确认是否已安装WinPcap.\n");
        return -1;
    }
    printf("\n");
    printf("请选择要打开的网卡号(1-%d):", i);
    //让用户输入要打开的网卡代号
    scanf("%d", &inum);
    //判断是否输入非法
    if (inum < 1 || inum > i)
    {
        printf("\n该网卡号超过现有网卡数!请按任意键退出…\n");
        //获取用户键入的内容
        getchar();
        getchar();
        /* 释放设备列表*/
        pcap_freealldevs(alldevs);
        return -1;
    }
    //运行到此处说明用户输入网卡设备代号合理，定位到某一个适配器
    /* 跳转到选中的适配器*/
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
        ; //注意此处是一个无限循环，用来定位到某一个适配器之后结束

    /* 打开设备*/
    if ((adhandle = pcap_open(d->name, // 设备名
                              65536, // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
                              PCAP_OPENFLAG_PROMISCUOUS, // 混杂模式
                              1000, // 读取超时时间
                              NULL, // 远程机器验证
                              errbuf // 错误缓冲池
                             )) == NULL) //为NULL说明无法打开此适配器。
    {
        fprintf(stderr, "\n无法读取该适配器. 适配器%s 不被WinPcap支持\n", d->name);
        /* 释放设备列表*/
        pcap_freealldevs(alldevs);
        return -1;
    }
    //运行到此处说明可以打开该设备，并且adhandle已经得到有效赋值。
    //传入选中的适配器,用来存储ip和掩码的变量
    ifget(d, ip_addr, ip_netmask); //获取所选网卡的基本信息--IP地址--掩码
    GetSelfMac(adhandle, ip_addr, ip_mac); //输入网卡设备句柄网卡设备ip地址获取该设备的MAC地址
    sp.adhandle = adhandle;
    sp.ip = ip_addr;
    sp.mac = ip_mac;
    sp.netmask = ip_netmask;
    gp.adhandle = adhandle;
    sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SendArpPacket,
                              &sp, 0, NULL);
    recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) GetLivePC, &gp,
                              0, NULL);
    printf("\nlistening on 网卡%d ...\n", inum);


    getchar();
    getchar();


    printf("\n请输入你想发送信息的主机的IP地址(以空格隔开)：");
    scanf("%d",&ip1);
    scanf("%d",&ip2);
    scanf("%d",&ip3);
    scanf("%d",&ip4);
    printf("输入的IP为：%d.%d.%d.%d\n",ip1,ip2,ip3,ip4);
    //unsigned long k1=2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2;
    //unsigned long k2=2*2*2*2*2*2*2*2*2*2*2*2*2*2*2*2;
    //unsigned long k3=2*2*2*2*2*2*2*2;
    //printf("%d..%d..%d",k1,k2,k3);
    //real_ip=ip1*k1+ip2*k2+ip3*k3+ip4;
    //printf("输入的IP为：%u\n",real_ip);
    /*    int x;
        for (int j=counts-1;j>=0;j--)
        {
            printf("%u\n",lists[j].ip_add);
            if(lists[j].ip_add==real_ip)
            {
                x=j;
                printf("已发现该IP地址，请稍等......");
                break;
            }

            if (j==0)
            {
                printf("你输入的IP地址有误，在内网中未发现该IP地址。");
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
            printf("已发现该IP地址，请稍等......\n");
            break;
        }
        if (j==0 && x!=j)
        {
            printf("你输入的IP地址有误，在内网中未发现该IP地址。\n");
            return -1;
        }
    }
    //结构体初始化为0序列
    memset(&ethernet,0,sizeof(ethernet));
    byte destmac[6];
    //设置MAC的目的地址
    destmac[0]=lists[x].mac_add[0];
    destmac[1]=lists[x].mac_add[1];
    destmac[2]=lists[x].mac_add[2];
    destmac[3]=lists[x].mac_add[3];
    destmac[4]=lists[x].mac_add[4];
    destmac[5]=lists[x].mac_add[5];
    memcpy(ethernet.dest_mac_add,destmac,6);
    memcpy(ethernet.source_mac_add,hostmac,6);
    //上层协议类型，0x0800代表IP协议
    ethernet.type=htons(0x0800);
    //赋值SendBuffer
    memcpy(&SendBuffer,&ethernet,sizeof(struct ethernet_head));
    //赋值IP头部信息
    ip.Version_HLen=0x45;
    ip.TOS=0;
    ip.Length=htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
    ip.Ident=htons(1);
    ip.Flags_Offset=0;
    ip.TTL=128;
    ip.Protocol=6;
    ip.Checksum=0;
    //源IP地址 分割ip_addr 然后填入
    printf("测试%s\n",ip_addr);
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
    //目的IP地址
    ip.DestinationAddr.byte1 = ip1;
    ip.DestinationAddr.byte2 = ip2;
    ip.DestinationAddr.byte3 = ip3;
    ip.DestinationAddr.byte4 = ip4;

    //赋值SendBuffer
    memcpy(&SendBuffer[sizeof(struct ethernet_head)], &ip, 20);
	//赋值TCP头部内容
    tcp.DstPort = htons(102);
    tcp.SrcPort = htons(1000);
    tcp.SequenceNum = htonl(11);
    tcp.Acknowledgment = 0;
    tcp.HdrLen = 0x50;
    tcp.Flags = 0x18;
    tcp.AdvertisedWindow = htons(512);
    tcp.UrgPtr = 0;
    tcp.Checksum = 0;
	//赋值SendBuffer
    memcpy(&SendBuffer[sizeof(struct ethernet_head) + 20], &tcp, 20);
	//赋值伪首部
    ptcp.SourceAddr = ip.SourceAddr;//
    ptcp.DestinationAddr = ip.DestinationAddr;
    ptcp.Zero = 0;
    ptcp.Protocol = 6;
    ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(TcpData));
	//声明临时存储变量，用来计算校验和
    char TempBuffer[65535];
    memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
    memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
    memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	//计算TCP的校验和
    tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
	//重新把SendBuffer赋值，因为此时校验和已经改变，赋值新的
    memcpy(SendBuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader), &tcp, sizeof(struct TcpHeader));
    memcpy(SendBuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	//初始化TempBuffer为0序列，存储变量来计算IP校验和
    memset(TempBuffer, 0, sizeof(TempBuffer));
    memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
	//计算IP校验和
    ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
	//重新把SendBuffer赋值，IP校验和已经改变
    memcpy(SendBuffer + sizeof(struct ethernet_head), &ip, sizeof(struct IpHeader));
    //发送序列的长度
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

    /* 释放设备列表*/
    pcap_freealldevs(alldevs);


    return 0;
}
/* 获取可用信息*/
void ifget(pcap_if_t *d, char *ip_addr, char *ip_netmask)
{
    pcap_addr_t *a;
    char ip6str[128];
    /* IP addresses */
    /*pcap_if_t是一个网络设备，一个结构体
    	它包含了 pcap_if *  next   指向下一个适配器的指针
    					char *  name       适配器的名字
    					char *  description  适配器的描述
    					pcap_addr *  addresses   适配器对应的IP地址
    					u_int  flags              适配器的标识符，一般可能的值为PCAP_IF_LOOPBACK，
    */
    /*
    struct pcap_addr {
    	struct pcap_addr *next;    指向下一个元素的指针
    	struct sockaddr *addr;      IP地址
    	struct sockaddr *netmask;    网络掩码
    	struct sockaddr *broadaddr; 广播地址
    	struct sockaddr *dstaddr;    P2P目的地址
    };
    */
    //遍历所有的地址,a代表一个pcap_addr
    for (a = d->addresses; a; a = a->next)
    {
        switch (a->addr->sa_family)
        {
        case AF_INET:  //sa_family ：是2字节的地址家族，一般都是“AF_xxx”的形式。通常用的都是AF_INET。代表IPV4
            if (a->addr)
            {
                char *ipstr;
                //将地址转化为字符串
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

/* 将数字类型的IP地址转换成字符串类型的*/
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

/* 获取自己主机的MAC地址 */
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, unsigned char *ip_mac)
{
    unsigned char sendbuf[42]; //arp包结构大小
    int i = -1;
    int res;
    struct ethernet_head eh;
    struct arp_head ah;
    struct pcap_pkthdr * pkt_header;
    const u_char * pkt_data;
    //将已开辟内存空间 eh.dest_mac_add 的首 6个字节的值设为值 0xff。
    memset(eh.dest_mac_add, 0xff, 6); //目的地址为全为广播地址
    memset(eh.source_mac_add, 0x0f, 6);
    memset(ah.source_mac_add, 0x0f, 6);
    memset(ah.dest_mac_add, 0x00, 6);
    //htons将一个无符号短整型的主机数值转换为网络字节顺序
    eh.type = htons(ETH_ARP);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_add_len = 6;
    ah.protocol_add_len = 4;
    ah.source_ip_add = inet_addr("100.100.100.100"); //随便设的请求方ip
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
            printf("获取自己主机的MAC地址成功!\n");
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
/* 向局域网内所有可能的IP地址发送ARP请求包线程 */
DWORD WINAPI SendArpPacket(LPVOID lpParameter) //(pcap_t *adhandle,char *ip,unsigned char *mac,char *netmask)
{
    sparam *spara = (sparam *) lpParameter;
    pcap_t *adhandle = spara->adhandle;
    char *ip = spara->ip;
    unsigned char *mac = spara->mac;
    char *netmask = spara->netmask;
    printf("ip_mac:%02x-%02x-%02x-%02x-%02x-%02x\n", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
    printf("自身的IP地址为:%s\n", ip);
    printf("地址掩码NETMASK为:%s\n", netmask);
    printf("\n");
    unsigned char sendbuf[42]; //arp包结构大小
    struct ethernet_head eh;
    struct arp_head ah;
    memset(eh.dest_mac_add, 0xff, 6); //目的地址为全为广播地址
    memcpy(eh.source_mac_add, mac, 6);
    memcpy(ah.source_mac_add, mac, 6);
    memset(ah.dest_mac_add, 0x00, 6);
    eh.type = htons(ETH_ARP);
    ah.hardware_type = htons(ARP_HARDWARE);
    ah.protocol_type = htons(ETH_IP);
    ah.hardware_add_len = 6;
    ah.protocol_add_len = 4;
    ah.source_ip_add = inet_addr(ip); //请求方的IP地址为自身的IP地址
    ah.operation_field = htons(ARP_REQUEST);
    //向局域网内广播发送arp包
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
/* 分析截留的数据包获取活动的主机IP地址 */
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
            printf("扫描完毕，按任意键退出!\n");
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
                    printf("IP地址:%d.%d.%d.%d   MAC地址:",
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
