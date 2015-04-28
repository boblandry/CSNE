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

char *iptos(u_long in);       //u_long即为 unsigned long
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
//struct tm *ltime;					//和时间处理有关的变量
// 函数原型
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

//帧头部结构体，共14字节
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

//IP头部结构体，共20字节
struct IpHeader
{
    unsigned char Version_HLen;   //版本信息4位 ，头长度4位 1字节
    unsigned char TOS;                    //服务类型    1字节
    short Length;                              //数据包长度 2字节
    short Ident;                                 //数据包标识  2字节
    short Flags_Offset;                    //标志3位，片偏移13位  2字节
    unsigned char TTL;                    //存活时间  1字节
    unsigned char Protocol;           //协议类型  1字节
    short Checksum;                        //首部校验和 2字节
    IpAddress SourceAddr;           //源IP地址   4字节
    IpAddress DestinationAddr;   //目的IP地址  4字节
};

//TCP头部结构体，共20字节
struct TcpHeader
{
    unsigned short SrcPort;                        //源端口号  2字节
    unsigned short DstPort;                        //目的端口号 2字节
    unsigned int SequenceNum;               //序号  4字节
    unsigned int Acknowledgment;         //确认号  4字节
    unsigned char HdrLen;                         //首部长度4位，保留位6位 共10位
    unsigned char Flags;                              //标志位6位
    unsigned short AdvertisedWindow;  //窗口大小16位 2字节
    unsigned short Checksum;                  //校验和16位   2字节
    unsigned short UrgPtr;						  //紧急指针16位   2字节
};

//TCP伪首部结构体 12字节
struct PsdTcpHeader
{
    IpAddress SourceAddr;                     //源IP地址  4字节
    IpAddress DestinationAddr;             //目的IP地址 4字节
    char Zero;                                                    //填充位  1字节
    char Protocol;                                               //协议号  1字节
    unsigned short TcpLen;                           //TCP包长度 2字节
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
//存放所有IP及对应MAC地址的映射表
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
struct ip_mac_list lists[2560];
byte hostmac[6];//自己本身的MAC地址
int counts=0;//用来统计网内有多少主机
int main(){

	ethernet_head *ethernet;    //以太网帧头
    IpHeader *ip;                            //IP头
    TcpHeader *tcp;                      //TCP头
    PsdTcpHeader ptcp;             //TCP伪首部

	pcap_if_t  * alldevs;       //所有网络适配器
	pcap_if_t  *d1,*d2;					//选中的网络适配器  d1为监听对象 d2为发送对象
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	char source[PCAP_ERRBUF_SIZE];
	unsigned char transmitbuffer[200];
	pcap_t *adhandle1,*adhandle2;           //捕捉实例,是pcap_open返回的对象
	int i = 0;                            //适配器计数变量
	struct pcap_pkthdr *header;    //接收到的数据包的头部
    const u_char *pkt_data;			  //接收到的数据包的内容
	int res;                                    //表示是否接收到了数据包
	u_int netmask;                       //过滤时用的子网掩码
	char packet_filter[] = "tcp";        //过滤字符
	struct bpf_program fcode;                     //pcap_compile所调用的结构体

	u_int ip_len;                                       //ip地址有效长度
	u_short sport,dport;                        //主机字节序列
	u_char packet[100];                       //发送数据包目的地址
	pcap_dumper_t *dumpfile;         //堆文件

	//time_t local_tv_sec;				//和时间处理有关的变量
    //char timestr[16];					//和时间处理有关的变量
    char *ip_addr;
    char *ip_netmask;
    unsigned char *ip_mac;
    HANDLE sendthread;
    HANDLE recvthread;

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

	//获取本地适配器列表
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf) == -1){
		//结果为-1代表出现获取适配器列表失败
		fprintf(stderr,"Error in pcap_findalldevs_ex:\n",errbuf);
		//exit(0)代表正常退出,exit(other)为非正常退出,这个值会传给操作系统
		exit(1);
	}
	//打印设备列表信息
	for(d1 = alldevs;d1 !=NULL;d1 = d1->next){
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n",++i,d1->name);
		if(d1->description){
			//打印适配器的描述信息
			printf("description:%s\n",d1->description);
		}else{
			//适配器不存在描述信息
			printf("description:%s","no description\n");
		}
		//打印本地环回地址
		printf("\tLoopback: %s\n",(d1->flags & PCAP_IF_LOOPBACK)?"yes":"no");

		 pcap_addr_t *a;       //网络适配器的地址用来存储变量
		 for(a = d1->addresses;a;a = a->next){
			 //sa_family代表了地址的类型,是IPV4地址类型还是IPV6地址类型
			 switch (a->addr->sa_family)
			 {
				 case AF_INET:  //代表IPV4类型地址
					 printf("Address Family Name:AF_INET\n");
					 if(a->addr){
						 //->的优先级等同于括号,高于强制类型转换,因为addr为sockaddr类型，对其进行操作须转换为sockaddr_in类型
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
				 case AF_INET6: //代表IPV6类型地址
					 printf("Address Family Name:AF_INET6\n");
					 printf("this is an IPV6 address\n");
					 break;
				 default:
					 break;
			 }
		 }
	}
	//i为0代表上述循环未进入,即没有找到适配器,可能的原因为Winpcap没有安装导致未扫描到
	if(i == 0){
		printf("interface not found,please check winpcap installation");
	}

    int num2;
	printf("请输入要发送数据的网卡:");
	//让用户选择选择哪个适配器进行抓包
	scanf("%d",&num2);
	printf("\n");

	//用户输入的数字超出合理范围
	if(num2<1||num2>i){
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//跳转到选中的适配器
	int j;
	for(d2=alldevs, j=0; j< num2-1 ; d2=d2->next, j++);

	//运行到此处说明用户的输入是合法的
	if((adhandle2 = pcap_open(d2->name,		//设备名称
														65535,       //存放数据包的内容长度
														PCAP_OPENFLAG_PROMISCUOUS,  //混杂模式
														1000,           //超时时间
														NULL,          //远程验证
														errbuf         //错误缓冲
														)) == NULL){
        //打开适配器失败,打印错误并释放适配器列表
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d2->name);
        // 释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
	}

	int num1;
	printf("请输入要接收数据的网卡:");
	//让用户选择选择哪个适配器进行抓包
	scanf("%d",&num1);
	printf("\n");

    if(num1<1||num1>i){
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//跳转到选中的适配器
	for(d1=alldevs, i=0; i< num1-1 ; d1=d1->next, i++);

	//运行到此处说明用户的输入是合法的
	if((adhandle1 = pcap_open(d1->name,		//设备名称
														65535,       //存放数据包的内容长度
														PCAP_OPENFLAG_PROMISCUOUS,  //混杂模式
														1000,           //超时时间
														NULL,          //远程验证
														errbuf         //错误缓冲
														)) == NULL){
        //打开适配器失败,打印错误并释放适配器列表
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d1->name);
        // 释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
	}


    //用户输入的数字超出合理范围

    //printf("11111111\n");

	//打印输出,正在监听中
	//printf("\nlistening on %s...\n", d1->description);

	//所在网络不是以太网,此处只取这种情况
	if(pcap_datalink(adhandle1) != DLT_EN10MB)
    {
        fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
        //释放列表
        pcap_freealldevs(alldevs);
        return -1;
    }

	//先获得地址的子网掩码
	if(d1->addresses != NULL)
        //获得接口第一个地址的掩码
        netmask=((struct sockaddr_in *)(d1->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        // 如果接口没有地址，那么我们假设一个C类的掩码
        netmask=0xffffff;

	//pcap_compile()的原理是将高层的布尔过滤表
	//达式编译成能够被过滤引擎所解释的低层的字节码
	if(pcap_compile(adhandle1,	//适配器处理对象
										&fcode,
										packet_filter,   //过滤ip和UDP
										1,                       //优化标志
										netmask           //子网掩码
										)<0)
	{
		//过滤出现问题
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        // 释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
	}

	//设置过滤器
    if (pcap_setfilter(adhandle1, &fcode)<0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        //释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
    }

    ifget(d2, ip_addr, ip_netmask); //获取所选网卡的基本信息--IP地址--掩码
    GetSelfMac(adhandle2, ip_addr, ip_mac); //输入网卡设备句柄网卡设备ip地址获取该设备的MAC地址
    sp.adhandle = adhandle2;
    sp.ip = ip_addr;
    sp.mac = ip_mac;
    sp.netmask = ip_netmask;
    gp.adhandle = adhandle2;
    sendthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) SendArpPacket,
                              &sp, 0, NULL);
    recvthread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) GetLivePC, &gp,
                              0, NULL);
    printf("\n获取网卡%d 上的ip-mac映射表\n",num2);


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

    printf("开启路由...\n");
    ethernet = (ethernet_head *) malloc(sizeof(char) * 14); //申请内存存放ethernet
    if (ethernet == NULL)
    {
        printf("申请内存存放ethernet帧头地址失败!\n");
        return -1;
    }

	//利用pcap_next_ex来接受数据包
	while((res = pcap_next_ex(adhandle1,&header,&pkt_data))>=0)
	{
		if(res ==0)
        {
			//返回值为0代表接受数据包超时，重新循环继续接收
			printf("超时...\n");
			continue;
		}
		else
        {
			//运行到此处代表接受到正常从数据包
			//header为帧的头部
			//printf("%.6ld len:%d ", header->ts.tv_usec, header->len);
			//获得以太网帧头部
			ethernet=(ethernet_head *)pkt_data;
			// 获得IP数据包头部的位置
			ip = (IpHeader *) (pkt_data +14);    //14为以太网帧头部长度
			//获得TCP头部的位置
			ip_len = (ip->Version_HLen & 0xf) *4;
			//printf("ip_length:%d ",ip_len);


			tcp = (TcpHeader *)((u_char *)ip+ip_len);
			char * data;
            data = (char *)((u_char *)tcp+20);
			 //将网络字节序列转换成主机字节序列
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
            //打印数据
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
                    printf("已发现该IP地址，请稍等......\n");
                    break;
                }
                if (j==0 && x!=j)
                {
                    printf("目的IP未发现\n");
                    flag1=false;
                    break;
                }
            }
            if (flag1==false)
                continue;
            //结构体初始化为0序列

            //memset(&ethernet,0,sizeof(ethernet));
            ethernet_head eh;
            IpHeader s_ip;
            TcpHeader s_tcp;
            memset(&transmitbuffer,0,200);
            byte destmac[6];
            //设置MAC的目的地址
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
            //上层协议类型，0x0800代表IP协议
            eh.type=htons(0x0800);
            //赋值SendBuffer
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
            //赋值伪首部
            ptcp.SourceAddr = s_ip.SourceAddr;
            ptcp.DestinationAddr = s_ip.DestinationAddr;
            ptcp.Zero = 0;
            ptcp.Protocol = 6;
            ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(data));
            //声明临时存储变量，用来计算校验和
            char TempBuffer[65535];
            memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
            memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
            memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), data, strlen(data));
            //计算TCP的校验和
            s_tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(data));
            //重新把SendBuffer赋值，因为此时校验和已经改变，赋值新的
            memcpy(transmitbuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader), &s_tcp, sizeof(struct TcpHeader));
            memcpy(transmitbuffer + sizeof(struct ethernet_head) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), data, strlen(data));
            //初始化TempBuffer为0序列，存储变量来计算IP校验和
            memset(TempBuffer, 0, sizeof(TempBuffer));
            memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
            //计算IP校验和
            s_ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
            //重新把SendBuffer赋值，IP校验和已经改变
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



	//释放网络适配器列表
	pcap_freealldevs(alldevs);

	int inum;
	scanf("%d", &inum);

	return 0;

}



/* 将数字类型的IP地址转换成字符串类型的 */
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
    for (a = d2->addresses; a; a = a->next)
    {
        switch (a->addr->sa_family)
        {
        case AF_INET:  //sa_family ：是2字节的地址家族，一般都是“AF_xxx”的形式。通常用的都是AF_INET。代表IPV4
            if (a->addr)
            {
                char *ipstr;
                //将地址转化为字符串
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
            printf("获取ip-mac映射表成功！\n");
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
