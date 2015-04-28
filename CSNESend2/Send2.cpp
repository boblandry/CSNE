
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

//IP地址格式
struct IpAddress
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

//帧头部结构体，共14字节
struct EthernetHeader
{
    u_char DestMAC[6];    //目的MAC地址 6字节
    u_char SourMAC[6];   //源MAC地址 6字节
    u_short EthType;         //上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp  2字节
};

//IP头部结构体，共20字节
struct IpHeader
{
    unsigned char Version_HLen;   //版本信息4位 ，头长度4位 1字节
    unsigned char TOS;                    //服务类型    1字节
    short Length;                              //数据包长度 2字节
    short Ident;                                 //数据包标识  2字节
    short Flags_Offset;                    //标志3位，片偏移13位  2字节
    unsigned char TTL;                   //存活时间  1字节
    unsigned char Protocol;          //协议类型  1字节
    short Checksum;                       //首部校验和 2字节
	IpAddress SourceAddr;       //源IP地址   4字节
	IpAddress DestinationAddr; //目的IP地址  4字节
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
    char Protcol;                                               //协议号  1字节
    unsigned short TcpLen;                           //TCP包长度 2字节
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


int main(){

	struct EthernetHeader ethernet;    //以太网帧头
    struct IpHeader ip;                            //IP头
    struct TcpHeader tcp;                      //TCP头
    struct PsdTcpHeader ptcp;             //TCP伪首部

	unsigned char SendBuffer[200];       //发送队列
	char TcpData[] = "Routing Test!!!!!!!!!!!";  //发送内容

	pcap_if_t  * alldevs;       //所有网络适配器
	pcap_if_t  *d;					//选中的网络适配器
	char errbuf[PCAP_ERRBUF_SIZE];   //错误缓冲区,大小为256
	pcap_t *adhandle;           //捕捉实例,是pcap_open返回的对象
	int i = 0;                            //适配器计数变量


	//获取本地适配器列表
	if(pcap_findalldevs_ex(PCAP_SRC_IF_STRING,NULL,&alldevs,errbuf) == -1){
		//结果为-1代表出现获取适配器列表失败
		fprintf(stderr,"Error in pcap_findalldevs_ex:\n",errbuf);
		//exit(0)代表正常退出,exit(other)为非正常退出,这个值会传给操作系统
		exit(1);
	}


	for(d = alldevs;d !=NULL;d = d->next){
		printf("-----------------------------------------------------------------\nnumber:%d\nname:%s\n",++i,d->name);
		if(d->description){
			//打印适配器的描述信息
			printf("description:%s\n",d->description);
		}else{
			//适配器不存在描述信息
			printf("description:%s","no description\n");
		}
		//打印本地环回地址
		 printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");
		 /**
		 pcap_addr *  next     指向下一个地址的指针
		 sockaddr *  addr       IP地址
		 sockaddr *  netmask  子网掩码
		 sockaddr *  broadaddr   广播地址
		 sockaddr *  dstaddr        目的地址
		 */
		 pcap_addr_t *a;       //网络适配器的地址用来存储变量
		 for(a = d->addresses;a;a = a->next){
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

	int num;
	printf("Enter the interface number(1-%d):",i);
	//让用户选择选择哪个适配器进行抓包
	scanf("%d",&num);
	printf("\n");

	//用户输入的数字超出合理范围
	if(num<1||num>i){
		printf("number out of range\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//跳转到选中的适配器
	for(d=alldevs, i=0; i< num-1 ; d=d->next, i++);

	//运行到此处说明用户的输入是合法的
	if((adhandle = pcap_open(d->name,		//设备名称
														65535,       //存放数据包的内容长度
														PCAP_OPENFLAG_PROMISCUOUS,  //混杂模式
														1000,           //超时时间
														NULL,          //远程验证
														errbuf         //错误缓冲
														)) == NULL){
        //打开适配器失败,打印错误并释放适配器列表
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        // 释放设备列表
        pcap_freealldevs(alldevs);
        return -1;
	}

	//结构体初始化为0序列
    memset(&ethernet, 0, sizeof(ethernet));
    BYTE destmac[8];
	//目的MAC地址
    destmac[0] = 0x10;
    destmac[1] = 0xbf;
    destmac[2] = 0x48;
    destmac[3] = 0x08;
    destmac[4] = 0x7c;
    destmac[5] = 0x19;
	//赋值目的MAC地址
    memcpy(ethernet.DestMAC, destmac, 6);
    BYTE hostmac[8];
	//源MAC地址
    hostmac[0] = 0x26;
    hostmac[1] = 0xdb;
    hostmac[2] = 0xc9;
    hostmac[3] = 0x33;
    hostmac[4] = 0xc8;
    hostmac[5] = 0xbd;
	//赋值源MAC地址
    memcpy(ethernet.SourMAC, hostmac, 6);
	//上层协议类型,0x0800代表IP协议
    ethernet.EthType = htons(0x0800);
	//赋值SendBuffer
    memcpy(&SendBuffer, &ethernet, sizeof(struct EthernetHeader));
	//赋值IP头部信息
    ip.Version_HLen = 0x45;
    ip.TOS = 0;
    ip.Length = htons(sizeof(struct IpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
    ip.Ident = htons(1);
    ip.Flags_Offset = 0;
    ip.TTL = 128;
    ip.Protocol = 6;
    ip.Checksum = 0;
	//源IP地址
	ip.SourceAddr.byte1 = 172;
	ip.SourceAddr.byte2 = 29;
	ip.SourceAddr.byte3 = 7;
	ip.SourceAddr.byte4 = 1;
	//目的IP地址
	ip.DestinationAddr.byte1 = 211;
	ip.DestinationAddr.byte2 = 87;
	ip.DestinationAddr.byte3 = 229;
	ip.DestinationAddr.byte4 = 11;
	//赋值SendBuffer
    memcpy(&SendBuffer[sizeof(struct EthernetHeader)], &ip, 20);
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
    memcpy(&SendBuffer[sizeof(struct EthernetHeader) + 20], &tcp, 20);
	//赋值伪首部
    ptcp.SourceAddr = ip.SourceAddr;//
    ptcp.DestinationAddr = ip.DestinationAddr;
    ptcp.Zero = 0;
    ptcp.Protcol = 6;
    ptcp.TcpLen = htons(sizeof(struct TcpHeader) + strlen(TcpData));
	//声明临时存储变量，用来计算校验和
    char TempBuffer[65535];
    memcpy(TempBuffer, &ptcp, sizeof(struct PsdTcpHeader));
    memcpy(TempBuffer + sizeof(struct PsdTcpHeader), &tcp, sizeof(struct TcpHeader));
    memcpy(TempBuffer + sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	//计算TCP的校验和
    tcp.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct PsdTcpHeader) + sizeof(struct TcpHeader) + strlen(TcpData));
	//重新把SendBuffer赋值，因为此时校验和已经改变，赋值新的
    memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader), &tcp, sizeof(struct TcpHeader));
    memcpy(SendBuffer + sizeof(struct EthernetHeader) + sizeof(struct IpHeader) + sizeof(struct TcpHeader), TcpData, strlen(TcpData));
	//初始化TempBuffer为0序列，存储变量来计算IP校验和
    memset(TempBuffer, 0, sizeof(TempBuffer));
    memcpy(TempBuffer, &ip, sizeof(struct IpHeader));
	//计算IP校验和
    ip.Checksum = checksum((USHORT*)(TempBuffer), sizeof(struct IpHeader));
	//重新把SendBuffer赋值，IP校验和已经改变
    memcpy(SendBuffer + sizeof(struct EthernetHeader), &ip, sizeof(struct IpHeader));
	//发送序列的长度
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
	//释放网络适配器列表
	pcap_freealldevs(alldevs);

	int scan;
	scanf("%d",&scan);

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
