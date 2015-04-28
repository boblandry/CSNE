#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
int main()
{
    char *ip_addr="192.168.1.110";

    printf("%s\n",ip_addr);

    char ip[15];
    char realip[3];
    strcpy(ip,ip_addr);
    const char *mark=".";
    char *_ip;
    _ip=strtok(ip,mark);


    printf("%s\n",_ip);

    //char realip;
    //realip=_ip;
    strcpy(realip,_ip);

    printf("%s\n",realip);
    return 1;
}
