#include<stdio.h>
#include<ctype.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<signal.h>
#include<sys/wait.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<errno.h>
#include<sys/file.h>
#include<sys/msg.h>
#include<sys/ipc.h>
#include<time.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <getopt.h>

//TODO: Name DHCPPROBE'

#define BROADCAST_ADDRESS "255.255.255.255"

#define MAX_DHCP_CHADDR_LENGTH 16
#define MAX_DHCP_SNAME_LENGTH 64
#define MAX_DHCP_FILE_LENGTH 128
#define DHCP_MAGIC_LENGTH 4
#define MAX_DHCP_OPTIONS_LENGTH 312 - DHCP_MAGIC_LENGTH

typedef struct dhcp_packet
{
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[MAX_DHCP_CHADDR_LENGTH];
    uint8_t sname[MAX_DHCP_SNAME_LENGTH];
    uint8_t file[MAX_DHCP_FILE_LENGTH];
    uint8_t magic[DHCP_MAGIC_LENGTH];
    uint8_t opt[MAX_DHCP_OPTIONS_LENGTH];
} __attribute__((__packed__)) dhcp_packet_t;

static int fill_mac_address(uint8_t* base_addr, const char* interface_name)
{
    int fd;
    struct ifreq ifr;

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
        exit(1);

    strcpy(ifr.ifr_name, interface_name);

    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
        exit(1);

    close(fd);

    memcpy(base_addr, ifr.ifr_addr.sa_data, 6);

    return 0;
}

static int construct_dhcp_discover(dhcp_packet_t* packet, const char* iface_name)
{
    srand(time(NULL));

    packet->op = 1; //request
    packet->htype = 6; //wifi
    packet->hlen = 6; //default
    packet->hops = 0;
    packet->xid = htonl(rand()); //random
    packet->secs = htons(0);
    packet->flags = htons(0x8000); //dont know my own ip, so send back by broadcast
    packet->ciaddr = 0; //my ip address
    packet->yiaddr = 0; //my future ip address
    packet->siaddr = 0; //server address
    packet->giaddr = 0; //gateway address

    if(fill_mac_address(packet->chaddr, iface_name) < 0)
        exit(1);

    packet->magic[0]=0x63;
    packet->magic[1]=0x82;
    packet->magic[2]=0x53;
    packet->magic[3]=0x63;

    packet->opt[0]=53;
    packet->opt[1]=1;
    packet->opt[2]=1;

    packet->opt[MAX_DHCP_OPTIONS_LENGTH - 1] = 0xFF;

    return 0;
}

static int handle_dhcp_option(uint8_t option_type, const uint8_t* option_start, uint32_t option_length)
{
    //printf("Option type: %d (length: %d)\n", option_type, option_length);

    // http://networksorcery.com/enp/protocol/bootp/options.htm
    switch(option_type)
    {
        case 1: //mask
        {
            printf("Mask: %u.%u.%u.%u\n", option_start[0], option_start[1], option_start[2], option_start[3]);
            break;
        }
        case 6: //dns
        {
            printf("DNS Server: %u.%u.%u.%u\n", option_start[0], option_start[1], option_start[2], option_start[3]);
            break;
        }
        case 15: //domain name
        {
            char domain_name[option_length + 1];
            strncpy(domain_name, (const char*)option_start, option_length);
            domain_name[option_length] = '\0';
            printf("Domain name: %s\n", domain_name);
            break;
        }
        case 54: //router
        {
            printf("DHCP server ip: %u.%u.%u.%u\n", option_start[0], option_start[1], option_start[2], option_start[3]);
            break;
        }
        default: //undefined
            return 0; //-1
    }

    return 0;
}

static void print_dhcp_offer_info(const dhcp_packet_t* dhcp_offer)
{
    //uint32_t ip = ntohl(dhcp_offer->yiaddr);
    //printf("Got IP %u.%u.%u.%u\n", ip >> 24, ((ip << 8) >> 24), (ip << 16) >> 24, (ip << 24) >> 24);

    size_t i = 0;
    while(i < MAX_DHCP_OPTIONS_LENGTH && dhcp_offer->opt[i] != 0)
    {
        uint8_t option = dhcp_offer->opt[i++];
        uint32_t length = dhcp_offer->opt[i++];

        if(handle_dhcp_option(option, &dhcp_offer->opt[i], length) < 0)
            exit(1);

        i += dhcp_offer->opt[length];
    }
}

int main(int argc, char** argv)
{
    const char* iface_name = NULL;

    char c;
    while((c = getopt(argc, argv, "i:")) > 0)
    {
        switch(c)
        {
            case 'i':
                iface_name = optarg;
                break;
            default:
            usage:
                printf("Usage: ./dhcpprobe -i %%INTERFACE\n");
                exit(1);
        }
    }

    if(iface_name == NULL)
        goto usage;

    int sock_fd;

    printf("Creating socket...\n");
    if((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        exit(1);
    else
        printf("Succesfully created socket.\n");

    printf("Setting socket options...\n");
    int broadcast_enabled = 1;
    if(setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &broadcast_enabled, sizeof(int)) < 0)
        exit(1);
    else
        printf("Succesfully set socket options.\n");

    printf("Binding... ");
    struct sockaddr_in server_send_addr = {0};
    server_send_addr.sin_family = AF_INET;
    server_send_addr.sin_addr.s_addr = inet_addr(BROADCAST_ADDRESS);
    server_send_addr.sin_port = htons(67);
    if(bind(sock_fd, (struct sockaddr*)&server_send_addr, sizeof(struct sockaddr_in)) < 0)
         exit(1);
    else
        printf("Succesfully binded.\n");

    printf("Sending dhcpdiscover...\n");
    dhcp_packet_t dhcp_discover = {0};
    construct_dhcp_discover(&dhcp_discover, iface_name);

    if(sendto(sock_fd, &dhcp_discover, sizeof(dhcp_packet_t), 0, (struct sockaddr*)&server_send_addr, sizeof(struct sockaddr_in)) == -1)
        exit(1);
    else
        printf("Succesfully sent dhcpdiscover.\n");

    close(sock_fd);

    if((sock_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
            exit(1);
    else
        printf("Opened socket to recieve response.\n");

    if(setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &broadcast_enabled, sizeof(int)) < 0)
        exit(1);
    else
        printf("Succesfully set socket options.\n");

    struct sockaddr_in server_recv_addr = {0};
    server_recv_addr.sin_family = AF_INET;
    server_recv_addr.sin_port = htons(68);
    server_recv_addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(sock_fd, (struct sockaddr*)&server_recv_addr, sizeof(struct sockaddr_in)) < 0)
         exit(1);
    else
        printf("Succesfully binded.\n");

    dhcp_packet_t dhcp_recv = {0};
    recieve:
    if(recvfrom(sock_fd, &dhcp_recv, sizeof(dhcp_packet_t), 0, NULL, 0) < 0)
        exit(1);
    else if(dhcp_discover.xid != dhcp_recv.xid)
    {
            printf("Recieved invalid dhcp offer.\n");
            goto recieve;
    }
    else
        printf("Succesfully recieved dhcp offer.\n");

    print_dhcp_offer_info(&dhcp_recv);
}
