// #include <sys/time.h>
// #include <netinet/in.h>
// #include <net/ethernet.h>
// #include <signal.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/types.h>
// #include <errno.h>
// #include <unistd.h>
// #include <netinet/ip.h>
// #include <netinet/tcp.h>
// #include <netinet/udp.h>
// #include <netinet/ip_icmp.h>
// #include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#include "ethernet.h"
#include "rtps.h"


// struct ether_header
// {
//     u_int8_t ether_dest_host[ETH_ALEN];
//     u_int8_t ether_src_host[ETH_ALEN];
//     u_int16_t ether_type;
// }__attribute__((__packed__));

#define PACKET_BUFFER 1048

// char CURRENT_IP[PACKET_BUFFER];

// void check_host_name(int host_name);
// void check_host_entry(char* p_host_entry);
// void check_ip_buffer(const char* ip_buffer);
// void my_packet_receive_handler_callback(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *packet_data)
// {
//     // printf("captured Length : %d\n", header->caplen);
//     // printf("length : %d\n", header->len);
//     // printf("CAP LEN :%d\n", header->caplen);
//     // printf("LEN : %d\n", header->len);
//     // dump_ethernet_header((const unsigned char*)header);

//     const struct ether_header *ethernet_header = NULL;
//     const struct ip_header *ip_header = NULL;
//     // const struct sniff_tcp* tcp_header = NULL;
//     const struct udp_header *udp_header = NULL;
//     const char *my_payload = NULL;

//     int ip_header_size;
//     int udp_header_size;
//     int payload_size;
//     unsigned short ether_type ;
//     const char* src = NULL;
//     const char* dest  = NULL;
//     int total_length;

//     ethernet_header = (struct ether_header *)(packet_data);
//     ether_type = ethernet_header->ether_type;

//     ip_header = (struct ip_header *)(packet_data + SIZE_ETHERNET);
//     ip_header_size = IP_GET_HEADER_LENGTH(ip_header) * 4;
//     if (ip_header_size < 20)
//     {
//         return;
//     }
//     else
//     {
//         // printf("The Length Of The IP Header is %d\n", ip_header_size);
//     }

//     switch (ip_header->protocol)
//     {
//     case IPPROTO_TCP:
//     {
//         // printf("    Protocol : TCP\n");
//         return;
//     }
//     break;

//     case IPPROTO_UDP:
//     {
//         src = inet_ntoa(ip_header->src);
//         if (0 != strcmp(src, CURRENT_IP))
//         {
//             printf("The Source IPs are different!\n");
//             printf("Current Packet From  %s,  My IP %s\n", src, CURRENT_IP);
//         }
//         printf("----------------------\n");
//         printf("Sender : %s\n", src);
//         dest = inet_ntoa(ip_header->dest);
//         printf("Receiver : %s\n", dest);
        
//         // dest = 
//         // print_as_address(ip_header->src.s_addr, 4);
        
//         // printf("Dest :\t\t");
//         // print_as_address(ip_header->dest.s_addr, 4);
//         printf("----------------------\n");
//         // printf("version : %d\n", IP_GET_VERSION(ip_header));
//         // printf("header lenght : %d\n", IP_GET_HEADER_LENGTH(ip_header) * 4);
//         // printf("type of service %d\n", ip_header->type_of_service);
//         // total_length = (int)(ip_header->total_length);
//         // printf("Total Length : %d %04x\n", total_length, total_length);
//         // printf("Fragement Identifier %04x\n", ip_header->fragment_identifier);
//         // printf("Fragment offset : %04x\n", ip_header->fragment_offset_field);
//         // printf("Protocol : UDP\n");
//         // printf("Time To Live : %d\n", ip_header->time_to_live);
//         // printf("Check Sum : %d\n", ip_header->check_sum);
//         // printf("%p Source Address : %s\n",src, src);
//         // printf("%p Dest Address : %s\n",dest, dest);
//     }
//     break;

//     case IPPROTO_ICMP:
//     {
//         // printf("    Protocol : ICMP\n");
//         return;
//     }
//     break;

//     case IPPROTO_IP:
//     {
//         // printf("    Protocol : IP\n");
//         return;
//     }
//     break;
//     default:
//     {
//         // printf("    Protocol : Unknown\n");
//         return;
    
//     }
//     break;
//     }

//     break_down_packet(packet_data);
// }





// #define	ETHERTYPE_PUP		0x0200          /* Xerox PUP */
// #define ETHERTYPE_SPRITE	0x0500		/* Sprite */
// #define	ETHERTYPE_IP		0x0800		/* IP */
// #define	ETHERTYPE_ARP		0x0806		/* Address resolution */
// #define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
// #define ETHERTYPE_AT		0x809B		/* AppleTalk protocol */
// #define ETHERTYPE_AARP		0x80F3		/* AppleTalk ARP */
// #define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
// #define ETHERTYPE_IPX		0x8137		/* IPX */
// #define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
// #define ETHERTYPE_LOOPBACK	0x9000		/* used to test interfaces */

int main(int argc, char *argv[])
{
    // char input[10];
    int input;
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;
    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0)
    {
        /* Tell the user that we could not find a usable */
        /* Winsock DLL.                                  */
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }
    // printf("1. Packet Caputuring  2. Packet Sending\n");
    input = 0;
    while (1)
    {
        /* code */
        printf("1. Packet Caputuring  2. Packet Sending\n");
        scanf_s("%d", &input, sizeof(int));
        fflush(stdin);

        if(input == 1)
        {
            start_capturing_rtps_packets();
        }
        else if(input == 2)
        {
            // start_sending_rtps_packet();
            send_rtps_packet();
        }
        else if((char)input == 'q' || (char)input == 'Q')
        {
            break;
        }
        else
        {
            printf("=====Invalid Input========\n");
        }


        // if(input == '')
    }
    printf("Program Ended\n");
    return 0;

    // char error_buffer[PCAP_ERRBUF_SIZE];
    // pcap_if_t *p_interfaces = NULL;
    // pcap_if_t *p_temp = NULL;
    // pcap_if_t *p_packet_capturing_device = NULL;
    // pcap_t *p_ad_handle = NULL;
    // int interface_idx = 1;
    // char host_buffer[256];
    // pcap_if_t* p_interfaces;
    // pcap_if_t* p_temp;
    // pcap_if_t* p_packet_capturing_device;
    // pcap_t* p_ad_handle;
    // int interface_idx;
    // char host_buffer[256];
    // char *ip_buffer;
    // struct hostent *p_host_entry;
    // int host_name;
    // struct in_addr* p_in_addr ;


    // p_interfaces = NULL;
    // p_temp = NULL;
    // p_packet_capturing_device = NULL;
    // p_ad_handle = NULL;
    // interface_idx = 1;


    


    // send_rtps_packet();
    

    // if (pcap_findalldevs(&p_interfaces, error_buffer) == -1)
    // {
    //     printf("\nEror In pcap find all devices");
    //     return -1;
    // }

    // printf("\n the interfaces present on the system are :");
    // for (p_temp = p_interfaces; p_temp->next != NULL; p_temp = p_temp->next)
    // {
    //     /* code */
    //     // printf("\n %d : Name :%s Description :%s Net :%s, Mask : %s",  interface_idx++, p_temp->name, p_temp->description, (p_temp->addresses->addr->sa_data), (p_temp->addresses->netmask->sa_data));
    //     printf("\n %d : Name :%s Description :%s ", interface_idx++, p_temp->name, p_temp->description);
    // }
    // printf("\n");
    // p_packet_capturing_device = p_interfaces;
    // if (!(p_ad_handle = pcap_open_live(p_packet_capturing_device->name, 65536, 1, 1000, error_buffer)))
    // {
    //     printf("pcap_open_live error %s\n", p_packet_capturing_device->name);
    //     printf("%s\n", error_buffer);
    //     pcap_freealldevs(p_interfaces);
    //     return -1;
    // }

    

    // host_name = gethostname(host_buffer, sizeof(host_buffer));
    // if(host_name == -1)
    // {
    //     printf("get host name error");
    //     exit(1);
    // }

    // p_host_entry = gethostbyname(host_buffer);
    // check_host_entry(host_buffer);
    // p_in_addr = (struct in_addr*)(p_host_entry);
    // ip_buffer = inet_ntoa(*(struct in_addr*)(p_host_entry->h_addr_list[0]));

    // printf("host name : %s\n", host_buffer);
    // printf("host ip : %s", ip_buffer);

    // strcpy(CURRENT_IP, ip_buffer);



    // scanf("%d", &num);
    

    // if(p_ad_handle == NULL)
    // {
    //     printf("pcap_open_live error %s\n", p_packet_capturing_device->name);
    //     pcap_freealldevs(p_interfaces);
    //     return -1;
    // }

    // pcap_loop(p_ad_handle, -1, my_packet_receive_handler_callback, NULL);
    // pcap_close(p_ad_handle);

}
//
//void check_host_name(int host_name)
//{
//    if(host_name == -1)
//    {
//        perror("get host name");
//        exit(1);
//    }
//}
//
//void check_host_entry(char* host_entry)
//{
//    if(host_entry == NULL)
//    {
//        perror("get host by name");
//        exit(1);
//    }
//}
//
//void check_ip_buffer(const char* ip_buffer)
//{
//    if(NULL == ip_buffer)
//    {
//        perror("inet_ntoa");
//        exit(1);
//    }
//}


// int main