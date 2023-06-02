//#include <sys/types.h>
#include <WinSock2.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>

// #include <pcap.h>
// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>
// #include <ctype.h>
// #include <errno.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
//typedef 

typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;

struct ip_header
{
    uint8_t version_header_length;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t fragment_identifier;
    uint16_t fragment_offset_field;
    #define IP_RESERVED_FRAGMENT 0x8000   
    #define IP_DO_NOT_FRAMENT 0x4000
    #define IP_MORE_FRAGMENTS 0x2000

    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t check_sum;
    struct in_addr src;
    struct in_addr dest;

};

#define IP_GET_HEADER_LENGTH(ip) (((ip)->version_header_length) & 0x0f)
#define IP_GET_VERSION(ip)         (((ip)->version_header_length)>>4)

struct udp_header
{
    uint16_t source_port_number;
    uint16_t destination_port_number;
    uint16_t udp_packet_length;
    uint16_t udp_check_sum;
    
};

#define UDP_HEADER_SIZE sizeof(struct udp_header)