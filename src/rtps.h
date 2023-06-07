

#pragma comment(lib,"Ws2_32.lib")


#include <stdio.h>
#include <stdlib.h>
//#include <netinet/in.h>
#include <stdbool.h>
//# include <sys/socket.h>
//# include <arpa/inet.h>
//#include <pcap/pcap.h>
#include <string.h>
#include <time.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <winsock.h>
#include <assert.h>
//#include <>
//#include <Wp>
//#include <sys/time.h>
//#include <net/ethernet.h>
// #include <Time.t.h>

// #include <sys/time.b>
// #include <sys/timeb.h>
#include "ip_header.h"
#include "ethernet.h"



#define TRUE 1
#define FALSE 0 

typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;



struct protocol_version
{
    uint8_t major;
    uint8_t minor;
};

struct vendor_id
{
    uint8_t former;
    uint8_t latter;
};

struct guid_prefix
{
    uint32_t host_id;
    uint32_t app_id;
    uint32_t instance_id;
};

struct entity_id   //Entity ID
{
    unsigned char key[3];
    unsigned char kind;
};


struct guid
{
    struct guid_prefix prefix;
    // uint32_t last_id;
    struct entity_id last_id;
};

struct rtps_header
{
    char rtps_literal[4];
    struct protocol_version protoc_ver;
    struct vendor_id ven_id;
    struct guid_prefix guid_pre;
};




// typedef uint16_t param_id16;
// typedef uint16_t param_length16;






#define PID_KEY_HASH 0x0070
#define PID_SENTINEL 0x0001


struct param_info
{
    uint16_t param_id;
    uint16_t param_len;
};
 

struct parameter_key_hash          //20 bytes
{
    struct param_info info;
    struct guid entity_guid;  //4 + 4 + 4 + 4 ->16 bytes
};



struct parameter_sentinel
{
    uint16_t param_id;
};


struct sd_parameter_sentinel
{
    /* data */
    uint16_t param_id;
};




struct inline_qos //Inline Qos 
{
    struct parameter_key_hash key_hash;
    struct sd_parameter_sentinel sentinel;
};

// typedef struct sd_parameter_sentinel        parameter_sentinel;

// struct serialized_data_
struct sd_parameter_protocol_version  //Serialized Data Prameter Protocol Version
{
    // uint16_t param_id ;
    // uint16_t param_len;
    struct param_info info;
    struct protocol_version proc_version;
    unsigned char extra[2];

};

 struct sd_parameter_vendor_id   //Serialized Data Prameter Vendor ID
{
    // uint16_t id;
    // uint16_t len;
    struct param_info info;
    struct vendor_id ven_id;
    unsigned char extra[2];
};

struct cast_locator
{
    uint32_t kind;
    uint32_t port;
};


struct sd_parameter_metatraffic_locator
{
    // uint16_t param_id;
    // uint16_t param_len;
    struct param_info info; //4byte
    struct cast_locator locator; // 8byte
    unsigned char extra[16]; //16bytes
};

struct sd_parameter_default_multicast_locator
{
    // uint16_t param_id;
    // uint16_t param_length;
    struct param_info info;
    unsigned char param_data[24];
};

struct sd_parameter_default_unicast_locator
{
    // uint16_t param_id;
    // uint16_t param_length;
    struct param_info info;
    struct cast_locator locator;
    unsigned char extra[16];
};

struct lease_duration
{
    uint32_t seconds;
    uint32_t fraction;
};

struct sd_parameter_participant_lease_duration
{
    // uint16_t param_id;
    // uint16_t param_length;
    struct param_info info;
    struct lease_duration lease_dur;
};

struct sd_parameter_participant_guid
{
    struct param_info info;
    struct guid this_guid;
};

struct sd_parameter_builtin_endpoint_set
{
    struct param_info info;
    // unsigned char flags[4];
    uint32_t flags;
};


struct sd_user_data
{
    struct param_info info;
    // unsigned char* parameter_data;
    unsigned char parameter_data[4];
};


#define PORT_BASE 7400 // PORT_BASE
#define DOMAIN_ID_GAIN 250  // DOMAIN_ID_GAIN
#define PARTICIPANT_ID_GAIN 2    // PARTICIPANT_ID_GAIN
#define D0 0    // BUILTIN_MULTICAST_PORT_OFFSET  D0
#define D1 10   // BUILTIN_UNICAST_PORT_OFFSET    D1
#define D2 1    // USER_MULTICAST_PORT_OFFSET     D2
#define D3 11   // USER_UNICAST_PORT_OFFSET       D3

#define SPDP_WELL_KNOWN_MULTICAST_PORT(domainId)              (PORT_BASE + DOMAIN_ID_GAIN * (domainId) + D0)
#define SPDP_WELL_KNOWN_UNICAST_PORT(domainId, participantId) (PORT_BASE + DOMAIN_ID_GAIN * (domainId) + D1 + PARTICIPANT_ID_GAIN * (participantId))
#define USER_MULTICAST_PORT(domainId)                         (PORT_BASE + DOMAIN_ID_GAIN * (domainId) + D2)
#define USER_UNICAST_PORT(domainId, participantId)            (PORT_BASE + DOMAIN_ID_GAIN * (domainId) + D3 + PARTICIPANT_ID_GAIN * (participantId))

struct serialized_data_core
{
    // uint16_t encap_kind;
    // uint16_t encap_option;
    struct sd_parameter_protocol_version                    proc_version;
    struct sd_parameter_vendor_id                           vendor_id;
    struct sd_parameter_metatraffic_locator                 meta_multicast_locator;
    struct sd_parameter_metatraffic_locator                 meta_unicast_locator;
    struct sd_parameter_default_multicast_locator           default_multi;
    struct sd_parameter_default_unicast_locator             default_uni;
    struct sd_parameter_participant_lease_duration          participant_lease_dur;
    struct sd_parameter_participant_guid                    participant_guid;             
    struct sd_parameter_builtin_endpoint_set                endpoint_set;
    struct sd_user_data                                     user_data;
    struct sd_parameter_sentinel                            sentinel;
};

struct serialized_data_encap
{
    unsigned char encap_kind[2];
    unsigned char encap_options[2];
    struct serialized_data_core sd_core;
};

struct writer_seq_number    //Writing Sequence Number
{   
    uint32_t former;
    uint32_t latter;
};

typedef struct _SequenceNumber
{
	uint32_t high;
	uint32_t low;
} SequenceNumber;

struct SubmessageHeader
{
	uint8_t submessageId;
	uint8_t flags;
	uint16_t submessageLength; /* octetsToNextHeader */
} ;

struct DataMessageHeader
{
	uint16_t extraFlags;
	uint16_t octetsToInlineQos;
	uint32_t readerId; // must be interpreted in big endian
	uint32_t writerId; // must be interpreted in big endian
	// SequenceNumber writerSN;
    struct writer_seq_number writerSN;
	// Parameter[]	inlineQos
	// serializedPayload
};


struct Submessage
{
    struct SubmessageHeader* sub_header;
    unsigned char* buffer;
    uint32_t buffer_write_pos;
};

struct sm_data
{
    // unsigned char sub_id;
    // unsigned char flags;
    // uint16_t octets_to_next_header;
    uint16_t extra_flags;
    uint16_t octets_to_inline_qos;
    struct entity_id reader_id;         //Reader ID
    struct entity_id writer_id;         //Writer ID
    struct writer_seq_number w_seq_num;  //Writer Sequence Number
    struct inline_qos in_qos;  //Inline Qos    
    struct serialized_data_encap sz_data_encap;

};

enum DataKind
{
    // RTPS_PACKET_KIND_PARTICIPANT_DISCOVERY = 0x01,
    // RTPS_PACKET_KIND_ENDPOINT_DISCONVERY_READER = 0x02,
    // RTPS_PACKET_KIND_ENDPOINT_DISCOVERY_WRITER = 0x03
    DATA_KIND_PARTICIPANT_DISCOVERY = 0x01,
    DATA_KIND_ENDPOINT_DISCOVERY_READER = 0x02,
    DATA_KIND_ENDPOINT_DISCOVERY_WRITER = 0x03,
    DATA_KIND_USER_DATA = 0x04

};

enum SubmessageKind
{
    INFO_TS = 0x09,
    INFO_DST = 0x0e,
    HEARTBEAT = 0x07,
    HEARTBEAT_FRAG = 0x13,
    ACKNACK = 0x06,
    NACK_FRAG = 0x12,
    DATA = 0x15,
    DATA_FRAG = 0x16,
    SEC_PREFIX = 0x31,
    SEC_POSTFIX = 0x32,
    SEC_BODY = 0x30,
    SRTPS_PREFIX = 0x33,
    SRTPS_POSTFIX = 0x34,
    GAP = 0x08,
    PAD = 0x01
// }SubMessageKind;
};


enum DataFlag
{
    ENDIANNESS = 0x01,
    INLINE_QOS = 0x01<<1,
    DATA_PRESENT = 0x01<<2,
    SERIALIZED_KEY = 0x01<<3

};


#define RTPS_HEADER_SIZE        sizeof(struct rtps_header)
#define BUFFER_SIZE             1024

void print_rtps_info(const unsigned char* rtps, const unsigned int udp_length);

void print_rtps_header(const unsigned char* p_header);


void print_rtps_submessage(const unsigned char* rtps_payload, const unsigned int rtps_submessages_size);


void print_sub_id(enum SubmessageKind submessage_kind);

void print_submessage_flag(const unsigned char submessage_flag);

void send_rtps_packet();


// void CreateSubmessage()
struct Submessage* create_submessage();

int delete_submessage(struct Submessage* submessage);


int put_rtps_header(unsigned char* header);


int setup_rtps_packet(unsigned char* packet);

enum DataElementType
{
    DATA_ELEMENT_TYPE_INT,
    DATA_ELEMENT_TYPE_STRING,
};


struct real_data
{
    unsigned char* buffer;
    uint16_t data_size;
    uint16_t seq_size;
    const char* topic_name;
    const char* type_name;
    int element_count;
    char* element_type;
};

int insert_rtps_submessage(char* sub_pos, struct real_data* r_data ,enum SubmessageKind submessage_kind, enum DataKind data_kind);

int insert_rtps_submessage_info_timestamp(char* sub_pos, struct real_data* r_data,struct Submessage* p_submessage,enum SubmessageKind submessage_kind, enum DataKind data_kind);

int insert_rtps_submessage_info_destination(char* sub_pos, struct real_data* r_data, struct Submessage* p_submessage,enum SubmessageKind submessage_kind, enum DataKind data_kind);

int insert_rtps_submessage_data(char* sub_pos, struct real_data* r_data,struct Submessage* p_submessage,enum SubmessageKind submessage_kind, enum DataKind data_kind);

//int put_user_data(struct real_data* r_data, size_t* p_user_data_size);



int start_capturing_rtps_packets();

int start_sending_rtps_packets();


void break_down_packet(const unsigned char* packet_data);

void my_packet_receive_handler_callback(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *packet_data);


int write_submessage_header(struct Submessage* p_submessage, enum SubmessageKind submessage_kind, enum DataKind data_kind);


int add_submessage_to_packet(char* packet_buffer, struct Submessage* p_submessage);

int add_extra_flags_to_submessage(struct Submessage* p_submessage, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_reader_writer_entity_id_to_submessage(struct Submessage* p_submessage, enum SubmessageKind sub_kind, enum DataKind data_kind);


int add_write_seq_number_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData,enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_inline_qos_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);


int add_protocol_version_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);



int add_vendor_id_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);


int add_locator_info_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind, int domain_id, int participant_id);


int add_participant_guid_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);


int add_enpoint_info_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);


int add_lease_duration_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_user_data_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int process_user_topic_data(struct Submessage* p_submessage, struct real_data* p_rData);

int add_sentinel_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_octets_to_inlineQos_to_submessage(struct Submessage* p_submessage, const uint16_t octets_to_inline_qos);


// int add_guid_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_encapsulation_info_to_submessage(struct Submessage* p_submessage, struct real_data* p_data, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_endpoint_guid_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_group_entity_id_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_topic_name_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_type_name_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);


int add_entity_name_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_reliability_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

int add_type_consistency_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind);

struct ip_buffer
{
    char buf[30];
};

int GetDefaultMyIP(struct ip_buffer* buffer);