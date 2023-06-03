
#include "rtps.h"

void print_rtps_header(const unsigned char *p_header)
{
    unsigned char rtps_literal[5];
    const unsigned char *packet_literal = p_header;
    // const unsigned char* protocol_version = NULL;
    // const unsigned char* vendor_id = NULL;
    // const unsigned char* guid_prefix = NULL;
    const struct rtps_header *header_data = (struct rtps_header *)(p_header);
    const struct protocol_version *cur_proc_ver = (struct protocol_version *)(&(header_data->protoc_ver));
    const struct vendor_id *cur_vendor_id = (struct vendor_id *)(&(header_data->ven_id));
    const struct guid_prefix *cur_guid_prefix = (struct guid_prefix *)(&(header_data->guid_pre));

    if (packet_literal[0] == 'R' && packet_literal[1] == 'T' && packet_literal[2] == 'P' && packet_literal[3] == 'S')
    {
        for (int idx = 0; idx < 4; idx++)
        {
            /* code */
            rtps_literal[idx] = packet_literal[idx];
        }
        rtps_literal[4] = '\0';
    }
    else
    {
        return;
    }

    printf("Magic : %s\n", rtps_literal);

    printf("Protocol Version : %d.%d\n", header_data->protoc_ver.major, header_data->protoc_ver.minor);

    printf("major : %d\nminor : %d\n", cur_proc_ver->major, cur_proc_ver->minor);

    printf("Vendor ID : %d.%d\n", cur_vendor_id->former, cur_vendor_id->latter);

    printf("guid Prefix : %04x%04x%04x\n", cur_guid_prefix->host_id, cur_guid_prefix->app_id, cur_guid_prefix->instance_id);

    printf("host ID : %04x\n", ntohl(cur_guid_prefix->host_id));

    printf("app ID : %04x\n", ntohl(cur_guid_prefix->app_id));

    printf("instance ID : %04x\n", ntohl(cur_guid_prefix->instance_id));
}

void print_rtps_info(const unsigned char *rtps, const unsigned int udp_length)
{
    unsigned int remain_size;
    const unsigned char *submessage;

    remain_size = udp_length - RTPS_HEADER_SIZE - UDP_HEADER_SIZE;
    print_rtps_header(rtps);
    submessage = (rtps + sizeof(struct rtps_header));
    print_rtps_submessage(submessage, remain_size);
}

void print_rtps_submessage(const unsigned char *rtps_payload, const unsigned int rtps_submessges_size)
{
    if (rtps_payload == NULL)
    {
        fprintf(stderr, "payload NULL!!!");
        return;
    }

    // char sub_id = rtps_payload[0];
    unsigned char sub_id;
    enum SubmessageKind sub_kind;

    sub_id = rtps_payload[0];
    sub_kind = (enum SubmessageKind)(sub_id);

    print_sub_id(sub_kind);
    print_submessage_flag(rtps_payload[1]);
}

void print_sub_id(enum SubmessageKind e)
{
    // INFO_TS = 0x09,
    // INFO_DST = 0x0e,
    // HEARTBEAT = 0x07,
    // HEARTBEAT_FRAG = 0x13,
    // ACKNACK = 0x06,
    // NACK_FRAG = 0x12,
    // DATA = 0x15,
    // DATA_FRAG = 0x16,
    // SEC_PREFIX = 0x31,
    // SEC_POSTFIX = 0x32,
    // SEC_BODY = 0x30,
    // SRTPS_PREFIX = 0x33,
    // SRTPS_POSTFIX = 0x34,
    // GAP = 0x08,
    // PAD = 0x01
    printf("submessage ID : ");
    switch (e)
    {
    case INFO_TS:
    {
        printf("INFO_TS");
    }
    break;

    case INFO_DST:
    {
        printf("INFO_DST");
    }
    break;

    case HEARTBEAT:
    {
        printf("HEARTBEAT");
    }
    break;

    case HEARTBEAT_FRAG:
    {
        printf("HEARTBEAT_FRAG");
    }
    break;
        // NACK_FRAG = 0x12,
        // DATA = 0x15,
        // DATA_FRAG = 0x16,
        // SEC_PREFIX = 0x31,

    case ACKNACK:
    {
        printf("ACK_NACK");
    }
    break;

    case NACK_FRAG:
    {
        printf("NACK_FRAG");
    }
    break;

    case DATA:
    {
        printf("DATA");
    }
    break;

    case DATA_FRAG:
    {
        printf("DATA_FRAG");
    }
    break;

    case SEC_PREFIX:
    {
        printf("SEC_PREFIX");
    }
    break;

    case SEC_POSTFIX:
    {
        // SEC_POSTFIX = 0x32,
        // SEC_BODY = 0x30,
        // SRTPS_PREFIX = 0x33,
        // SRTPS_POSTFIX = 0x34,
        // GAP = 0x08,
        // PAD = 0x01
        printf("SEC_POSTFIX");
    }
    break;

    case SEC_BODY:
    {
        printf("SEC_BODY");
    }
    break;

    case SRTPS_PREFIX:
    {
        printf("SEC_PREFIX");
    }
    break;

    case SRTPS_POSTFIX:
    {
        printf("SRTPS_POSTFIX");
    }
    break;

    case GAP:
    {
        printf("GAP");
    }
    break;

    case PAD:
    {
        printf("PAD");
    }
    break;

    default:
    {
        printf("DEFAULT");
    }
    break;
    }
    printf("(0x%02x)\n", e);
}

void print_submessage_flag(const unsigned char submessage_flag)
{
    // for (int flagIdx = 0; flagIdx < 8; i++)
    // {
    //     /* code */
    //     bool b_is_set = submessage_flag & ( 0x01 << flagIdx);

    //     for (int printIdx = 0; printIdx < 8; printIdx++)
    //     {
    //         /* code */
    //         if(flagIdx == printIdx)
    //         {

    //         }
    //         else
    //         {
    //             printf(".");
    //         }
    //     }

    // }
    // printf("0x");
    printf("======Sub Message Flag======\n");
    for (int flagIdx = 8; flagIdx >= 0; flagIdx--)
    {
        /* code */
        bool b_is_bit_set = submessage_flag & (0x01 << flagIdx);
        if (b_is_bit_set)
        {
            printf("1");
        }
        else
        {
            printf("0");
        }
    }
    printf("\n=========================\n");
}

void send_rtps_packet()
{
    // int domain_id;
    // int participant_id;
    SOCKET socket_handle;
    // int address_size;
    char quit;
    unsigned char payload[BUFFER_SIZE];
    struct sockaddr_in receiver_address;
    int sent_data_in_bytes;
    int rtps_data_size;
    const char *sz_receiver_address = "192.168.10.218";


    /*WORD wVersionRequested;
    WSADATA wsaData;
    int err;*/

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
    //wVersionRequested = MAKEWORD(2, 2);

    //err = WSAStartup(wVersionRequested, &wsaData);
    //if (err != 0) {
    //    /* Tell the user that we could not find a usable */
    //    /* Winsock DLL.                                  */
    //    printf("WSAStartup failed with error: %d\n", err);
    //    return 1;
    //}

    // const TCHAR wszFuckIngClassName

    memset(&receiver_address, 0, sizeof(struct sockaddr_in));
    receiver_address.sin_family = AF_INET;

    //if (-1 == inet_aton(sz_receiver_address, (struct in_addr *)(&receiver_address.sin_addr.s_addr)))
    if (-1 == inet_pton(AF_INET, sz_receiver_address, (struct in_addr*)(&receiver_address.sin_addr.s_addr)))
    {
        fprintf(stderr, "Converting address fail");
        return;
    }
    receiver_address.sin_port = htons(4000);
    socket_handle = socket(PF_INET, SOCK_DGRAM, 0);
    if (socket_handle == -1)
    {
        DWORD dwError = GetLastError();
        printf("Failed to Create Socket\n");
        return;
    }

    rtps_data_size = setup_rtps_packet(payload);
    if (rtps_data_size == -1)
    {
        printf("making rtps header error\n");
        return;
    }
    else
    {
        printf("RTPS Packet Size : %d\n", rtps_data_size);
    }
    sent_data_in_bytes = sendto(socket_handle, payload, rtps_data_size, 0, (struct sockaddr *)&receiver_address, sizeof(receiver_address));
    if (sent_data_in_bytes == -1)
    {
        printf("Sending data failed!\n");
        return;
    }
    else
    {
        printf("\n=========Succesfully sent %d bytes of data==========\n", sent_data_in_bytes);
    }
}

int setup_rtps_packet(unsigned char *packet)
{
    // int packet_size = 0;
    // int header_size = 0;
    // int submessage_size = 0;
    // unsigned char* submessage_pos = NULL;
    int packet_size;
    int header_size;
    int submessage_size;
    unsigned char *submessage_pos;

    struct real_data rData;

    
    packet_size = 0;
    header_size = put_rtps_header(packet);
    packet_size += header_size;
    submessage_pos = (packet + header_size);

	submessage_size = insert_rtps_submessage(submessage_pos, NULL, INFO_TS, DATA_KIND_PARTICIPANT_DISCOVERY);
    printf("Time Stamp Submessage Size : %d\n", submessage_size);
    packet_size += submessage_size;
    submessage_pos += submessage_size;

    submessage_size = insert_rtps_submessage(submessage_pos, NULL, INFO_DST, DATA_KIND_PARTICIPANT_DISCOVERY);
    packet_size += submessage_size;
    submessage_pos += submessage_size;

    submessage_size = insert_rtps_submessage(submessage_pos, &rData,DATA, DATA_KIND_PARTICIPANT_DISCOVERY);
    packet_size += submessage_size;
    submessage_pos += submessage_size;

    return packet_size;

    // submessage

    // packet_size+= insert_rtps_submessage

    // submessage[0] = 0x09;
    // submessage[1] = 0x01;
    // submessage[2] = 0x08;
    // submessage[3] = 0x00;
    // data_size+=4;
    // cur_time  = time(NULL);
    // data_size += sizeof(cur_time);
    // memcpy(&(submessage[4]), &cur_time, sizeof(time_t));
    // return data_size;
}

int put_rtps_header(unsigned char *header)
{
    // char rtps_literal[4];
    // struct protocol_version protoc_ver;
    // struct vendor_id ven_id;
    // struct guid_prefix guid_pre;
    if (header == NULL)
    {
        return -1;
    }
    int data_size;
    // int idx = 0;
    struct rtps_header put_header;
    struct protocol_version *p_proc_version;
    struct vendor_id *p_ven_id;
    struct guid_prefix *p_guid_prefix;
    unsigned char *submessage;
    // struct timeb itb;
    // struct timeval time_value;
    // time_t cur_time;
    // put_header = &(put_header)
    memset(&put_header, 0, sizeof(put_header));
    p_proc_version = &(put_header.protoc_ver);
    p_ven_id = &(put_header.ven_id);
    p_guid_prefix = &(put_header.guid_pre);
    submessage = (header + sizeof(struct rtps_header));
    data_size = 0;
    put_header.rtps_literal[0] = 'R';
    put_header.rtps_literal[1] = 'T';
    put_header.rtps_literal[2] = 'P';
    put_header.rtps_literal[3] = 'S';

    p_proc_version->major = 2;
    p_proc_version->minor = 1;

    p_ven_id->former = 1;
    p_ven_id->latter = 17;

    p_guid_prefix->host_id = htonl(0xc0a80ab7);
    p_guid_prefix->app_id = htonl(0xdffbff64);
    p_guid_prefix->instance_id = htonl(0xb1190000);
    memcpy(header, &put_header, sizeof(struct rtps_header));
    data_size += sizeof(struct rtps_header);
    return data_size;

    // submessage[0] = 0x09;
    // submessage[1] = 0x01;
    // submessage[2] = 0x08;
    // submessage[3] = 0x00;
    // data_size+=4;
    // cur_time  = time(NULL);
    // data_size += sizeof(cur_time);
    // memcpy(&(submessage[4]), &cur_time, sizeof(time_t));
    // return data_size;
}

int insert_rtps_submessage(unsigned char *submessage_position, struct real_data* r_data,enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    //     enum e_submessage
    // {
    //     INFO_TS = 0x09,
    //     INFO_DST = 0x0e,
    //     HEARTBEAT = 0x07,
    //     HEARTBEAT_FRAG = 0x13,
    //     ACKNACK = 0x06,
    //     NACK_FRAG = 0x12,
    //     DATA = 0x15,
    //     DATA_FRAG = 0x16,
    //     SEC_PREFIX = 0x31,
    //     SEC_POSTFIX = 0x32,
    //     SEC_BODY = 0x30,
    //     SRTPS_PREFIX = 0x33,
    //     SRTPS_POSTFIX = 0x34,
    //     GAP = 0x08,
    //     PAD = 0x01
    // };
    struct Submessage *p_submessage;
    int submessage_size;
    int (*insert_what)(unsigned char *submessage_pos, struct real_data* p_rData,struct Submessage *p_submessage, enum SubmessageKind submessage_kind, enum DataKind data_kind);
    // int submessage_size = 0;
    p_submessage = create_submessage();
    switch (sub_kind)
    {
    case INFO_TS:
    {
        insert_what = insert_rtps_submessage_info_timestamp;
    }

    break;
    case INFO_DST:
    {
        insert_what = insert_rtps_submessage_info_destination;
    }
    break;

    case DATA:
    {
        insert_what = insert_rtps_submessage_data;
    }
    break;

    default:
        return -1;
        // break;
    }
    submessage_size = insert_what(submessage_position, p_submessage, sub_kind, data_kind);
    write_submessage_header(p_submessage, sub_kind, data_kind);
    submessage_size = add_submessage_to_packet(submessage_position, p_submessage);
    delete_submessage(p_submessage);

    return submessage_size;
}

int insert_rtps_submessage_info_timestamp(unsigned char *sub_pos, struct real_data* r_data,struct Submessage *p_submessage, enum SubmessageKind submessage_kind, enum DataKind data_kind)
{
    time_t cur_time;
    //int submsg_size;
    struct SubmessageHeader *p_header;
    // if(write_submessage_header(p_submessage, submessage_kind, data_kind) == FALSE)
    // {
    //     return FALSE;
    // }

    p_header = p_submessage->sub_header;
    // buffer = p_submessage->b
    cur_time = time(NULL);
    memcpy(p_submessage->buffer, &cur_time, sizeof(time_t));
    p_submessage->buffer_write_pos = sizeof(time_t);
    p_header->submessageLength = sizeof(time_t);
    // submsg_size = sizeof(SubmessageHeader) + sizeof()
    // submsg_size = add_submessage_to_packet(sub_pos, p_submessage);
    return p_submessage->buffer_write_pos;

    // memcpy(sub_pos, &p_submessage, sizeof(time_t));

    // submsg_siz

    // submsg_size = 0;
    // sub_pos[0] = 0x09;
    // sub_pos[1] = 0x01;
    // sub_pos[2] = 0x08;
    // sub_pos[3] = 0x00;
    // submsg_size += 4;
    // cur_time = time(NULL);
    // submsg_size += sizeof(time_t);
    // memcpy(&(sub_pos[4]), &cur_time, sizeof(time_t));

    // return sizeof(struct )
}

int insert_rtps_submessage_info_destination(unsigned char *sub_pos, struct real_data* r_data, struct Submessage *p_submessage, enum SubmessageKind submessage_kind, enum DataKind data_kind)
{
    // return 1;
    // Submessage
    struct SubmessageHeader *p_header;
    uint16_t octets_to_next_header;
    struct guid_prefix cur_guid;
    // int submsg_size;
    int cpy_msg_size;
    uint32_t guid[3];

    // submsg_size;
    // if(write_submessage_header(p_submessage, INFO_DST, data_kind) == FALSE)
    // {
    //     return FALSE;
    // }
    // submsg_size += sizeof(struct SubmessageHeader);
    p_header = p_submessage->sub_header;

    guid[0] = htonl(0xc0a80ab7);
    guid[1] = htonl(0xdffbff64);
    guid[2] = htonl(0xb1190000);
    // cpy_msg_size = 
    memcpy(p_submessage->buffer, guid, 3 * sizeof(uint32_t));
    p_submessage->buffer_write_pos += 3 * sizeof(uint32_t);
    // p_header->submessageLength = p_submessage->buffer_write_pos;

    return p_submessage->buffer_write_pos;
    // submsg_size = sizeof()

    // p_submessage->cur_write

    // memcpy()

    // submsg_size = 0;
    // sub_pos[submsg_size++] = INFO_DST;

    // sub_pos[submsg_size++] = 0x01;
    // octets_to_next_header = 12;
    // memcpy(&(sub_pos[2]), &octets_to_next_header, sizeof(uint16_t));

    // submsg_size += sizeof(uint16_t);

    // memset(&cur_guid, 0, sizeof(struct guid_prefix));
    // cur_guid.host_id = htonl(0xc0a80ab7);
    // cur_guid.host_id = htonl(0xc0a80ab7);
    // cur_guid.app_id = htonl(0xdffbff64);
    // cur_guid.instance_id = htonl(0xb1190000);

    // cur_guid.host_id = htonl(cur_guid.host_id);
    // cur_guid.app_id = htonl(cur_guid.app_id);
    // cur_guid.instance_id = htonl(cur_guid.instance_id);

    // p_guid_prefix->host_id = htonl(0xc0a80ab7);
    // p_guid_prefix->app_id = htonl(0xdffbff64);
    // p_guid_prefix->instance_id = htonl(0xb1190000);
}

int insert_rtps_submessage_data(unsigned char *sub_pos, struct real_data* r_data,struct Submessage *p_submessage, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    // unsigned char sub_id;
    // unsigned char flags;
    // uint16_t octets_to_next_header;
    // uint16_t extra_flags;
    // uint16_t octets_to_inline_qos;
    // struct entity_id reader_id;         //Reader ID
    // struct entity_id writer_id;         //Writer ID
    // struct writer_seq_number w_seq_num;  //Writer Sequence Number
    // struct inline_qos in_qos;  //Inline Qos
    // struct serialized_data_encap sz_data_encap;
    int submsg_size;
    struct entity_id *p_reader_id;
    struct entity_id *p_writer_id;
    struct writer_seq_number *p_seq_num;
    struct inline_qos *p_inline_qos;
    struct param_info *p_param_info;
    struct parameter_key_hash *p_key_hash;
    struct sd_parameter_sentinel *p_sentinel;
    struct serialized_data_encap *p_encap_sz_data;
    struct serialized_data_core *p_core_sz_data;
    struct sd_parameter_protocol_version *p_param_proc_version;
    struct sd_parameter_vendor_id *p_param_vendor_id;
    struct sd_parameter_metatraffic_locator *p_meta_multicast_locator;
    struct sd_parameter_metatraffic_locator *p_meta_unicast_locator;
    struct sd_parameter_default_multicast_locator *p_default_multi_locator;
    struct sd_parameter_default_unicast_locator *p_default_uni_locator;
    struct sd_parameter_participant_lease_duration *p_lease_duration;
    struct sd_parameter_participant_guid *p_part_guid;
    struct sd_parameter_builtin_endpoint_set *p_endpoint_set;
    struct sd_user_data *p_user_data;
    struct sd_parameter_sentinel *p_param_sentinel;
    struct cast_locator *p_locator;
    struct lease_duration *p_lease_dur;
    struct guid *p_guid;
    unsigned int domain_id;
    unsigned int participant_id;
    unsigned char *p_ch_user_data;
    struct guid_prefix *p_guid_prefix;
    struct entity_id *p_entity_id;
    struct sm_data *p_data;
    struct protocol_version *p_protocol_ver;
    struct vendor_id *p_ven_id;

    struct SubmessageHeader *p_header;

    p_header = p_submessage->sub_header;
    // if(write_submessage_header(p_submessage, DATA, data_kind) == FALSE)
    // {
    //     return FALSE;
    // }

    // SubMessage ID
    //  sub_pos[0] = 0x15;

    // submsg_size = 0;
    // const char param_dat
    domain_id = 1;
    participant_id = 0;

    // p_data = (struct sm_data *)sub_pos;
    // submessage ID
    // p_data->sub_id = 0x15;
    // flag data
    // p_data->flags = 0x07;
    /// extra flag
    // p_data->extra_flags = 0x00;
    //add_extra_flags(p_submessage, sub_kind, data_kind);
    // bytes count to inline qos
    //p_data->octets_to_inline_qos = (uint16_t)(2 * (sizeof(struct entity_id)) + sizeof(struct writer_seq_number));

    //add_reader_writer_entity_id(p_submessage, sub_kind, data_kind);


    // add_reader


    
// int add_reader_writer_entity_id(struct Submessage* p_submessage, enum SubmessageKind sub_kind, enum DataKind data_kind);

    // Reader ID
    //     typedef enum
    // {
    //     // RTPS_PACKET_KIND_PARTICIPANT_DISCOVERY = 0x01,
    //     // RTPS_PACKET_KIND_ENDPOINT_DISCONVERY_READER = 0x02,
    //     // RTPS_PACKET_KIND_ENDPOINT_DISCOVERY_WRITER = 0x03
    //     DATA_KIND_PARTICIPANT_DISCOVERY = 0x01,
    //     DATA_KIND_ENDPOINT_DISCOVERY_READER = 0x02,
    //     DATA_KIND_ENDPOINT_DISCOVERY_WRITER = 0x03

    // }DataKind;
    // p_reader_id = &(p_data->reader_id);
    // p_writer_id = &(p_data->writer_id);

    // if (data_kind == DATA_KIND_PARTICIPANT_DISCOVERY)
    // {
    //     p_reader_id->key[0] = 0x00;
    //     p_reader_id->key[1] = 0x01;
    //     p_reader_id->key[2] = 0x00;
    //     p_reader_id->kind = 0xc7;

    //     // Writer ID
    //     p_writer_id->key[0] = 0x00;
    //     p_writer_id->key[1] = 0x01;
    //     p_writer_id->key[2] = 0x00;
    //     // p_reader_id->kind = 0xc2;
    //     p_writer_id->kind = 0xc2;
    // }
    // else if (data_kind == DATA_KIND_ENDPOINT_DISCOVERY_WRITER)
    // {
    //     p_reader_id->key[0] = 0x00;
    //     p_reader_id->key[1] = 0x00;
    //     p_reader_id->key[2] = 0x03;
    //     p_reader_id->kind = 0xc7;

    //     // Writer ID
    //     p_writer_id->key[0] = 0x00;
    //     p_writer_id->key[1] = 0x0;
    //     p_writer_id->key[2] = 0x03;
    //     p_writer_id->kind = 0xc2;
    // }
    // else if (data_kind == DATA_KIND_ENDPOINT_DISCOVERY_READER)
    // {
    //     p_reader_id->key[0] = 0x00;
    //     p_reader_id->key[1] = 0x00;
    //     p_reader_id->key[2] = 0x04;
    //     p_reader_id->kind = 0xc7;

    //     // Writer ID
    //     p_writer_id->key[0] = 0x00;
    //     p_writer_id->key[1] = 0x0;
    //     p_writer_id->key[2] = 0x04;
    //     p_writer_id->kind = 0xc2;
    // }
    // else // User Data Reader || User Data Writer....
    // {
    // }

    // Write Seq Number

    
    /*p_seq_num = &(p_data->w_seq_num);
    p_seq_num->former = 0x00;
    p_seq_num->latter = 0x01;

    p_inline_qos = &(p_data->in_qos);
    p_key_hash = &(p_inline_qos->key_hash);
    p_param_info = &(p_key_hash->info);
    p_param_info->param_id = (uint16_t)0x0070;
    p_param_info->param_len = (uint16_t)(sizeof(struct guid));

    p_sentinel = &(p_inline_qos->sentinel);
    p_sentinel->param_id = 0x01;*/





   /* p_encap_sz_data = &(p_data->sz_data_encap);
    p_encap_sz_data->encap_kind[0] = 0x00;
    p_encap_sz_data->encap_kind[1] = 0x03;
    p_encap_sz_data->encap_options[0] = 0x00;
    p_encap_sz_data->encap_options[1] = 0x00;



    p_core_sz_data = &(p_encap_sz_data->sd_core);*/

    //     struct serialized_data_core
    // {
    //     // uint16_t encap_kind;
    //     // uint16_t encap_option;
    //     struct sd_parameter_protocol_version proc_version;
    //     struct sd_parameter_vendor_id vendor_id;
    //     struct sd_parameter_metatraffic_locator meta_multicast_locator;
    //     struct sd_parameter_metatraffic_locator meta_unicast_locator;
    //     struct sd_parameter_default_multicast_locator default_multi;
    //     struct sd_parameter_default_unicast_locator default_uni;
    //     struct sd_parameter_participant_lease_duration;
    //     struct sd_parameter_participant_guid guid;
    //     struct sd_parameter_builtin_endpoint_set endpoint_set;
    //     struct sd_user_data user_data;
    //     struct sd_parameter_sentinel sentinel;
    // };

    //  struct sd_parameter_protocol_version* p_proc_version;
    //     struct sd_parameter_vendor_id* p_vendor_id ;
    //     struct sd_parameter_metatraffic_locator* p_meta_multicast_locator ;
    //     struct sd_parameter_metatraffic_locator* p_meta_unicast_locator ;
    //     struct sd_parameter_default_mulitcast_locator* p_default_multi_locator ;
    //     struct sd_parameter_default_unicast_locator* p_default_uni_locator;
    //     struct sd_parameter_participant_lease_duration* p_lease_duration;
    //     struct sd_parameter_participant_guid* p_part_guid;
    //     struct sd_parameter_builtin_endpoint_set* p_endpoint_set;
    //     struct sd_user_data* p_user_data;
    //     struct sd_parameter_sentinel* p_param_sentinel;

    // protocol version
   // p_param_proc_version = &(p_core_sz_data->proc_version);
   // p_param_info = &(p_param_proc_version->info);
   // p_param_info->param_id = (uint16_t)0x15;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_protocol_version) - sizeof(struct param_info));

   // p_protocol_ver = &(p_param_proc_version->proc_version);
   // p_protocol_ver->major = (uint8_t)0x02;
   // p_protocol_ver->minor = (uint8_t)0x01;

   // // vendor id
   // p_param_vendor_id = &(p_core_sz_data->vendor_id);
   // p_param_info = &(p_param_vendor_id->info);
   // p_param_info->param_id = (uint16_t)0x16;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_vendor_id) - sizeof(struct param_info));
   // p_ven_id = &(p_param_vendor_id->ven_id);
   // p_ven_id->former = (uint8_t)0x01;
   // p_ven_id->latter = (uint8_t)0x11;

   // p_meta_multicast_locator = &(p_core_sz_data->meta_multicast_locator);
   // p_param_info = &(p_meta_multicast_locator->info);
   // p_param_info->param_id = (uint16_t)0x0033;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_metatraffic_locator) - sizeof(struct param_info));
   // p_locator = &(p_meta_multicast_locator->locator);
   // p_locator->kind = (uint32_t)0x01;
   // p_locator->port = SPDP_WELL_KNOWN_MULTICAST_PORT(domain_id);

   // p_meta_unicast_locator = &(p_core_sz_data->meta_unicast_locator);
   // p_param_info = &(p_meta_unicast_locator->info);
   // p_param_info->param_id = (uint16_t)0x0032;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_metatraffic_locator) - sizeof(struct param_info));
   // p_locator = &(p_meta_unicast_locator->locator);
   // p_locator->kind = (uint32_t)0x01;
   // p_locator->port = SPDP_WELL_KNOWN_UNICAST_PORT(domain_id, participant_id);

   // p_default_multi_locator = &(p_core_sz_data->default_multi);
   // p_param_info = &(p_default_multi_locator->info);
   // p_param_info->param_id = (uint16_t)0x0048;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_default_multicast_locator) - sizeof(struct param_info));
   // p_ch_user_data = p_default_multi_locator->param_data;
   // memset(p_ch_user_data, 0, 24);
   // p_ch_user_data[0] = 0x01;
   // p_ch_user_data[19] = 0xef;
   // p_ch_user_data[20] = 0xff;
   // p_ch_user_data[21] = 0xf0;
   // p_ch_user_data[22] = 0x00;
   // p_ch_user_data[23] = 0x01;
   // // p_default_multicast_data = p_default_multi_locator->param_data;

   // // p_locator = &(p_default_muilti_locator->locator);
   // // p_locator

   // // p_locator->
   // // p_locator->port =
   // // p_meta_m
   // // uint32_t kind;
   // // uint32_t port;

   // p_default_uni_locator = &(p_core_sz_data->default_uni);
   // p_param_info = &(p_default_uni_locator->info);
   // p_param_info->param_id = (uint16_t)0x0031;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_default_unicast_locator) - sizeof(struct param_info));
   // p_locator = &(p_default_uni_locator->locator);
   // p_locator->kind = (uint32_t)0x01;
   // p_locator->port = USER_UNICAST_PORT(domain_id, participant_id);




   // p_lease_duration = &(p_core_sz_data->participant_lease_dur);
   // p_param_info = &(p_lease_duration->info);
   // p_param_info->param_id = (uint16_t)0x02;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_participant_lease_duration) - sizeof(struct param_info));
   // p_lease_dur = &(p_lease_duration->lease_dur);
   // p_lease_dur->seconds = (uint32_t)0x0a;
   // p_lease_dur->fraction = (uint32_t)0x00;

   // p_part_guid = &(p_core_sz_data->participant_guid);
   // p_param_info = &(p_part_guid->info);
   // p_param_info->param_id = (uint16_t)0x50;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_participant_guid) - sizeof(struct param_info));
   // p_guid = &(p_part_guid->this_guid);
   // p_guid_prefix = &(p_guid->prefix);
   // p_entity_id = &(p_guid->last_id);
   // p_guid_prefix->host_id = htonl(0xc0a80ab7);
   // p_guid_prefix->app_id = htonl(0xdffbff64);
   // p_guid_prefix->instance_id = htonl(0xb1190000);
   // p_entity_id->key[0] = 0x00;
   // p_entity_id->key[1] = 0x00;
   // p_entity_id->key[2] = 0x01;
   // p_entity_id->kind = 0xc1;

   // p_endpoint_set = &(p_core_sz_data->endpoint_set);
   // p_param_info = &(p_endpoint_set->info);
   // p_param_info->param_id = (uint16_t)0x58;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_builtin_endpoint_set) - sizeof(struct param_info));
   // p_endpoint_set->flags = 0x0c3f;

   // // p_guid_prefix->host_id = htonl(0xc0a80ab7);
   // // p_guid_prefix->app_id = htonl(0xdffbff64);
   // // p_guid_prefix->instance_id = htonl(0xb1190000);

   // p_user_data = &(p_core_sz_data->user_data);
   // p_param_info = &(p_user_data->info);
   // p_param_info->param_id = 0x8000;
   // p_param_info->param_len = (uint16_t)(sizeof(struct sd_user_data) - sizeof(struct param_info));
   // p_ch_user_data = p_user_data->parameter_data;
   // p_ch_user_data[0] = (unsigned char)0x02;
   // p_ch_user_data[1] = (unsigned char)0x08;
   // p_ch_user_data[2] = (unsigned char)0x00;
   // p_ch_user_data[3] = (unsigned char)0x00;

   // // p_param_info->param_len =

   // p_param_sentinel = &(p_core_sz_data->sentinel);
   // p_param_sentinel->param_id = (uint16_t)0x01;


   ///* p_data->octets_to_next_header = 0;
   // p_data->octets_to_next_header += (uint16_t)sizeof(struct sm_data);
   // p_data->octets_to_next_header -= 4;*/

   // submsg_size = (int)(sizeof(struct sm_data));
submsg_size = 1;
    return submsg_size;
}

//int put_user_data(char *user_data_pos, size_t *p_user_data_size)
//{
//    if (NULL == user_data_pos)
//    {
//        return -1;
//    }
//    if (NULL == p_user_data_size)
//    {
//        return -1;
//    }
//
//    *p_user_data_size = 0;
//    return 1;
//}

int start_capturing_rtps_packets()
{
   ///* char error_buffer[PCAP_ERRBUF_SIZE];
   // pcap_if_t *p_interfaces;
   // pcap_if_t *p_temp;
   // pcap_if_t *p_packet_capturing_device;
   // pcap_t *p_ad_handle;*/
   // int interface_idx;
   // char host_buffer[256];
   // char *ip_buffer;
   // struct hostent *p_host_entry;
   // int host_name;
   // struct in_addr *p_in_addr;

   // interface_idx = 1;
   // memset(host_buffer, 0, 256);

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

   // pcap_loop(p_ad_handle, -1, my_packet_receive_handler_callback, NULL);
   // pcap_close(p_ad_handle);

    return 1;
}

int start_sending_rtps_packets()
{
    send_rtps_packet();

    return 1;
}

void break_down_packet(const unsigned char *packet_data)
{
    int ip_header_size;
    const struct ip_header *ip_header;
    uint16_t udp_total_length;
    unsigned char *udp_payload;
    struct udp_header *cur_packet_udp_header;

    ip_header = (struct ip_header *)(packet_data + SIZE_ETHERNET);
    ip_header_size = IP_GET_HEADER_LENGTH(ip_header) * 4;

    cur_packet_udp_header = (struct udp_header *)(packet_data + SIZE_ETHERNET + ip_header_size);
    printf("Source Port Number : %d\n", ntohs(cur_packet_udp_header->source_port_number));
    printf("Destination Port Number : %d\n", ntohs(cur_packet_udp_header->destination_port_number));

    udp_total_length = ntohs(cur_packet_udp_header->udp_packet_length);
    printf("UDP Packet Length : %d\n", udp_total_length);

    udp_payload = (unsigned char *)(packet_data + SIZE_ETHERNET + ip_header_size + sizeof(struct udp_header));
    print_rtps_info(udp_payload, udp_total_length);
}

#define DEFAULT_SUBMESSAGE_BUFFER_SIZE 1024

struct Submessage *create_submessage()
{
    struct Submessage *pSubmessage;

    pSubmessage = (struct Submessage *)malloc(sizeof(struct Submessage));
    if (pSubmessage != NULL)
    {
        pSubmessage->sub_header = (struct SubmessageHeader*)malloc(sizeof(struct SubmessageHeader));
        pSubmessage->buffer = (unsigned char*)malloc(DEFAULT_SUBMESSAGE_BUFFER_SIZE);
        pSubmessage->buffer_write_pos = 0;
    }
    
    // pSubmessage_header = pSubmessage->sub_header;

    return pSubmessage;
}

int write_submessage_header(struct Submessage *p_submessage, enum SubmessageKind submessage_kind, enum DataKind data_kind)
{
    struct SubmessageHeader *p_header;
    uint8_t write_submessageId;
    uint8_t write_submessage_flag;
    // p_header = p_submessage
    if (p_submessage == NULL)
    {
        return 0;
    }
    write_submessage_flag = 0;
    write_submessage_flag |= ENDIANNESS;
    p_header = p_submessage->sub_header;
    switch (submessage_kind)
    {
    case DATA:
    {
        write_submessageId = 0x15;
        if (data_kind == DATA_KIND_ENDPOINT_DISCOVERY_WRITER || data_kind == DATA_KIND_PARTICIPANT_DISCOVERY)
        {
            write_submessage_flag |= INLINE_QOS;
        }
        write_submessage_flag |= DATA_PRESENT;
    }
    break;

    case INFO_TS:
    {
        write_submessageId = 0x09;
    }
    break;

    case INFO_DST:
    {
        write_submessageId = 0x0e;
    }
    break;

    default:
    {
        write_submessageId = 0x01;
    }
    break;
    }

    p_header->submessageId = write_submessageId;
    p_header->flags = write_submessage_flag;
    p_header->submessageLength = p_submessage->buffer_write_pos;
    return 1;
}

int delete_submessage(struct Submessage *submessage)
{
    if (NULL != submessage)
    {
        if (NULL != submessage->sub_header)
        {
            free(submessage->sub_header);
            submessage->sub_header = NULL;
        }
        if (NULL != submessage->buffer)
        {
            free(submessage->buffer);
            submessage->buffer = NULL;
        }
        free(submessage);
        return 1;
    }
    else
    {
        return 0;
    }
}

void my_packet_receive_handler_callback(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *packet_data)
{
    //// printf("captured Length : %d\n", header->caplen);
    //// printf("length : %d\n", header->len);
    //// printf("CAP LEN :%d\n", header->caplen);
    //// printf("LEN : %d\n", header->len);
    //// dump_ethernet_header((const unsigned char*)header);

    //// const struct ether_header *ethernet_header = NULL;
    //const struct ether_header *ethernet_header;
    //// const struct ip_header *ip_header = NULL;
    //const struct ip_header *ip_header;
    //// const struct sniff_tcp* tcp_header = NULL;
    //// const struct udp_header *udp_header = NULL;
    //const struct udp_header *udp_header;
    //const char *my_payload;

    //int ip_header_size;
    //int udp_header_size;
    //int payload_size;
    //unsigned short ether_type;
    //const char *src;
    //const char *dest;
    //int total_length;

    //total_length = 0;
    //ethernet_header = (struct ether_header *)(packet_data);
    //ether_type = ethernet_header->ether_type;

    //ip_header = (struct ip_header *)(packet_data + SIZE_ETHERNET);
    //ip_header_size = IP_GET_HEADER_LENGTH(ip_header) * 4;
    //if (ip_header_size < 20)
    //{
    //    return;
    //}
    //else
    //{
    //    // printf("The Length Of The IP Header is %d\n", ip_header_size);
    //}

    //switch (ip_header->protocol)
    //{
    //case IPPROTO_TCP:
    //{
    //    // printf("    Protocol : TCP\n");
    //    return;
    //}
    //break;

    //case IPPROTO_UDP:
    //{
    //    // if (0 != strcmp(src, CURRENT_IP))
    //    // {
    //    // printf("The Source IPs are different!\n");
    //    // printf("Current Packet From  %s,  My IP %s\n", src, CURRENT_IP);
    //    // }
    //    src = inet_ntoa(ip_header->src);
    //    printf("----------------------\n");
    //    printf("Sender : %s\n", src);
    //    dest = inet_ntoa(ip_header->dest);
    //    printf("Receiver : %s\n", dest);
    //    printf("----------------------\n");

    //    // dest =
    //    // print_as_address(ip_header->src.s_addr, 4);

    //    // printf("Dest :\t\t");
    //    // print_as_address(ip_header->dest.s_addr, 4);
    //    // printf("version : %d\n", IP_GET_VERSION(ip_header));
    //    // printf("header lenght : %d\n", IP_GET_HEADER_LENGTH(ip_header) * 4);
    //    // printf("type of service %d\n", ip_header->type_of_service);
    //    // total_length = (int)(ip_header->total_length);
    //    // printf("Total Length : %d %04x\n", total_length, total_length);
    //    // printf("Fragement Identifier %04x\n", ip_header->fragment_identifier);
    //    // printf("Fragment offset : %04x\n", ip_header->fragment_offset_field);
    //    // printf("Protocol : UDP\n");
    //    // printf("Time To Live : %d\n", ip_header->time_to_live);
    //    // printf("Check Sum : %d\n", ip_header->check_sum);
    //    // printf("%p Source Address : %s\n",src, src);
    //    // printf("%p Dest Address : %s\n",dest, dest);
    //}
    //break;

    //case IPPROTO_ICMP:
    //{
    //    // printf("    Protocol : ICMP\n");
    //    return;
    //}
    //break;

    //case IPPROTO_IP:
    //{
    //    // printf("    Protocol : IP\n");
    //    return;
    //}
    //break;
    //default:
    //{
    //    // printf("    Protocol : Unknown\n");
    //    return;
    //}
    //break;
    //}

    //break_down_packet(packet_data);
}

int add_submessage_to_packet(unsigned char *packet_buffer, struct Submessage *p_submessage)
{
    struct SubmessageHeader *p_subHeader;
    unsigned char *submessage_payload_pos;
    int copy_size;
    if (NULL == p_submessage)
    {
        return -1;
    }

    if (NULL == packet_buffer)
    {
        return -1;
    }
    copy_size = 0;
    p_subHeader = p_submessage->sub_header;
    submessage_payload_pos = packet_buffer + sizeof(struct SubmessageHeader);

    memcpy(packet_buffer, p_subHeader, sizeof(struct SubmessageHeader));
    copy_size += sizeof(struct SubmessageHeader);
    // memcpy(packet_buffer + sizeof)
    // memcpy()d
    memcpy(submessage_payload_pos, p_submessage->buffer, p_submessage->buffer_write_pos);
    copy_size += p_submessage->buffer_write_pos;

    return copy_size;
}

int add_extra_flags_to_submessage(struct Submessage *p_submessage, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    uint16_t extra_flags;
    uint32_t copy_submsg_size;
    // unsigned char* buff
    //   DATA_KIND_PARTICIPANT_DISCOVERY = 0x01,
    // DATA_KIND_ENDPOINT_DISCOVERY_READER = 0x02,
    // DATA_KIND_ENDPOINT_DISCOVERY_WRITER = 0x03,
    // DATA_KIND_USER_DATA = 0x04
    // p_submessage()
    extra_flags = 0;
    switch (data_kind)
    {
    case DATA_KIND_PARTICIPANT_DISCOVERY:
    {
        // extra_flags |= 0x0
    }
    break;

    case DATA_KIND_ENDPOINT_DISCOVERY_READER:
    {

    }
    break;

    case DATA_KIND_ENDPOINT_DISCOVERY_WRITER:
    {

    }
    break;

    default:
        break;
    }
    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), &extra_flags, sizeof(extra_flags));
    copy_submsg_size = sizeof(extra_flags);
    p_submessage->buffer_write_pos += copy_submsg_size;
    

    return copy_submsg_size;
    // return sizeof(extra_flags);
    // return sizeof()
}

int add_reader_writer_entity_id_to_submessage(struct Submessage* p_submessage, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    char reader_writer[8];
    //  writer[4];
     if (data_kind == DATA_KIND_PARTICIPANT_DISCOVERY)
    {

        reader_writer[0] = 0x00;
        reader_writer[1] = 0x01;
        reader_writer[2] = 0x00;
        reader_writer[3] = 0xc7;
        reader_writer[4] = 0x00;
        reader_writer[5] = 0x01;
        reader_writer[6] = 0x00;
        reader_writer[7] = 0xc2;

    }
    else if (data_kind == DATA_KIND_ENDPOINT_DISCOVERY_WRITER)
    {
      
        reader_writer[0] = 0x00;
        reader_writer[1] = 0x00;
        reader_writer[2] = 0x03;
        reader_writer[3] = 0xc7;
        reader_writer[4] = 0x00;
        reader_writer[5] = 0x0;
        reader_writer[6] = 0x03;
        reader_writer[7] = 0xc2;
    }
    else if (data_kind == DATA_KIND_ENDPOINT_DISCOVERY_READER)
    {
       
        reader_writer[0] = 0x00;
        reader_writer[1] = 0x00;
        reader_writer[2] = 0x04;
        reader_writer[3] = 0xc7;
        reader_writer[4] = 0x00;
        reader_writer[5] = 0x00;
        reader_writer[6] = 0x04;
        reader_writer[7] = 0xc2;
    }
     else // User Data Reader || User Data Writer....
    {
         assert(false);
         //_ASSERT_EXPT
    }
    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), reader_writer, 8);
    p_submessage->buffer_write_pos += 8;
}

// int add_write_seq_number
int add_write_seq_number_to_submessage(struct Submessage *p_submessage, struct real_data *p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    //  p_seq_num = &(p_data->w_seq_num);
    // p_seq_num->former = 0x00;
    // p_seq_num->latter = 0x01;
    int cpy_msg_size;
    if(p_rData == NULL)
    {
        return 0;
    }
    // uint32_t former;
    // uint32_t latter;

    // former = 0x00;
    // latter= r_data->seq_number;
    uint32_t seq_number[2];
    seq_number[0] = 0x00;
    seq_number[1] = p_rData->seq_size;

    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), seq_number, 2 * sizeof(uint32_t));
    cpy_msg_size = sizeof(uint32_t) * 2;
    p_submessage->buffer_write_pos += cpy_msg_size;

    return cpy_msg_size;
}

int add_inline_qos_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    int                             cpy_msg_size;
    struct inline_qos               cur_qos;
    struct parameter_key_hash*      p_key_hash;
    struct sd_parameter_sentinel*   p_sentinel;
    struct param_info*              p_info;
    struct guid*                    p_guid;  //4 + 4 + 4 + 4 ->16 bytes

    if(p_rData  == NULL)
    {
        return 0;
    }

    p_key_hash = &(cur_qos.key_hash);
    p_sentinel = &(cur_qos.sentinel);
    p_info = &(p_key_hash->info);
    p_guid = &(p_key_hash->entity_guid);

    p_info->param_id = (uint16_t)0x0070;                //Key Hash Parameter ID
    p_info->param_len = (uint16_t)sizeof(struct guid);

    // p_sentinel->param
    p_sentinel->param_id = 0x01;     //Sentinel Parameter ID
    cpy_msg_size = sizeof(struct inline_qos);
    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), &cur_qos, cpy_msg_size);
    p_submessage->buffer_write_pos+=cpy_msg_size;

    return cpy_msg_size;    
}


int add_protocol_version_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    // p_param_proc_version = &(p_core_sz_data->proc_version);
    // p_param_info = &(p_param_proc_version->info);
    // p_param_info->param_id = (uint16_t)0x15;
    // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_protocol_version) - sizeof(struct param_info));

    // p_protocol_ver = &(p_param_proc_version->proc_version);
    // p_protocol_ver->major = (uint8_t)0x02;
    // p_protocol_ver->minor = (uint8_t)0x01;
    int cpy_msg_size;
    uint16_t protocol_ver_info[4];
    cpy_msg_size = 3 * sizeof(uint16_t) + 2; // extra... buffer
    protocol_ver_info[0] = (uint16_t)0x15;
    protocol_ver_info[1] = (uint16_t)(cpy_msg_size - 4);
    protocol_ver_info[2] = (uint16_t)0x0201;
    protocol_ver_info[3] = (uint16_t)0x00;
    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), protocol_ver_info, cpy_msg_size);
    p_submessage->buffer_write_pos += cpy_msg_size;

    return cpy_msg_size;

}

int add_vendor_id_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    //     p_param_vendor_id = &(p_core_sz_data->vendor_id);
    // p_param_info = &(p_param_vendor_id->info);
    // p_param_info->param_id = (uint16_t)0x16;
    int cpy_msg_size;
    uint16_t vendor_id_info[4];
    cpy_msg_size = 3 * sizeof(uint16_t) + 2;//extra
    // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_vendor_id) - sizeof(struct param_info));
    // p_ven_id = &(p_param_vendor_id->ven_id);
    // p_ven_id->former = (uint8_t)0x01;
    // p_ven_id->latter = (uint8_t)0x11;
    vendor_id_info[0] = (uint16_t)0x16;
    vendor_id_info[1] = (uint16_t)(cpy_msg_size - 4);
    vendor_id_info[2] = (uint16_t)0x0111;
    vendor_id_info[3] = (uint16_t)0x00;
    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), vendor_id_info, cpy_msg_size);
    p_submessage->buffer_write_pos+=cpy_msg_size;

    return cpy_msg_size;
}


int add_locator_info_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind, int domain_id, int participant_id)
{
    int cast_info_idx;
    int cpy_msg_size;
    uint32_t cast_info[30];
    
    cast_info_idx=0;
    cast_info[cast_info_idx++] = 0x33002800;    //0x33 -> param id   0x28 ->
    cast_info[cast_info_idx++] = 0x01;
    cast_info[cast_info_idx++] = SPDP_WELL_KNOWN_MULTICAST_PORT(domain_id);
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;

    
     
    cast_info[cast_info_idx++] = 0x32002800;
    cast_info[cast_info_idx++] = 0x01;
    cast_info[cast_info_idx++] = SPDP_WELL_KNOWN_UNICAST_PORT(domain_id, participant_id);
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;
    
    


    // p_meta_multicast_locator = &(p_core_sz_data->meta_multicast_locator);
    // p_param_info = &(p_meta_multicast_locator->info);
    // p_param_info->param_id = (uint16_t)0x0033;
    // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_metatraffic_locator) - sizeof(struct param_info));
    cast_info[cast_info_idx++] = 0x48002800;
    cast_info[cast_info_idx++] = 0x01;
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;
    cast_info[cast_info_idx++] = 0x00;


    cast_info[cast_info_idx++] = 0x31002800;
    cast_info[cast_info_idx++] = 0x01;
    cast_info[cast_info_idx++] = USER_UNICAST_PORT(domain_id, participant_id);
    cpy_msg_size = sizeof(uint32_t) * cast_info_idx;

    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), cast_info, cpy_msg_size);
    p_submessage->buffer_write_pos += cpy_msg_size;
    return cpy_msg_size;
}


int add_lease_duration_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    int cpy_msg_size;
    uint32_t lease_dur[4];
    // cpy_msg_siz
    lease_dur[0] = 0x02001000;
    lease_dur[1] = 0x0a;
    lease_dur[2] = 0x00;
    cpy_msg_size = sizeof(uint32_t) * 3;

    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), lease_dur, cpy_msg_size);

    return cpy_msg_size;
    // p_lease_dur->fraction = (uint32_t)0x00;
}


int add_participant_guid_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    uint32_t guid_info[5];
    int cpy_msg_size;
    //p_part_guid = &(p_core_sz_data->participant_guid);
    guid_info[0] = 0x50001000;
    guid_info[1] = htonl(0xc0a80ab7);
    guid_info[2] = htonl(0xdffbff64);
    guid_info[3] = htonl(0xb1190000);
    guid_info[4] = 0x000001c1;

    cpy_msg_size = sizeof(uint32_t) * 5;
    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), guid_info, cpy_msg_size);
    p_submessage->buffer_write_pos+=cpy_msg_size;
    return cpy_msg_size;

    // p_param_info = &(p_part_guid->info);
    // p_param_info->param_id = (uint16_t)0x50;
    // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_participant_guid) - sizeof(struct param_info));
    // p_guid = &(p_part_guid->this_guid);
    // p_guid_prefix = &(p_guid->prefix);
    // p_entity_id = &(p_guid->last_id);
    // p_guid_prefix->host_id = htonl(0xc0a80ab7);
    // p_guid_prefix->app_id = htonl(0xdffbff64);
    // p_guid_prefix->instance_id = htonl(0xb1190000);
    // p_entity_id->key[0] = 0x00;
    // p_entity_id->key[1] = 0x00;
    // p_entity_id->key[2] = 0x01;
    // p_entity_id->kind = 0xc1;
}

int add_enpoint_info_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    //  p_endpoint_set = &(p_core_sz_data->endpoint_set);
    // p_param_info = &(p_endpoint_set->info);
    // p_param_info->param_id = (uint16_t)0x58;
    // p_param_info->param_len = (uint16_t)(sizeof(struct sd_parameter_builtin_endpoint_set) - sizeof(struct param_info));
    // p_endpoint_set->flags = 0x0c3f;
    uint32_t flag_info[2];
    int cpy_msg_size;

    flag_info[0] = 0x58000400;
    flag_info[1] = 0x0c3f;


    cpy_msg_size = 2* sizeof(uint32_t);

    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), flag_info, cpy_msg_size);
    p_submessage->buffer_write_pos += cpy_msg_size;

    return cpy_msg_size;    
    
}

int add_user_data_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    // p_user_data = &(p_core_sz_data->user_data);
    // p_param_info = &(p_user_data->info);
    // p_param_info->param_id = 0x8000;
    // p_param_info->param_len = (uint16_t)(sizeof(struct sd_user_data) - sizeof(struct param_info));
    // p_ch_user_data = p_user_data->parameter_data;
    // p_ch_user_data[0] = (unsigned char)0x02;
    // p_ch_user_data[1] = (unsigned char)0x08;
    // p_ch_user_data[2] = (unsigned char)0x00;
    // p_ch_user_data[3] = (unsigned char)0x00;
    uint32_t user_data[2];
    int cpy_msg_size;

    user_data[0] = 0x80000400;
    user_data[1] = 0x02080000;
    cpy_msg_size = sizeof(uint32_t) * 2;
    memcpy(&(p_submessage->buffer[p_submessage->buffer_write_pos]), user_data, cpy_msg_size);
    p_submessage->buffer_write_pos+=cpy_msg_size;

    return cpy_msg_size;
}

int add_sentinel_to_submessage(struct Submessage* p_submessage, struct real_data* p_rData, enum SubmessageKind sub_kind, enum DataKind data_kind)
{
    //  p_param_sentinel = &(p_core_sz_data->sentinel);
    // p_param_sentinel->param_id = (uint16_t)0x01;
    uint16_t sentinel_id;
    uint16_t* cast_buffer;
    int cpy_msg_size;
    cpy_msg_size = sizeof(uint16_t);
    cast_buffer = (uint16_t*)(&(p_submessage->buffer[p_submessage->buffer_write_pos]));
    sentinel_id = 0x01;
    cast_buffer[0] = sentinel_id;
    p_submessage->buffer_write_pos += cpy_msg_size;

    return cpy_msg_size;
}