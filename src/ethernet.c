#include <stdio.h>
//#include <arpa/inet.h>
//#include <net/ethernet.h>

#include "ethernet.h"

//void dump_ethernet_header(const unsigned char *pkt_data) 
//{
//  struct ether_header *header = (struct ether_header *)pkt_data;
//
//  const char *name = NULL;
//
//  u_int8_t *dmac = header->ether_dhost;
//  u_int8_t *smac = header->ether_shost;
//  u_int16_t type = ntohs(header->ether_type);
//  int addressType = (int)type;
//
//
//
//  switch (type) 
//  {
//    case ETHERTYPE_IP:
//      name = "IP";
//      break;
//    case ETHERTYPE_ARP:
//      name = "ARP";
//      return;
//      break;
//    default:
//      name = "Unknown";
//      return;
//      break;
//  }
//
//  printf("%02x:%02x:%02x:%02x:%02x:%02x => " \
//      "%02x:%02x:%02x:%02x:%02x:%02x (%s) (%04x)\n",
//
//  smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
//  dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5], name, addressType);
//}