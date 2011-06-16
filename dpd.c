/*	Frank Zwart [frank@frankzwart.nl]  [blaataap]
 *	v0.1 16/6/2011
 *	Tool simply stores captured packets based on pcap filter and afterwards checks if there are duplicate packets in this array
 */ 	

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define SIZE_ETHERNET_HEADER 14
#define SIZE_IP_HEADER 20
#define SIZE_TCP_HEADER 20

struct pkt
{
    u_int32_t src_ip;
    u_int32_t dst_ip;
	u_int16_t src_port;
	u_int16_t dst_port;	
    u_int32_t seq;
    u_int32_t ack_seq;
	u_int16_t tcp_check;
	u_int16_t ip_check;
	int syn_flag;
	int ack_flag;
};

/* Global vars */
struct pkt tmp_pkt;
struct pkt *sent_pkts;	/* struct we use for storing SENT packet info */
u_int32_t *checksum;	/* array where only TCP checksums are stored */
int sent_ptr = 0;		/* points to the next element in the sent_pkts array */
int pkt_cnt;


void clear_pkt(struct pkt *pkt_strct)
{
	memset((void *)pkt_strct,0, sizeof(struct pkt));	
}

void store_pkt(struct pkt *pkt_strct)
{
	memcpy((void *)&(sent_pkts[sent_ptr]),(void *)pkt_strct,sizeof(struct pkt));
	sent_ptr++;
}

int sort(const void *x, const void *y) {
	return (*(u_int16_t*)x - *(u_int16_t*)y);
}

void generate_stats()
{

	puts("Analysing captured packets");
	int i,j;

	for(i = 0 ; i < pkt_cnt; i++)
	{
		for(j = i+1;j < pkt_cnt; j++)
		{
			if(sent_pkts[i].seq == sent_pkts[j].seq)
			{
				if(sent_pkts[i].ack_seq == sent_pkts[j].ack_seq)
				{		
					if(sent_pkts[i].syn_flag == sent_pkts[j].ack_flag)
					{		
						if(sent_pkts[i].ack_flag == sent_pkts[j].ack_flag)
						{
							struct in_addr src,dst;
							char ip_src[INET_ADDRSTRLEN],ip_dst[INET_ADDRSTRLEN];
							src.s_addr=htonl(sent_pkts[i].src_ip);	
							dst.s_addr=htonl(sent_pkts[i].dst_ip);	
							inet_ntop(AF_INET,&(src),ip_src,INET_ADDRSTRLEN);
							inet_ntop(AF_INET,&(dst),ip_dst,INET_ADDRSTRLEN);
							printf("Duplicate found..\n");
							printf("\t* Packet1 Source: %s:%u Destination %s:%u seq: %u ack_seq: %u checksum: %u\n",ip_src,sent_pkts[i].src_port,ip_dst,sent_pkts[i].dst_port,sent_pkts[i].seq,sent_pkts[i].ack_seq,sent_pkts[i].tcp_check);
							printf("\t* Packet2 Source: %s:%u Destination %s:%u seq: %u ack_seq: %u checksum: %u\n",ip_src,sent_pkts[j].src_port,ip_dst,sent_pkts[j].dst_port,sent_pkts[j].seq,sent_pkts[j].ack_seq,sent_pkts[j].tcp_check);
						}
							
					}
				}
			}		
		
		}
	}
}

void process_packet(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	struct ip *ip_hdr;
	struct tcphdr *tcp_hdr;
	int plength;

	plength = pkthdr->len;

	if(plength < (sizeof(struct iphdr) + sizeof(struct tcphdr)))
	{
		printf("invalid ip or tcp header length\n");
		return 1;
	}

	ip_hdr = (struct ip *)(packet+SIZE_ETHERNET_HEADER);
	tcp_hdr = (struct tcphdr *)(packet+SIZE_ETHERNET_HEADER+SIZE_IP_HEADER);

	/* fill tmp packet struct */
	tmp_pkt.src_ip = ntohl(ip_hdr->ip_src.s_addr);
	tmp_pkt.dst_ip = ntohl(ip_hdr->ip_dst.s_addr);
	tmp_pkt.ip_check = ntohs(ip_hdr->ip_sum);
	tmp_pkt.src_port = ntohs(tcp_hdr->source);
	tmp_pkt.dst_port = ntohs(tcp_hdr->dest);
	tmp_pkt.seq = ntohl(tcp_hdr->seq);
	tmp_pkt.ack_seq = ntohl(tcp_hdr->ack_seq);
	tmp_pkt.tcp_check = ntohs(tcp_hdr->check);

	/* set packet flags */
 	if(tcp_hdr->syn)
	{
		tmp_pkt.syn_flag = 1;	
	}
	if(tcp_hdr->ack)
	{
		tmp_pkt.ack_flag = 1;
	} 

	/* add packet to array for processing later on */
	store_pkt(&tmp_pkt);

	if(sent_ptr == pkt_cnt)
	{
		puts("Done capturing packets");
		generate_stats();
		exit(1);
	}

	clear_pkt(&tmp_pkt);
}


int main(int argc, char *argv[])
{
	pcap_t *handle;

	if(argc < 3 || !strcmp(argv[1],"--help"))
	{
	  printf("usage: ./bin <dev> <packets_to_capture>\nExample: ./bin eth0 10\n");
	  exit(1); 
 	}

	char *dev = argv[1];
	pkt_cnt = atoi(argv[2]);
	
	char errbuf[PCAP_ERRBUF_SIZE];
	char filter_exp[] = "tcp";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	u_int bytes = 65535;

	/* init global packet storage */
	sent_pkts = (struct pkt *)malloc(sizeof(struct pkt)*pkt_cnt);
	checksum = (u_int32_t *)malloc(sizeof(u_int32_t)*pkt_cnt);

	
	/* Create sniffing session */
    handle = pcap_open_live(dev,bytes,1, 0, errbuf);

	
	if (handle == NULL){
		fprintf(stderr, "Could not open device %s\n",dev);
		exit(1);
	}

	if (pcap_lookupnet(dev,&net,&mask,errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		exit(1);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(1);
	}

	if (pcap_setfilter(handle, &fp) == -1){
		fprintf(stderr, "Couldn't apply filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

	printf("Capturing %i packet for Device: %s\n", pkt_cnt,dev);
	pcap_loop(handle,pkt_cnt,process_packet,NULL);
	pcap_close(handle);
	exit(0);

}
