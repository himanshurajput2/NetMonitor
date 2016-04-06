#include "netmonitor.h"

void
print_line(const u_char *payload, int len)
{
	int i;
	int gap;
	const u_char *ch;

	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
			printf(" ");
	}
	if (len < 8)
		printf(" ");
	
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
	return;
}

void process_payload(const char *payload, int size) {
	
	int len;
	int rem = size;
	int width = 16;			
	const u_char *ch = payload;

	if (size <= 0)
		return;

	if (size <= width) {
		print_line(ch, len);
		return;
	}

	for ( ;; ) {
		len = width % rem;
		print_line(ch, len);
		rem = rem - len;
		ch = ch + len;
		if (rem <= width) {
			print_line(ch, rem);
			break;
		}
	}

	return;
}

void print_time(const struct timeval *ts)
{
	time_t Time = (ts->tv_sec);
	struct tm *tm = localtime (&Time);
	if (!tm)
		printf("Date fail  ");
    else
		printf ( "%04d-%02d-%02d %02d:%02d:%02d.%06ld ",
                 tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
			     tm->tm_hour, tm->tm_min, tm->tm_sec, ts->tv_usec);
	return;
}

void print_mac(struct sniff_ethernet* ethernet)
{
		printf(" %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->src[0],ethernet->src[1],
				ethernet->src[2],ethernet->src[3],ethernet->src[4], ethernet->src[5]);
		printf("-> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->dst[0],ethernet->dst[1],
				ethernet->dst[2],ethernet->dst[3],ethernet->dst[4], ethernet->dst[5]);
		return;
}

void process_packet(u_char *string, const struct pcap_pkthdr *header,
        const u_char *packet)
{
    struct sniff_ethernet *ethernet;
    const struct sniff_ip *ip;
    const struct sniff_arp *arp;
    const struct sniff_tcp *tcp;
    const struct sniff_udp *udp;
    const char *payload;   

	int size_ip;
	int size_tcp;
	int size_udp = 8; 
	int size_icmp = 8; 
	int size_payload=0;
	int size_proto = 0;

	ethernet = (struct sniff_ethernet*)(packet);

	if (ntohs(ethernet->ether_type) == ETHERTYPE_IPV4) {	
		
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;

		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;

				if (size_tcp < 20) {
					printf(" Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}
				size_proto = size_tcp;
				break;

			case IPPROTO_UDP:
				size_proto = size_udp;
				break;

			case IPPROTO_ICMP:
				size_proto = size_icmp;
				break;
		}
	
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_proto);
		size_payload = ntohs(ip->ip_len) - (size_ip + size_proto);
		

		if (string && !strstr(payload,string))
			return;

		print_time(&header->ts);
		print_mac(ethernet);
		printf(" type 0x%x len %d ", ntohs(ethernet->ether_type), ntohs(ip->ip_len));
		
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
				printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
				printf(" TCP");
				break;

			case IPPROTO_UDP:
				udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
				printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->sport));
				printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(udp->dport));
				printf(" UDP");
				break;

			case IPPROTO_ICMP:
				printf("%s -> ", inet_ntoa(ip->ip_src));
				printf("%s ", inet_ntoa(ip->ip_dst));
				printf(" ICMP");
				break;
			DEFAULT:
				printf(" OTHER");
		}

		printf("\n");

		if (size_payload >0) {
			process_payload(payload,size_payload);	
		} 
		
			
	} else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP && !string) {
		
		arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
		print_time(&header->ts);

        printf(" %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", arp->sha[0], arp->sha[1], arp->sha[2],
				arp->sha[3], arp->sha[4], arp->sha[5]); 
        printf("-> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", arp->tha[0], arp->tha[1], arp->tha[2],
				arp->tha[3], arp->tha[4], arp->tha[5]);

		printf(" type 0x%x len %d ", ntohs(ethernet->ether_type), header->len);
	    printf("%d.%d.%d.%d ", arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
		printf("%d.%d.%d.%d", arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);

		printf(" %s\n",(ntohs(arp->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

	} else if (!string) {
		print_time(&header->ts);
		print_mac(ethernet);
		printf(" type 0x%x len %d", ntohs(ethernet->ether_type), header->len);
		printf(" OTHER\n");
	}
	
	return;
}


int main(int argc, char* argv[])
{
	char* interface=NULL;
	const char* file=NULL;
	char* string=NULL;
	const char* expression=NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;      /* The compiled filter */    
    bpf_u_int32 net = 0;        
	int  ch;
	pcap_t *handle;


	while ((ch = getopt(argc, argv, "i:r:s:")) != -1) {
		switch(ch) {
		case 'i': 
				interface = optarg; 
			break;
		
		case 'r':
				file  = optarg;
			break;
		case 's':
				string = optarg;
			break;
		case '?':
				printf("Please provide valid arguments\n"); //TODO Elaborate it
		}		
	}

    if (optind == argc - 1)
        expression = argv[optind];
    else if (argc > optind + 1 ){
        printf("Please check arguments.\n");
        return 1;
    }    

	if (interface && file) {
		printf(" Use only one option: Interface or file\n");
		return 1;
	}

	if (!interface && !file) {
		
		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return 1;
		}
	}
    
    if (interface) {
    	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	    if (handle == NULL) {
		    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		    return 1;
	    }
    } else if (file) {
        handle = pcap_open_offline(file, errbuf);
	    if (handle == NULL) {
		    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		    return 1;
	    }     
    } else {
        return 1;
    }

	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf(" Interface %s do not use ethernet\n", interface);
		return 1;
	}

    if (expression) {
        if (pcap_compile(handle, &fp, expression, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", expression, pcap_geterr(handle));
            return 1;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", expression, pcap_geterr(handle));
            return 1;
        }        
    }
	
	if(interface) {
		printf("listening on  %s,", interface);
	} else {
		printf("reading from file  %s,", file);
	}
	printf(" link-type EN10MB (Ethernet)\n");

    pcap_loop(handle, 0, process_packet, string);
	
    pcap_close(handle);

	printf("Complete\n");
    return 0;
}    
