#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>


int main(int argc, char** argv) {
	struct sockaddr_ll socket_address;
	int s;
	int packetlen = 0;

	void* buffer = (void *) malloc(ETH_FRAME_LEN);
	 
	unsigned char* etherhead = buffer;
		
	unsigned char* data = buffer + 14;
		
	struct ethhdr *eh = (struct ethhdr *)etherhead;
	 
	int send_result = 0;

	unsigned char src_mac[6] = {0x11, 0x22, 0x33, 0x44, 0x7b, 0xc7};
// Change dest mac here to address to target machine
	unsigned char dest_mac[6] = {0x00, 0x0C, 0x29, 0xdf, 0x0e, 0x15};

	socket_address.sll_family   = PF_PACKET;	
	socket_address.sll_protocol = htons(ETH_P_IP);	

	socket_address.sll_ifindex  = 2;

	socket_address.sll_hatype   = ARPHRD_ETHER;
		
	socket_address.sll_pkttype  = PACKET_OTHERHOST;

	socket_address.sll_halen    = ETH_ALEN;		

// Change dest mac here to address to target machine

	socket_address.sll_addr[0]  = 0x00;		
	socket_address.sll_addr[1]  = 0x0C;		
	socket_address.sll_addr[2]  = 0x29;
	socket_address.sll_addr[3]  = 0xdf;
	socket_address.sll_addr[4]  = 0x0e;
	socket_address.sll_addr[5]  = 0x15;

	socket_address.sll_addr[6]  = 0x00; /*not used*/
	socket_address.sll_addr[7]  = 0x00; /*not used*/

	uint16_t fraglen = 0;
	uint32_t packet_num = 0;

	memcpy((void *) buffer, (void *) dest_mac, ETH_ALEN);
	memcpy((void *) (buffer + ETH_ALEN), (void *) src_mac, ETH_ALEN);
	
	eh->h_proto = 0xdd86; // IPv6

	packetlen += 14;

	if ((s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    printf("Error opening raw socket");
	}

	char version_traffic_flowlabel[] = "\x60\x00\x00\x00";
	memcpy((void *) data, (void *) version_traffic_flowlabel, sizeof(version_traffic_flowlabel));
	data += sizeof(version_traffic_flowlabel);
	packetlen += sizeof(version_traffic_flowlabel);

	char payload_length[] = "\x00\x14";
	memcpy((void *) data, (void *) payload_length, sizeof(payload_length));
	data += sizeof(payload_length);
	packetlen += sizeof(payload_length);

	unsigned char next_header_1 = '\x06';
	*data = next_header_1;
	data++;
	packetlen++;

	unsigned char hop_limit = '\x40';
	*data = hop_limit;
	data++;
	packetlen++;

	char ip_src[] = "\x20\x01\x06\xf8\x10\x2d\x00\x00\x02\xd0\x09\xff\xfe\xe3\xe8\xde";
	memcpy((void *) data, (void *) ip_src, sizeof(ip_src));
	data += sizeof(ip_src);
	packetlen += sizeof(ip_src);
	
	char ip_dst[] = "\x20\x01\x06\xf8\x09\x00\x07\xc0\x00\x00\x00\x00\x00\x00\x00\x02";
	memcpy((void *) data, (void *) ip_dst, sizeof(ip_dst));
	data += sizeof(ip_dst);
	packetlen += sizeof(ip_dst);

	char tcp_buf[] = "\xe7\x41\x00\x50\xab\xdc\xd6\x60\x00\x00\x00\x00\xa0\x02\x16\x80\x41\xa2\x00\x00\x02\x04\x05\xa0\x04\x02\x08\x0a\x00\x0a\x22\xa8\x00\x00\x00\x00\x01\x03\x03\x05";
	memcpy((void *) data, (void *) tcp_buf, sizeof(tcp_buf));
	data += sizeof(tcp_buf);
	packetlen += sizeof(tcp_buf);

	send_result = sendto(s, buffer, packetlen, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	if (send_result == -1) {
		printf("Sending failed!");
	}
}