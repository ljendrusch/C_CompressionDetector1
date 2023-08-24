
#define _DEFAULT_SOURCE

#include "utils.h"

#include <signal.h>
#include <string.h>
#include <unistd.h>           // close()

#include <sys/ioctl.h>        // non-blocking sockets
#include <sys/poll.h>         // poll() to multiplex
#include <sys/socket.h>
#include <sys/time.h>         // gettimeofday()
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t

#include <netinet/in.h>       // IPPROTO_xxx, struct sockaddr
#include <netinet/ip.h>       // struct ip
#include <netinet/tcp.h>      // struct tcphdr
#include <netinet/udp.h>      // struct udphdr
#include <arpa/inet.h>        // inet_pton()

#define IP4_HDRLEN 20
#define TCP_HDRLEN  20
#define UDP_HDRLEN  8
#define PACKET_BUF_MAX 4096


struct tcp_packet {
	uint8_t* bytes;
	struct ip* iph;
	struct tcphdr* tcph;
	uint16_t headers_len;
	uint8_t* payload;
	uint16_t pl_len;
};

struct udp_packet {
	uint8_t* bytes;
	struct ip* iph;
	struct udphdr* udph;
	uint16_t headers_len;
	uint8_t* payload;
	uint16_t pl_len;
};

struct pseudo_header {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t space;
	uint8_t protocol;
	uint16_t psl;
};

struct tcp_packet* blank_tcp_packet(struct sockaddr_in* src, struct sockaddr_in* dst)
{
	struct tcp_packet* pc = malloc(sizeof(struct tcp_packet));
	pc->bytes = malloc(4096);
	pc->iph = (struct ip*) pc->bytes;
	pc->tcph = (struct tcphdr*) (pc->bytes + sizeof(struct ip));

	pc->iph->ip_hl = 5; // endianness irrelevant cuz 4 bit bitfield
	pc->iph->ip_v = 4;  // ^^
	pc->iph->ip_tos = 0;
	pc->iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
	pc->iph->ip_id = 0;
	pc->iph->ip_off = htons(IP_DF);
	pc->iph->ip_ttl = 0;
	pc->iph->ip_p = IPPROTO_TCP;
	pc->iph->ip_sum = 0;
	pc->iph->ip_src.s_addr = src->sin_addr.s_addr;
	pc->iph->ip_dst.s_addr = dst->sin_addr.s_addr;

	pc->tcph->th_sport = src->sin_port;
	pc->tcph->th_dport = dst->sin_port;
	pc->tcph->th_seq = 0;
	pc->tcph->th_ack = 0;
	pc->tcph->th_x2 = 0;
	pc->tcph->th_off = 0;
	pc->tcph->th_flags = 0;
	pc->tcph->doff = 0b0101; // 5 16bit words in tcp header
	pc->tcph->th_win = htons(1024);
	pc->tcph->th_sum = 0;
	pc->tcph->th_urp = 0;

	pc->headers_len = (uint16_t) (sizeof(struct ip) + sizeof(struct tcphdr));
	pc->payload = 0;
	pc->pl_len = 0;
	return pc;
}

void tpacket_iph_csum(struct tcp_packet* pc)
{
	pc->iph->ip_sum = (uint16_t) 0;

	uint16_t* ic_buf = (uint16_t*) pc->bytes;
	uint16_t nwords = pc->iph->ip_len >> 1;

	uint32_t sum = 0;
	for (; nwords > 0; nwords--)
		sum += *ic_buf++;
	sum = (sum >> 16) + (sum & 0x00ff);
	sum += (sum >> 16);
	pc->iph->ip_sum = ~((uint16_t) (sum & 0x00ff));
}

// struct udp_packet* blank_udp_packet(struct sockaddr_in* src, struct sockaddr_in* dst)
// {
// 	struct udp_packet* pc = malloc(sizeof(struct tcp_packet));
// 	pc->bytes = malloc(4096);
// 	pc->iph = (struct ip*) pc->bytes;
// 	pc->udph = (struct udphdr*) (pc->bytes + sizeof(struct ip));

// 	pc->iph->ip_hl = 5; // endianness irrelevant cuz 4 bit bitfield
// 	pc->iph->ip_v = 4;  // ^^
// 	pc->iph->ip_tos = 0;
// 	pc->iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr);
// 	pc->iph->ip_id = 0;
// 	pc->iph->ip_off = htons(IP_DF);
// 	pc->iph->ip_ttl = 0;
// 	pc->iph->ip_p = IPPROTO_UDP;
// 	pc->iph->ip_sum = 0;
// 	pc->iph->ip_src.s_addr = src->sin_addr.s_addr;
// 	pc->iph->ip_dst.s_addr = dst->sin_addr.s_addr;

// 	pc->udph->uh_sport = src->sin_port;
// 	pc->udph->uh_dport = dst->sin_port;
// 	pc->udph->uh_ulen = htons(sizeof(struct udphdr));
// 	pc->udph->uh_sum = 0;

// 	pc->headers_len = (uint16_t) (sizeof(struct ip) + sizeof(struct udphdr));
// 	pc->payload = 0;
// 	pc->pl_len = 0;
// 	return pc;
// }

// void upacket_iph_csum(struct udp_packet* pc)
// {
// 	pc->iph->ip_sum = (uint16_t) 0;

// 	uint16_t* ic_buf = (uint16_t*) pc->bytes;
// 	uint16_t nwords = pc->iph->ip_len >> 1;

// 	uint32_t sum = 0;
// 	for (; nwords > 0; nwords--)
// 		sum += *ic_buf++;
// 	sum = (sum >> 16) + (sum & 0x00ff);
// 	sum += (sum >> 16);
// 	pc->iph->ip_sum = ~((uint16_t) (sum & 0x00ff));
// }

// void upacket_bind_data(struct udp_packet* pc, uint8_t* payload, uint16_t pllen)
// {
// 	pc->payload = pc->bytes + pc->headers_len;
// 	memcpy(pc->payload, payload, pllen);
// 	pc->iph->ip_len += pllen;
// 	pc->udph->uh_ulen += pllen;
// 	pc->pl_len = pllen;
// }

// void upacket_increment_id(struct udp_packet* pc, uint16_t n)
// {
// 	pc->iph->ip_id = htons(n);
// 	upacket_iph_csum(pc);

// 	(*pc->payload) &= 0x0;
// 	(*(pc->payload+1)) &= 0x0;
// 	(*pc->payload) |= (uint8_t) (n & 0x0f);
// 	(*(pc->payload+1)) |= (uint8_t) (n >> 8);
// }

// void upacket_release_data(struct udp_packet* pc)
// {
// 	pc->iph->ip_len -= pc->pl_len;
// 	pc->udph->uh_ulen -= pc->pl_len;
// 	pc->pl_len = 0;
// }

void tcp_packet_csum(struct tcp_packet* pc)
{
	pc->tcph->th_sum = (uint16_t) 0;

	uint16_t psl = ((uint16_t) (((pc->tcph->doff) * 4)));

	struct pseudo_header psh;
	psh.src_addr = pc->iph->ip_src.s_addr;
	psh.dst_addr = pc->iph->ip_dst.s_addr;
	psh.space = (uint8_t) 0;
	psh.protocol = pc->iph->ip_p;
	psh.psl = htons(sizeof(struct pseudo_header) + psl);// + pc->pl_len + (pc->pl_len & 0b1)));

	uint16_t* pc_buf_start = malloc(sizeof(struct pseudo_header) + psl);
	uint16_t* pc_buf = pc_buf_start;
	memcpy(pc_buf, &psh, sizeof(struct pseudo_header));
	memcpy(pc_buf, pc->tcph, sizeof(struct tcphdr));
	// if (pc->pl_len)
	// 	memcpy(pc_buf, pc->payload, pc->pl_len);

	uint16_t nwords = (uint16_t) ((sizeof(struct pseudo_header) + psl) >> 1);

	uint32_t sum = 0;
	for (; nwords > 0; nwords--)
		sum += *pc_buf++;
	sum = (sum >> 16) + (sum & 0x00ff);
	sum += (sum >> 16);
	pc->tcph->th_sum = ~((uint16_t) (sum & 0x00ff));

	free(pc_buf_start);
}

	// pc->tcph->th_sum = 0;

	// uint16_t psh[6];
	// psh[0] = (uint16_t) (pc->iph->ip_src.s_addr >> 16);
	// psh[1] = (uint16_t) (pc->iph->ip_src.s_addr & 0x00ff);
	// psh[2] = (uint16_t) (pc->iph->ip_dst.s_addr >> 16);
	// psh[3] = (uint16_t) (pc->iph->ip_dst.s_addr & 0x00ff);
	// psh[4] = (uint16_t) IPPROTO_TCP;
	// psh[5] = (uint16_t) (pc->len - sizeof(struct ip));

	// uint32_t sum = 0;
	// for (int i = 0; i < 6; i++)
	// 	sum += psh[i];

	// uint16_t* csum_buf = (uint16_t*) (pc->bytes + sizeof(struct ip));
	// int32_t nwords = (int32_t) ((pc->len - sizeof(struct ip)) >> 1);

	// for (; nwords > 0; nwords--)
	// 	sum += *csum_buf++;

	// sum = (sum >> 16) + (sum & 0x00ff);
	// sum += (sum >> 16);
	// pc->tcph->th_sum = ~((uint16_t) (sum & 0x00ff));

void clean_exit(){exit(0);}

int main(int argc, char const* argv[])
{
	if (argc < 2)
	{
		printf("  Must supply config json file, e.g.\n    ./compr_detect config.json\n");
		exit(1);
	}

	// graceful exit on ctrl-c ctrl-z
	signal(SIGTERM, clean_exit);
	signal(SIGINT, clean_exit);

	int err, opt, tcp_sock_fd, udp_sock_fd;

	// extract config parameters
	char*** json_parse;
	uint16_t json_n;
	int32_t f_len;
	char* json_raw = slurp_file(argv[1]);
	read_json(&json_raw, &json_parse, &json_n);

	char* d_ipa_str = malloc(strlen(json_parse[0][1])+1);
	strcpy(d_ipa_str, json_parse[0][1]);
	uint16_t s_port_tcp = (uint16_t) atoi(json_parse[1][1]);
	uint16_t s_port_udp = (uint16_t) atoi(json_parse[2][1]);
	uint16_t d_port_udp = (uint16_t) atoi(json_parse[3][1]);
	uint16_t d_port_headsyn = (uint16_t) atoi(json_parse[4][1]);
	uint16_t d_port_tailsyn = (uint16_t) atoi(json_parse[5][1]);
	uint16_t packet_num = (uint16_t) atoi(json_parse[6][1]);
	uint16_t packet_size = (uint16_t) atoi(json_parse[7][1]);
	uint8_t packet_ttl = (uint8_t) atoi(json_parse[8][1]);
	uint16_t pause_time = (uint16_t) atoi(json_parse[9][1]);
	uint16_t compression_threshold = (uint16_t) atoi(json_parse[10][1]);
	char* s_ipa_str = malloc(strlen(json_parse[11][1])+1);
	strcpy(s_ipa_str, json_parse[11][1]);

    check_port(argv[1], json_parse[1][0], s_port_tcp);
    check_port(argv[1], json_parse[2][0], s_port_udp);
    check_port(argv[1], json_parse[3][0], d_port_udp);
    check_port(argv[1], json_parse[4][0], d_port_headsyn);
    check_port(argv[1], json_parse[5][0], d_port_tailsyn);

	free_json(json_parse, json_n, json_raw);

	// address setup
	struct sockaddr_in self_addr_t, serv_addr_t, self_addr_u, serv_addr_u;
	self_addr_t.sin_family = AF_INET;
	self_addr_t.sin_port = htons(s_port_tcp);
	err = inet_pton(AF_INET, s_ipa_str, &self_addr_t.sin_addr);
	if (err <= 0)
	{
		perror("inet_pton");
		exit(1);
	}

	serv_addr_t.sin_family = AF_INET;
	serv_addr_t.sin_port = htons(d_port_headsyn);
	err = inet_pton(AF_INET, d_ipa_str, &serv_addr_t.sin_addr);
	if (err <= 0)
	{
		perror("inet_pton");
		exit(1);
	}

	self_addr_u.sin_family = AF_INET;
	self_addr_u.sin_port = htons(s_port_udp);
	self_addr_u.sin_addr.s_addr = self_addr_t.sin_addr.s_addr;

	serv_addr_u.sin_family = AF_INET;
	serv_addr_u.sin_port = htons(d_port_udp);
	serv_addr_u.sin_addr.s_addr = serv_addr_t.sin_addr.s_addr;

	// set up payloads
	uint8_t* lo_ent_payload = malloc(packet_size);
	memset(lo_ent_payload, 0, packet_size);

	uint8_t* hi_ent_payload = malloc(packet_size);
	FILE* vlt_data_f = fopen("/dev/urandom", "rb");
	fread(hi_ent_payload, 1, packet_size, vlt_data_f);
	fclose(vlt_data_f);

	// construct base packets
	struct tcp_packet* tp = blank_tcp_packet(&self_addr_t, &serv_addr_t);
	tp->tcph->syn = 0b1;
	tp->tcph->th_seq = random(); // max return from random is max 32-bit signed int
	tp->iph->ip_ttl = packet_ttl;
	tp->iph->ip_id = 0x7b32; //(uint16_t) (random() >> 16);
	tpacket_iph_csum(tp);

	// struct udp_packet* up = blank_udp_packet(&self_addr_u, &serv_addr_u);
	// up->iph->ip_ttl = packet_ttl;
	// upacket_bind_data(up, lo_ent_payload, packet_size);
	// upacket_iph_csum(up);

	// set up compression test variables
	struct timeval lo_head_rst, lo_tail_rst, hi_head_rst, hi_tail_rst;
	lo_head_rst.tv_sec = 0;
	lo_tail_rst.tv_sec = 0;
	hi_head_rst.tv_sec = 0;
	hi_tail_rst.tv_sec = 0;

	// tcp socket setup
    tcp_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (tcp_sock_fd < 0)
	{
		perror("tcp socket creation");
		exit(1);
	}

	opt = 1;
	err = setsockopt(tcp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (err)
	{
		perror("setsockopt SO_REUSEADDR");
		exit(1);
	}

	opt = 1;
	err = setsockopt(tcp_sock_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
	if (err)
	{
		perror("setsockopt IP_HDRINCL");
		exit(1);
	}

	// udp socket setup
	// udp_sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	// if (udp_sock_fd < 0)
	// {
	// 	perror("udp socket creation");
	// 	exit(1);
	// }

	udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_sock_fd < 0)
	{
		perror("udp socket creation");
		exit(1);
	}

	opt = 1;
	err = setsockopt(udp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (err)
	{
		perror("setsockopt SO_REUSEADDR");
		exit(1);
	}

	opt = packet_ttl;
	err = setsockopt(udp_sock_fd, IPPROTO_IP, IP_TTL, &opt, sizeof(opt));
	if (err)
	{
		perror("setsockopt IP_TTL");
		exit(1);
	}

	err = bind(udp_sock_fd, (struct sockaddr*)&self_addr_u, sizeof(struct sockaddr));
	if (err)
	{
		perror("bind udp socket");
		exit(1);
	}

	err = connect(udp_sock_fd, (struct sockaddr*)&serv_addr_u, sizeof(struct sockaddr));
	if (err)
	{
		perror("connect udp socket");
		exit(1);
	}

	// opt = 1;
	// err = setsockopt(udp_sock_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
	// if (err)
	// {
	// 	perror("setsockopt IP_HDRINCL");
	// 	exit(1);
	// }

	// init multiplexer
	uint16_t nfds = 2;
	struct pollfd fds[2];
	memset(fds, 0, sizeof(fds));

	fds[0].fd = tcp_sock_fd;
	fds[0].events = POLLIN;

	fds[1].fd = udp_sock_fd;
	fds[1].events = POLLOUT;

	int timeout = 2000;
	uint32_t addrlen = sizeof(struct sockaddr);
	uint8_t recv_buf[PACKET_BUF_MAX];

	for (int lo_ent_train = 1; lo_ent_train >= 0; lo_ent_train--)
	{
		// send head syn
		if (lo_ent_train == 0)
		{
			self_addr_t.sin_port = htons(ntohs(self_addr_t.sin_port)+1);
			serv_addr_t.sin_port = htons(ntohs(serv_addr_t.sin_port)+1);
			tp->tcph->th_sport = self_addr_t.sin_port;
			tp->tcph->th_dport = serv_addr_t.sin_port;
		}
		tp->tcph->th_sum = 0xa6f0 + (lo_ent_train ? 0 : 1);
		printf("outer tcp %d\n", lo_ent_train);
		err = sendto(tcp_sock_fd, tp->bytes, tp->headers_len, 0, (struct sockaddr*)&serv_addr_t, addrlen);
		if (err < 0)
		{
			perror("send head syn");
			break;
		}
		else
		{
			tp->iph->ip_id = htons(ntohs(tp->iph->ip_id)+1);
			tpacket_iph_csum(tp);
		}

		uint16_t udp_count = 0;

		for (int i = 0;; i++)
		{
			err = poll(fds, nfds, timeout);
			if (err < 0) // error
			{
				perror("poll");
				exit(1);
			}

			if (err == 0) // timeout
			{
				nfds = 2;
				if (lo_ent_train > 0)
				{
					// upacket_release_data(up);
					// upacket_bind_data(up, hi_ent_payload, packet_size);
					// up->iph->ip_id = 0x00;
					sleep(pause_time - 2);
				}
				break;
			}

			if (fds[0].revents & POLLIN) // tcp message in
			{
				err = recvfrom(fds[0].fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&serv_addr_t, (socklen_t*)&addrlen);
				if (err >= 40 && (recv_buf[33] & 0x4))
				{
					if (lo_ent_train > 0)
					{
						if (lo_head_rst.tv_sec == 0)
						{
							printf("setting lo_head_rst\n");
							gettimeofday(&lo_head_rst, 0);
						}
						else
						{
							printf("setting lo_tail_rst\n");
							gettimeofday(&lo_tail_rst, 0);
						}
					}
					else
					{
						if (hi_head_rst.tv_sec == 0)
						{
							printf("setting hi_head_rst\n");
							gettimeofday(&hi_head_rst, 0);
						}
						else
						{
							printf("setting hi_tail_rst\n");
							gettimeofday(&hi_tail_rst, 0);
						}
					}
				}
			}

			if (nfds > 1 && (fds[1].revents & POLLOUT)) // udp message out
			{
				if (udp_count == packet_num)
				{
					printf("inner tcp %d\n", lo_ent_train);
					self_addr_t.sin_port = htons(ntohs(self_addr_t.sin_port)+1);
					serv_addr_t.sin_port = htons(ntohs(serv_addr_t.sin_port)+1);
					tp->tcph->th_sport = self_addr_t.sin_port;
					tp->tcph->th_dport = serv_addr_t.sin_port;
					err = sendto(fds[0].fd, tp, tp->headers_len, 0, (struct sockaddr*)&serv_addr_t, addrlen);
					if (err >= 0)
					{
						tp->iph->ip_id = htons(ntohs(tp->iph->ip_id)+1);
						tpacket_iph_csum(tp);
						nfds = 1;
					}
				}
				else
				{
					if (lo_ent_train > 0)
					{
						err = sendto(fds[1].fd, lo_ent_payload, packet_size, 0, (struct sockaddr*)&serv_addr_u, addrlen);
						(*lo_ent_payload) &= 0x0;
						(*(lo_ent_payload+1)) &= 0x0;
						(*lo_ent_payload) |= (uint8_t) (udp_count & 0x0f);
						(*(lo_ent_payload+1)) |= (uint8_t) (udp_count >> 8);
					}
					else
					{
						err = sendto(fds[1].fd, hi_ent_payload, packet_size, 0, (struct sockaddr*)&serv_addr_u, addrlen);
						(*hi_ent_payload) &= 0x0;
						(*(hi_ent_payload+1)) &= 0x0;
						(*hi_ent_payload) |= (uint8_t) (udp_count & 0x0f);
						(*(hi_ent_payload+1)) |= (uint8_t) (udp_count >> 8);
					}
					udp_count++;
				}
			}
		}
	}

	// calculate and report findings
	char* result;
	if (!lo_head_rst.tv_sec || !lo_tail_rst.tv_sec || !hi_head_rst.tv_sec || !hi_tail_rst.tv_sec)
	{
		result = malloc(29);
		strcpy(result, "No compression was detected.");
		result[28] = '\0';
	}
	else
	{
		uint64_t lo_ent_delta_s = lo_tail_rst.tv_sec - lo_head_rst.tv_sec;
		uint64_t lo_ent_delta_us = lo_tail_rst.tv_usec - lo_head_rst.tv_usec;
		uint64_t hi_ent_delta_s = hi_tail_rst.tv_sec - hi_head_rst.tv_sec;
		uint64_t hi_ent_delta_us = hi_tail_rst.tv_usec - hi_head_rst.tv_usec;

		uint64_t delta_delta_s = hi_ent_delta_s - lo_ent_delta_s;
		uint64_t delta_delta_us = hi_ent_delta_us - hi_ent_delta_us;

		printf("lo_head_rst  %lu :: %lu", lo_head_rst.tv_sec, lo_head_rst.tv_usec);
		printf("lo_tail_rst  %lu :: %lu", lo_tail_rst.tv_sec, lo_tail_rst.tv_usec);
		printf("hi_head_rst  %lu :: %lu", hi_head_rst.tv_sec, hi_head_rst.tv_usec);
		printf("hi_tail_rst  %lu :: %lu", hi_tail_rst.tv_sec, hi_tail_rst.tv_usec);
		printf("lo_ent_delta %lu :: %lu", lo_ent_delta_s, lo_ent_delta_us);
		printf("hi_ent_delta %lu :: %lu", hi_ent_delta_s, hi_ent_delta_us);
		printf("delta_delta  %lu :: %lu", delta_delta_s, delta_delta_us);

		if (hi_ent_delta_s > lo_ent_delta_s ||
			(hi_ent_delta_s == lo_ent_delta_s &&
				hi_ent_delta_us > lo_ent_delta_us &&
				hi_ent_delta_us - lo_ent_delta_us >= (compression_threshold * 1000)))
		{
			result = malloc(22);
			strcpy(result, "Compression detected!");
			result[21] = '\0';
		}
		else
		{
			result = malloc(29);
			strcpy(result, "No compression was detected.");
			result[28] = '\0';
		}
	}

	printf("%s\n", result);

	close(udp_sock_fd);
	close(tcp_sock_fd);

	free(result);
	free(d_ipa_str);
	free(lo_ent_payload);
	free(hi_ent_payload);
	free(tp->bytes);
	if (tp->payload)
		free(tp->payload);
	free(tp);

    return 0;
}
