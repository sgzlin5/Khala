#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <syslog.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <stdint.h>

int main(void)
{
    int socket_fd;
    struct sockaddr_in mgmt_address;
    int rc, max_sock;
    fd_set mask;
    struct timeval punch_wait_time;
    char udp_buf[2048];

    socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    max_sock = socket_fd;

    FD_ZERO(&mask);
    memset(udp_buf, 0, sizeof(udp_buf));
    memset(&mgmt_address, 0, sizeof(mgmt_address));
    mgmt_address.sin_family = AF_INET;
    mgmt_address.sin_port = htons(5644);
    mgmt_address.sin_addr.s_addr = inet_addr("127.0.0.1");
    bind(socket_fd,(struct sockaddr*) &mgmt_address, sizeof(mgmt_address));
    FD_SET(socket_fd, &mask);
    sendto(socket_fd, "info", strlen("info"), 0 /*flags*/, (struct sockaddr *)&mgmt_address, sizeof(struct sockaddr_in));
    punch_wait_time.tv_sec = 0;
    punch_wait_time.tv_usec = 10000;
    struct sockaddr_in sender_sock;
    socklen_t slen;
    rc = select(max_sock + 1, &mask, NULL, NULL, &punch_wait_time);
    if (rc > 0) {
        if (FD_ISSET(socket_fd, &mask)) {
            slen = sizeof(sender_sock);
            if (recvfrom(socket_fd, udp_buf, 2048, 0/*flags*/, (struct sockaddr *) &sender_sock, (socklen_t *) &slen) > 0) {
                printf("%s", udp_buf);
            }
        }
    }
    close(socket_fd);

    return 0;
}
