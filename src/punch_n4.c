#include "n2n.h"
#include "network_traffic_filter.h"
#include "edge_utils_win32.h"

khala_n4_punch_t n4 = {
    .peer_min_port = 0,
    .peer_max_port = 0,
    .min_port = 0,
    .max_port = 0
};

static ssize_t sendto_n4_sock(n2n_edge_t *eee, const void * buf, size_t len)
{
    struct sockaddr_in peer_addr;
    ssize_t sent = 0;
    khala_n4_punch_t *ptr;

    ptr = (khala_n4_punch_t *)eee->curr_punch->ptr;
    if (ptr->punch_pool[EDGE_POOL_HEAD] < 0) {
        return 0;
    }
    fill_sockaddr((struct sockaddr *) &peer_addr, sizeof(peer_addr), &(eee->curr_sn->sock));
    sent = sendto(ptr->punch_pool[EDGE_POOL_HEAD], buf, len, 0, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr_in));
    if (sent < 0 && errno) {
        char * c = strerror(errno);
        traceEvent(TRACE_ERROR, "punch sendto supernode failed (%d) %s", errno, c);
    }
    return sent;
}

static uint16_t n4_get_port_from_socket(int sock)
{
    uint16_t port;
    struct sockaddr_in tmp_addr;
    socklen_t addr_len = sizeof(tmp_addr);

    memset(&tmp_addr, 0, sizeof(struct sockaddr_in));
    getsockname(sock, (struct sockaddr *)&tmp_addr, &addr_len);
    port = ntohs(tmp_addr.sin_port);
    return port;
}

static void n4_init_pool(n2n_edge_t *eee)
{
    struct sockaddr_in peer_addr;
    int index = 0;
    u_int opt = 1;
    khala_n4_punch_t *ptr;
    int ttl;
    int op;

    ttl = 64;
    ptr = (khala_n4_punch_t *)eee->curr_punch->ptr;

    /* Init First socket */
    memset(&peer_addr, 0, sizeof(peer_addr));
    ptr->punch_pool[EDGE_POOL_HEAD] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    setsockopt(ptr->punch_pool[EDGE_POOL_HEAD], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(socklen_t));
    setsockopt(ptr->punch_pool[EDGE_POOL_HEAD], SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(socklen_t));
    setsockopt(ptr->punch_pool[EDGE_POOL_HEAD], IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(0);
    peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind(ptr->punch_pool[EDGE_POOL_HEAD],(struct sockaddr*) &peer_addr, sizeof(peer_addr));
    ptr->punch_port = n4_get_port_from_socket(ptr->punch_pool[EDGE_POOL_HEAD]);
    /* Init Rest socket */
    op = (ptr->punch_port + EDGE_DEFAULT_MAX_SOCKET >= 0xffff) ? -1 : 1;
    for (index = EDGE_POOL_START; index < EDGE_DEFAULT_MAX_SOCKET; index++) {
        ptr->punch_pool[index] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        setsockopt(ptr->punch_pool[index], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(socklen_t));
        setsockopt(ptr->punch_pool[index], SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(socklen_t));
        setsockopt(ptr->punch_pool[index], IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(ptr->punch_port + index * op);
        peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        bind(ptr->punch_pool[index],(struct sockaddr*) &peer_addr, sizeof(peer_addr));
    }
}

static void n4_close_pool(n2n_edge_t *eee, int punch_sock)
{
    int index = 0;
    khala_n4_punch_t *ptr;

    ptr = (khala_n4_punch_t *)eee->curr_punch->ptr;
    for (index = EDGE_POOL_HEAD; index < EDGE_DEFAULT_MAX_SOCKET; index++) {
        if (punch_sock != ptr->punch_pool[index] && ptr->punch_pool[index] > 0){
            closesocket(ptr->punch_pool[index]);
        }
        ptr->punch_pool[index] = -1;
    }
}

static void n4_send_hello(n2n_edge_t *eee, khala_n4_punch_t *ptr)
{
    n2n_common_t common;
    n4_HELLO_t hello;
    size_t idx;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};

    memset(&common, 0, sizeof(common));
    memset(&hello, 0, sizeof(hello));
    common.ttl = N2N_DEFAULT_TTL;
    common.pc = n2n_n4_hello;
    common.flags = 0;
    memcpy(common.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    idx = 0;
    encode_mac(hello.srcMac, &idx, eee->device.mac_addr);
    idx = 0;
    encode_mac(hello.peerMac, &idx, eee->curr_punch_peer->mac_addr);
    hello.min_port = ptr->min_port;
    hello.max_port = ptr->max_port;
    hello.nat_type = eee->conf.nat_type;
    idx = 0;
    encode_N4_HELLO(pktbuf, &idx, &common, &hello);
    sendto_n4_sock(eee, pktbuf, idx);
}

static int n4_stop_cmd(uint8_t *pktbuf)
{
    if (!strncmp(pktbuf, EDGE_CMD_STOP, strlen(EDGE_CMD_STOP))) {
        traceEvent(TRACE_NORMAL," <= Edge is stopping");
        return 1;
    }
    return 0;
}

static size_t n4_recv_process(n2n_edge_t  *eee)
{
    struct sockaddr_in sender_sock;
    socklen_t slen;
    uint8_t  pktbuf[N2N_PKT_BUF_SIZE];
    ssize_t recvlen;
    n2n_common_t cmn;
    size_t idx;
    size_t msg_type = 0;
    uint8_t from_supernode;
    int max_sd = 0;
    int rc = 0;
    fd_set readfds;
    struct timeval wait_time;
    khala_n4_punch_t *ptr;

    ptr = (khala_n4_punch_t *)eee->curr_punch->ptr;
    memset(pktbuf, 0, N2N_PKT_BUF_SIZE);
    FD_ZERO(&readfds);
    FD_SET(ptr->punch_pool[EDGE_POOL_HEAD], &readfds);
    slen = sizeof(sender_sock);
    max_sd = ptr->punch_pool[EDGE_POOL_HEAD];

    wait_time.tv_sec = 10;
    wait_time.tv_usec = 0;

    rc = select(max_sd + 1, &readfds, NULL, NULL, &wait_time);
    if (rc > 0) {
        recvlen = recvfrom(ptr->punch_pool[EDGE_POOL_HEAD], pktbuf, N2N_PKT_BUF_SIZE, 0, (struct sockaddr *)&sender_sock, &slen);
        if(recvlen < 0) {
            traceEvent(TRACE_WARNING, "punch recvfrom failed: %d - %s", errno, strerror(errno));
            return msg_type;
        }
        if (n4_stop_cmd(pktbuf)) {
            return msg_type;
        }
        /* Decode pktbuf */
        idx = 0; /* marches through packet header as parts are decoded. */
        if(decode_common(&cmn, pktbuf, &recvlen, &idx) < 0) {
            traceEvent(TRACE_WARNING, "failed to decode common section in N2N_UDP");
            return msg_type; /* failed to decode packet */
        }
        msg_type = cmn.pc;
        from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
        if (!from_supernode) {
            return msg_type;
        }

        if(0 == memcmp(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE)) {
            switch(msg_type) {
                case MSG_TYPE_N4_HELLO: {
                    eee->conf.punch_status = edge_punch_punching;
                    traceEvent(TRACE_DEBUG, "Rx MSG_TYPE_N4_HELLO <= HELLO ACK");
                    break;
                }
                case MSG_TYPE_N4_PIINFO: {
                    n4_PIINFO_t piinfo;
 
                    memset(&piinfo, 0, sizeof(n4_PIINFO_t));
                    traceEvent(TRACE_INFO, "Rx MSG_TYPE_N4_PIINFO");
                    decode_N4_PIINFO(&piinfo, &cmn, pktbuf, &recvlen, &idx);
                    memset(&ptr->punch_addr, 0, sizeof(ptr->punch_addr));
                    ptr->punch_addr.sin_family = AF_INET;
                    ptr->punch_addr.sin_port = htons(piinfo.peerPort);
                    traceEvent(TRACE_DEBUG," <= PInfo Port %d \n", piinfo.peerPort);
                    memcpy(&(ptr->punch_addr.sin_addr.s_addr), piinfo.sock.addr.v4, IPV4_SIZE);
                    ptr->local_type = piinfo.n4_type;
                    ptr->peer_min_port = piinfo.peer_min_port;
                    ptr->peer_max_port = piinfo.peer_max_port;
                    traceEvent(TRACE_INFO, "Peer Port Range[%d~%d]", ptr->peer_min_port, ptr->peer_max_port);
                    break;
                }
                default: {
                    traceEvent(TRACE_WARNING, "not-punching packet type %d", (signed int)msg_type);
                    break;
                }
            }
        }
    }

    return msg_type;
}

static void n4_set_p2p_sock(n2n_edge_t  *eee, int sock, struct sockaddr_in *sender_sock)
{
    time_t now;
    struct peer_info *tmp;

    now = time(NULL);
    memset(&eee->curr_punch_peer->punch_sock, 0, sizeof(eee->curr_punch_peer->punch_sock));
    memcpy(&eee->curr_punch_peer->punch_sock, sender_sock, sizeof(struct sockaddr_in));
    eee->curr_punch_peer->sock.port = ntohs(sender_sock->sin_port);
    traceEvent(TRACE_DEBUG, " ==> Peer socket port updated to %d", ntohs(sender_sock->sin_port));
    eee->curr_punch_peer->last_seen = now;
    eee->curr_punch_peer->last_p2p = now;
    eee->curr_punch_peer->p2p_sock = sock;

    HASH_FIND_PEER(eee->pending_peers, eee->curr_punch_peer->mac_addr, tmp);
    if (tmp == NULL) {
        traceEvent(TRACE_WARNING, "Pending Peer removed, already in P2P");
        closesocket(sock);
        return;
    }
    pthread_mutex_lock(&eee->punch_access);
    HASH_DEL(eee->pending_peers, eee->curr_punch_peer);
    HASH_ADD_PEER(eee->known_peers, eee->curr_punch_peer);
    pthread_mutex_unlock(&eee->punch_access);
}

static int n4_generate_ports(uint16_t *ports, uint16_t max, uint16_t min)
{
    int port;
    int exists = 0;
    int count = 0;
    int max_range = EDGE_VISITOR_PORT_COUNT;

    if ((max - min) < max_range) {
        max_range = (max - min);
    }
    for(int i = 0; i < max_range; i++) {
        ports[i]=0;
    }
    srand(time(NULL));
    while (count < max_range) {
        port = rand() % (max - min + 1) + min;
        exists = 0;
        for (int i = 0; i < count; i++) {
            if (ports[i] == port) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            ports[count] = port;
            count++;
        }
    }
    return max_range;
}

static int punching(n2n_edge_t  *eee)
{
    int max_sd = 0;
    fd_set readfds;
    struct timeval wait_time;
    struct sockaddr_in tmp_addr;
    uint16_t tmp_port;
    socklen_t slen;
    int pool_id = 0;
    int rc;
    int id, k;
    char peer_ip_str[EDGE_INET_ADDRSTRLEN];
    char buf[32];
    khala_n4_punch_t *ptr;
    int cnt = 0;
    int port_range;

    ptr = (khala_n4_punch_t *)eee->curr_punch->ptr;
    FD_ZERO(&readfds);

    memset(peer_ip_str, 0, EDGE_INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ptr->punch_addr.sin_addr, peer_ip_str, sizeof(peer_ip_str));
    memcpy(&tmp_addr, &ptr->punch_addr, sizeof(struct sockaddr_in));
    tmp_port = ntohs(tmp_addr.sin_port);
    traceEvent(TRACE_INFO," ==> Target %s:%d\n", peer_ip_str, ntohs(ptr->punch_addr.sin_port));
again:
    wait_time.tv_sec = 3;
    wait_time.tv_usec = 0;
    switch(ptr->local_type) {
        case EDGE_N4_HOLDER: {
            /* Hold 25 socket for NAT */
            for (id = 0; id < EDGE_DEFAULT_MAX_SOCKET; id++) {
                if (max_sd < ptr->punch_pool[id]) {
                    max_sd = ptr->punch_pool[id];
                }
                FD_SET(ptr->punch_pool[id], &readfds);
                sendto(ptr->punch_pool[id], EDGE_CMD_PUNCH, strlen(EDGE_CMD_PUNCH), 0, (struct sockaddr *)&(tmp_addr), sizeof(struct sockaddr_in));
                sendto(ptr->punch_pool[id], EDGE_CMD_PUNCH, strlen(EDGE_CMD_PUNCH), 0, (struct sockaddr *)&(tmp_addr), sizeof(struct sockaddr_in));
                sendto(ptr->punch_pool[id], EDGE_CMD_PUNCH, strlen(EDGE_CMD_PUNCH), 0, (struct sockaddr *)&(tmp_addr), sizeof(struct sockaddr_in));
            }
            break;
        }
        case EDGE_N4_VISITOR: {
            /* Generate 600 Ports to visit */
            uint16_t ports[EDGE_VISITOR_PORT_COUNT];
            int max_range;
            max_sd = ptr->punch_pool[EDGE_POOL_HEAD];
            FD_SET(ptr->punch_pool[EDGE_POOL_HEAD], &readfds);
            max_range = n4_generate_ports(ports, ptr->peer_max_port, ptr->peer_min_port);
            for (k = 0; k < max_range; k++) {
                tmp_addr.sin_port = htons(ports[k]);
                sendto(ptr->punch_pool[EDGE_POOL_HEAD], EDGE_CMD_PUNCH, strlen(EDGE_CMD_PUNCH), 0, (struct sockaddr *)&(tmp_addr), sizeof(struct sockaddr_in));
                sendto(ptr->punch_pool[EDGE_POOL_HEAD], EDGE_CMD_PUNCH, strlen(EDGE_CMD_PUNCH), 0, (struct sockaddr *)&(tmp_addr), sizeof(struct sockaddr_in));
                sendto(ptr->punch_pool[EDGE_POOL_HEAD], EDGE_CMD_PUNCH, strlen(EDGE_CMD_PUNCH), 0, (struct sockaddr *)&(tmp_addr), sizeof(struct sockaddr_in));
            }
            break;
        }
    }

    rc = select(max_sd + 1, &readfds, NULL, NULL, &wait_time);
    if (rc > 0) {
        for (id = 0; id < EDGE_DEFAULT_MAX_SOCKET; id++) {
            if (ptr->punch_pool[id] > -1 && FD_ISSET(ptr->punch_pool[id], &readfds)) {
                pool_id = id;
                uint8_t  pktbuf[N2N_PKT_BUF_SIZE];
                struct sockaddr_in sender_sock;
                memset(pktbuf, 0, N2N_PKT_BUF_SIZE);
                ssize_t recvlen = recvfrom(ptr->punch_pool[pool_id], pktbuf, N2N_PKT_BUF_SIZE, 0, (struct sockaddr *)&sender_sock, &slen);
                if (n4_stop_cmd(pktbuf)) {
                    return -1;
                }
                if (!strncmp(pktbuf, EDGE_CMD_PUNCH, strlen(EDGE_CMD_PUNCH)) && ntohs(sender_sock.sin_port) != 0) {
                    n4_set_p2p_sock(eee, ptr->punch_pool[pool_id], &sender_sock);
                    traceEvent(TRACE_INFO," <= Punch Win from peer [%s:%u]\n", intoa(ntohl(sender_sock.sin_addr.s_addr), buf, sizeof(buf)),
                        ntohs(sender_sock.sin_port));
                    break;
                } else {
                    traceEvent(TRACE_DEBUG, "<= Received %d [%s] from [%s:%u]", recvlen, pktbuf, intoa(ntohl(sender_sock.sin_addr.s_addr), buf, sizeof(buf)),
                        ntohs(sender_sock.sin_port));
                    if (cnt < EDGE_N4_MAX_RETRY) {
                        goto again;
                    } else {
                        return -1;
                    }
                }
            }
        }
    } else {
        if (cnt < EDGE_N4_MAX_RETRY) {
            cnt++;
            traceEvent(TRACE_NORMAL, "N4 Timed out %s", (ptr->local_type == EDGE_N4_HOLDER) ? "Hold Nat" : "Try other Ports");
            goto again;
        } else {
            return -1;
        }
    }

    for (int i = 0; i < 10 ; i++) {
        sendto(ptr->punch_pool[pool_id], EDGE_CMD_PUNCH, strlen(EDGE_CMD_PUNCH), 0, (struct sockaddr *)&(ptr->punch_addr), sizeof(struct sockaddr_in));
    }
    return ptr->punch_pool[pool_id];
}

static void n4_get_port_range(n2n_edge_t *eee, khala_n4_punch_t *ptr)
{
    uint16_t ports = 0;
    int ret;
    n2n_sock_str_t sockbuf;

    sock_to_ip(sockbuf, &(eee->curr_sn->sock));
    ptr->min_port = 0xffff;
    ptr->max_port = 0;
    for(int i = 0; i < 10; i++) {
        ports = 0;
        ret = send_stun_binding(eee, ptr->punch_port + i, sockbuf, STUN_SERVER_PORT1, &ports);
        if (ret == 0) {
            traceEvent(TRACE_NORMAL, "Get Mapped Port [%d]", ports);
            ptr->min_port = (ports < ptr->min_port) ? ports : ptr->min_port;
            ptr->max_port = (ptr->max_port < ports) ? ports : ptr->max_port;
        }
        usleep(50000);
    }
    ptr->min_port = ((ptr->min_port - EDGE_N4_HNAT_PORT_GAP) > 0) ? (ptr->min_port - EDGE_N4_HNAT_PORT_GAP) : ptr->min_port;
    ptr->max_port = ((ptr->max_port + EDGE_N4_HNAT_PORT_GAP) < 0xffff) ? (ptr->max_port + EDGE_N4_HNAT_PORT_GAP) : ptr->max_port;
    traceEvent(TRACE_NORMAL, "N4 Min-Port[%d] Max-Port[%d]", ptr->min_port, ptr->max_port);
}

static int n4_punching(n2n_edge_t *eee)
{
    ssize_t msg_type;
    int ret;
    khala_n4_punch_t *ptr;

    ret = -1;
    ptr = (khala_n4_punch_t *)eee->curr_punch->ptr;
    n4_init_pool(eee);
    if ((ptr->min_port == 0 || ptr->max_port == 0) && eee->conf.nat_type == STUN_HARD_NAT) {
        n4_get_port_range(eee, ptr);
    } else if (eee->conf.nat_type == STUN_EASY_NAT) {
        ptr->min_port = ptr->punch_port - EDGE_N4_EHAT_PORT_GAP;
        ptr->max_port = ptr->punch_port + EDGE_N4_EHAT_PORT_GAP;
    }
retry:
    if (punch_stop) {
        n4_close_pool(eee, ret);
        return -1;
    }
    n4_send_hello(eee, ptr);
    traceEvent(TRACE_INFO,"N4 => Hello \n");
    msg_type = n4_recv_process(eee);
    if (msg_type != MSG_TYPE_N4_HELLO) {
        traceEvent(TRACE_WARNING,"N4 => Unknow MSG type %d expected [%d]", msg_type, MSG_TYPE_N4_HELLO);
        goto retry;
    }
    msg_type = n4_recv_process(eee);
    if (msg_type != MSG_TYPE_N4_PIINFO) {
        traceEvent(TRACE_WARNING,"N4 => Unknow MSG type %d expected [%d]", msg_type, MSG_TYPE_N4_PIINFO);
        goto retry;
    }
    ret = punching(eee);
    n4_close_pool(eee, ret);
    if (ret < 0) {
        /* Failed */
        traceEvent(TRACE_WARNING,"N4 ==> Local-Port [%d] failed\n", ptr->punch_port);
        return -1;
    }
    /* Success */
    return 0;
}

static int n4_lose(n2n_edge_t *eee)
{
    return 0;
}

static int n4_win(n2n_edge_t *eee)
{
    return 0;
}

static void n4_stop(n2n_edge_t *eee)
{
    struct sockaddr_in peer_addr;
    int index = 0;
    khala_n4_punch_t *ptr;

    ptr = (khala_n4_punch_t *)eee->curr_punch->ptr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr.s_addr = htonl(eee->conf.bind_address);
    peer_addr.sin_port = htons(ptr->punch_port);

    for (index = EDGE_POOL_HEAD; index < EDGE_DEFAULT_MAX_SOCKET; index++) {
        if (ptr->punch_pool[index] > 0) {
            sendto(ptr->punch_pool[index], EDGE_CMD_STOP, strlen(EDGE_CMD_STOP), 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
            break;
        }
    }
}

static void n4_cleanup(n2n_edge_t *eee)
{
    n4_close_pool(eee, -1);
}

static void n4_paris(n2n_sn_t *sss, struct sn_community *comm, n2n_punch_pairs_t *pairs, sendto_sock_t sendto_sock)
{
    n2n_common_t cmn;
    n4_PIINFO_t piinfo, piinfo2;
    uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
    uint8_t encbuf2[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0, encx2 = 0;

    memset(&piinfo, 0, sizeof(n4_PIINFO_t));
    memset(&piinfo2, 0, sizeof(n4_PIINFO_t));

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_n4_piinfo;
    cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
    memcpy(cmn.community, comm->community, sizeof(n2n_community_t));

    if (pairs->edge1->nat_type != pairs->edge2->nat_type) {
        if (pairs->edge1->nat_type > pairs->edge2->nat_type) {
            piinfo2.n4_type = EDGE_N4_HOLDER;
            piinfo.n4_type = EDGE_N4_VISITOR;
        } else {
            piinfo.n4_type = EDGE_N4_HOLDER;
            piinfo2.n4_type = EDGE_N4_VISITOR;
        }
    } else {
        if ((pairs->edge1->max_port - pairs->edge1->min_port) > (pairs->edge2->max_port - pairs->edge2->min_port)) {
            /* Edge2 is vistor send vistor to edge2 */
            piinfo.n4_type = EDGE_N4_VISITOR;
            /* Edge1 is holder send holder to edge1 */
            piinfo2.n4_type = EDGE_N4_HOLDER;
        } else {
            /* Edge2 is holder send holder to edge2 */
            piinfo.n4_type = EDGE_N4_HOLDER;
            /* Edge1 is vistor send vistor to edge1 */
            piinfo2.n4_type = EDGE_N4_VISITOR;
        }
    }

    /* to edge2 */
    encx = 0;
    encode_mac(piinfo.peerMac, &encx, pairs->edge1->mac_addr);
    piinfo.peerPort = pairs->edge1->punch_port;
    piinfo.sock.family = AF_INET;
    piinfo.sock.port = piinfo.peerPort;
    piinfo.peer_min_port = pairs->edge1->min_port;
    piinfo.peer_max_port = pairs->edge1->max_port;
    memcpy(piinfo.sock.addr.v4, pairs->edge1->sock.addr.v4, IPV4_SIZE);
    encx = 0;
    encode_N4_PIINFO(encbuf, &encx, &cmn, &piinfo);
    pairs->edge1->punch_port = 0;
    pairs->edge1->ok = 0;
    /* to edge1 */
    encx2 = 0;
    encode_mac(piinfo2.peerMac, &encx2, pairs->edge2->mac_addr);
    piinfo2.peerPort = pairs->edge2->punch_port;
    piinfo2.sock.family = AF_INET;
    piinfo2.sock.port = piinfo2.peerPort;
    piinfo2.peer_min_port = pairs->edge2->min_port;
    piinfo2.peer_max_port = pairs->edge2->max_port;
    memcpy(piinfo2.sock.addr.v4, pairs->edge2->sock.addr.v4, IPV4_SIZE);
    pairs->edge2->punch_port = 0;
    pairs->edge2->ok = 0;
    encx2 = 0;
    encode_N4_PIINFO(encbuf2, &encx2, &cmn, &piinfo2);

    sendto_sock(sss, sss->sock, (struct sockaddr *)&pairs->edge2->punch_sock, encbuf, encx);
    sendto_sock(sss, sss->sock, (struct sockaddr *)&pairs->edge1->punch_sock, encbuf2, encx2);
    memset(&pairs->edge2->punch_sock, 0, sizeof(pairs->edge2->punch_sock));
    memset(&pairs->edge1->punch_sock, 0, sizeof(pairs->edge1->punch_sock));
}

/*
N4
1. Hello -> Supernode
2. Receive Hello <- Supernode
3. Receive Piinfo <- Supernode
4. Punching -> Peer
5. Receive Peer <- Peer
*/

khala_punch_t n4_punch = {
    .name = "N4",
    .type = EDGE_N4_CAPS,
    .punch_loop = EDGE_N4_MAX_RETRY,
    .punching = n4_punching,
    .punch_lose = n4_lose,
    .punch_win = n4_win,
    .punch_stop = n4_stop,
    .punch_cleanup = n4_cleanup,
    .paris_fn = n4_paris,
    .ptr = &n4,
};
