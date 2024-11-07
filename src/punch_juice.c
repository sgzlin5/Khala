#include "n2n.h"
#include "network_traffic_filter.h"
#include "edge_utils_win32.h"

khala_juice_punch_t juice = {
    .sock = -1,
    .juice_agent = NULL,
};
/* 
Juice
1. Send SDP -> Supernode -> Peer
2. Receive SDP <- Supernode
3. Send Candiate -> Supernode -> Peer
4. Receive Candiate <- Supernode
5. Check Status
*/
static void juice_init_socket(n2n_edge_t *eee)
{
    struct sockaddr_in peer_addr;
    u_int opt = 1;
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    if (ptr->sock < 0) {
        ptr->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        setsockopt(ptr->sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(socklen_t));
        setsockopt(ptr->sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(socklen_t));
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(JUICE_EX_PORT);
        peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        bind(ptr->sock,(struct sockaddr*) &peer_addr, sizeof(peer_addr));
    }
}

static void juice_close_socket(n2n_edge_t *eee)
{
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    if (ptr->sock > 0) {
        closesocket(ptr->sock);
        ptr->sock = -1;
    }
}

static ssize_t juice_sendto_sock(n2n_edge_t *eee, const void * buf, size_t len)
{
    struct sockaddr_in peer_addr;
    ssize_t sent = 0;
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    if (ptr->sock < 0) {
        return 0;
    }

    fill_sockaddr((struct sockaddr *) &peer_addr, sizeof(peer_addr), &(eee->curr_sn->sock));
    sent = sendto(ptr->sock, buf, len, 0, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr_in));
    if (sent < 0 && errno) {
        char * c = strerror(errno);
        traceEvent(TRACE_ERROR, "ex sendto supernode failed (%d) %s", errno, c);
    }
    return sent;
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    char buffer[N2N_MSG_BUF_SIZE];
    if (size > N2N_MSG_BUF_SIZE - 1)
        size = N2N_MSG_BUF_SIZE - 1;
    memcpy(buffer, data, size);
    buffer[size] = '\0';
    traceEvent(TRACE_DEBUG, "JUICE Received: %s\n", buffer);
}

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
    traceEvent(TRACE_DEBUG, "JUICE State : %s\n", juice_state_to_string(state));

    if (state == JUICE_STATE_CONNECTED) {
        const char *message = "Hello Peer";
        juice_send(agent, message, strlen(message));
    }
}

static void juice_send_candidate(n2n_edge_t *eee, const char *candidate_buf)
{
    n2n_common_t common;
    juice_CANDIDATE_t candidate;
    size_t idx;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};

    memset(&common, 0, sizeof(common));
    memset(&candidate, 0, sizeof(candidate));
    common.ttl = N2N_DEFAULT_TTL;
    common.pc = n2n_juice_candidate;
    common.flags = 0;
    memcpy(common.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    idx = 0;
    encode_mac(candidate.srcMac, &idx, eee->device.mac_addr);
    idx = 0;
    encode_mac(candidate.peerMac, &idx, eee->curr_punch_peer->mac_addr);
    memcpy(candidate.candidate, candidate_buf, N2N_MSG_BUF_SIZE);
    idx = 0;
    encode_CANDIDATE(pktbuf, &idx, &common, &candidate);
    juice_sendto_sock(eee, pktbuf, idx);
}

static void juice_send_sdp(n2n_edge_t *eee, const char *sdp_buf)
{
    n2n_common_t common;
    juice_SDP_t sdp;
    size_t idx;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};

    memset(&common, 0, sizeof(common));
    memset(&sdp, 0, sizeof(sdp));
    common.ttl = N2N_DEFAULT_TTL;
    common.pc = n2n_juice_sdp;
    common.flags = 0;
    memcpy(common.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    idx = 0;
    encode_mac(sdp.srcMac, &idx, eee->device.mac_addr);
    idx = 0;
    encode_mac(sdp.peerMac, &idx, eee->curr_punch_peer->mac_addr);
    memcpy(sdp.sdp, sdp_buf, N2N_MSG_BUF_SIZE);
    idx = 0;
    encode_SDP(pktbuf, &idx, &common, &sdp);
    juice_sendto_sock(eee, pktbuf, idx);
}

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
    n2n_edge_t *eee = (n2n_edge_t *) user_ptr;
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    /* sdp is a RFC5245 string which should look like this:
        * "a=candidate:2 1 UDP <prio> <ip> <port> typ <type> ..."
        * Since libjuice reports only the external (after NAT translation)
        * receive port, we need to get the receive port number from the local
        * candidate (of type "host").
        */

    const char *c = sdp;
    //port is located after 5 space characters
    for(int i = 0; i < 5; i++){
            c = strchr(c, ' ') + 1;
            assert(c);
    }
    char *end;
    int port = strtol(c, &end, 10);
    assert(c != end);
    assert(*end == ' ');
    c = end + 1;

    if(strncmp(c, "typ host", strlen("typ host")) == 0){
        traceEvent(TRACE_DEBUG, "Local candidate port: %d\n", port);
        ptr->local_port = port;
    }

    if (!strstr(sdp, "typ srflx")) {
        return;
    }
    /* Only collect srflx */
    juice_send_candidate(eee, sdp);
    traceEvent(TRACE_DEBUG, "Received candidate: %s \nSend to Server\n", sdp);
}

static void juice_create_agent(n2n_edge_t *eee){
    char server_ipstr[N2N_SOCKBUF_SIZE];
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    memset(server_ipstr, 0, N2N_SOCKBUF_SIZE);

    snprintf(server_ipstr, N2N_SOCKBUF_SIZE, "%hu.%hu.%hu.%hu",
                 (unsigned short)(eee->curr_sn->sock.addr.v4[0] & 0xff),
                 (unsigned short)(eee->curr_sn->sock.addr.v4[1] & 0xff),
                 (unsigned short)(eee->curr_sn->sock.addr.v4[2] & 0xff),
                 (unsigned short)(eee->curr_sn->sock.addr.v4[3] & 0xff));
    traceEvent(TRACE_DEBUG, "Juice bind TURN: [%s]", server_ipstr);
    memset(&ptr->juice_conf, 0, sizeof(ptr->juice_conf));

    ptr->turn_server.host = server_ipstr;
    ptr->turn_server.username = DEFAULT_TURN_USER;
    ptr->turn_server.password = DEFAULT_TURN_PASWD;
    ptr->turn_server.port = DEFAULT_TURN_PORT;

    ptr->juice_conf.stun_server_host = server_ipstr;
    ptr->juice_conf.stun_server_port = DEFAULT_TURN_PORT;

    ptr->juice_conf.turn_servers = &ptr->turn_server;
    ptr->juice_conf.turn_servers_count = 1;

    ptr->juice_conf.cb_candidate = on_candidate;
    ptr->juice_conf.cb_recv = on_recv;
    ptr->juice_conf.cb_state_changed = on_state_changed;
    ptr->juice_conf.user_ptr = eee;
    ptr->juice_conf.concurrency_mode = JUICE_CONCURRENCY_MODE_THREAD;
    ptr->juice_agent =  juice_create(&ptr->juice_conf);
}

static void juice_destory_agent(n2n_edge_t *eee)
{
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    juice_close_socket(eee);
    if (ptr->juice_agent) {
        juice_destroy(ptr->juice_agent);
        ptr->juice_agent = NULL;
    }
}

static int juice_stop_cmd(uint8_t *pktbuf)
{
    if (!strncmp(pktbuf, EDGE_CMD_STOP, strlen(EDGE_CMD_STOP))) {
        traceEvent(TRACE_NORMAL," <= Edge is stopping");
        return 1;
    }
    return 0;
}

static size_t juice_recv_process(n2n_edge_t *eee, size_t exp)
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
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    memset(pktbuf, 0, N2N_PKT_BUF_SIZE);
    FD_ZERO(&readfds);
    FD_SET(ptr->sock, &readfds);
    slen = sizeof(sender_sock);
    max_sd = ptr->sock;

    wait_time.tv_sec = 2;
    wait_time.tv_usec = 0;

    rc = select(max_sd + 1, &readfds, NULL, NULL, &wait_time);
    if (rc > 0) {
        recvlen = recvfrom(ptr->sock, pktbuf, N2N_PKT_BUF_SIZE, 0, (struct sockaddr *)&sender_sock, &slen);
        if(recvlen < 0) {
            traceEvent(TRACE_WARNING, "punch recvfrom failed: %d - %s", errno, strerror(errno));
            return msg_type;
        }
        if (juice_stop_cmd(pktbuf)) {
            return -1;
        }
        /* Decode pktbuf */
        idx = 0; /* marches through packet header as parts are decoded. */
        if(decode_common(&cmn, pktbuf, &recvlen, &idx) < 0) {
            traceEvent(TRACE_INFO, "failed to decode common section in N2N_UDP");
            return msg_type; /* failed to decode packet */
        }
        msg_type = cmn.pc;
        if (exp != msg_type) {
            return 0;
        }
        from_supernode = cmn.flags & N2N_FLAGS_FROM_SUPERNODE;
        if (!from_supernode) {
            return msg_type;
        }

        if(0 == memcmp(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE)) {
            switch(msg_type) {
                case MSG_TYPE_JUICE_SDP: {
                    juice_SDP_t sdp;
 
                    memset(&sdp, 0, sizeof(juice_SDP_t));
                    decode_SDP(&sdp, &cmn, pktbuf, &recvlen, &idx);
                    traceEvent(TRACE_DEBUG, "Rx JUICE SDP \n%s", sdp.sdp);
                    juice_set_remote_description(ptr->juice_agent, sdp.sdp);
                    break;
                }
                case MSG_TYPE_JUICE_CANDIDATE: {
                    juice_CANDIDATE_t candidate;

                    memset(&candidate, 0, sizeof(juice_CANDIDATE_t));
                    decode_CANDIDATE(&candidate, &cmn, pktbuf, &recvlen, &idx);
                    traceEvent(TRACE_DEBUG, "Rx JUICE CANDIDATE %s add to remote candidate", candidate.candidate);
                    juice_add_remote_candidate(ptr->juice_agent, candidate.candidate);
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

static int juice_set_p2p_sock(n2n_edge_t *eee, char *remote)
{
    u_int opt = 1;
    time_t now;
    char ipstr[EDGE_INET_ADDRSTRLEN];
    uint32_t port = 0;
    struct sockaddr_in peer_addr;
    khala_juice_punch_t *ptr;
    char *colon;
    struct peer_info *tmp;
    int sock = -1;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    now = time(NULL);
    memset(ipstr, 0, EDGE_INET_ADDRSTRLEN);
    memset(&eee->curr_punch_peer->punch_sock, 0, sizeof(eee->curr_punch_peer->punch_sock));
    
    colon = strchr(remote, ':');
    if (colon != NULL) {
        size_t ip_length = colon - remote;

        strncpy(ipstr, remote, ip_length);
        ipstr[ip_length] = '\0';
        port = atoi(colon + 1);
        traceEvent(TRACE_INFO, "Juice Win : [%s:%d]\n", ipstr, port);
    } else {
        traceEvent(TRACE_WARNING, "Invalid input format [%s]\n", remote);
    }
    
    if (eee->curr_punch_peer->p2p_sock > 0) {
        closesocket(eee->curr_punch_peer->p2p_sock);
        eee->curr_punch_peer->p2p_sock = -1;
    }
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        traceEvent(TRACE_WARNING, "Init P2P Socket Failed");
        return -1;
    }
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(socklen_t));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(socklen_t));
    eee->curr_punch_peer->punch_sock.sin_family = AF_INET;
    eee->curr_punch_peer->punch_sock.sin_port = htons(port);

    inet_ntop(AF_INET, &eee->curr_punch_peer->punch_sock.sin_addr.s_addr, ipstr, sizeof(ipstr));
    eee->curr_punch_peer->sock.port = port;
    eee->curr_punch_peer->last_seen = now;
    eee->curr_punch_peer->last_p2p = now;

    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(ptr->local_port);
    peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock,(struct sockaddr*) &peer_addr, sizeof(peer_addr)) < 0) {
        traceEvent(TRACE_WARNING, "Bind P2P Socket Failed (%s)", strerror(errno));
        closesocket(sock);
        eee->curr_punch_peer->p2p_sock = -1;
        return -1;
    }

    HASH_FIND_PEER(eee->pending_peers, eee->curr_punch_peer->mac_addr, tmp);
    if (tmp == NULL) {
        traceEvent(TRACE_WARNING, "Pending Peer removed, already in P2P");
        closesocket(sock);
        return -1;
    }
    eee->curr_punch_peer->p2p_sock = sock;
    pthread_mutex_lock(&eee->punch_access);
    HASH_DEL(eee->pending_peers, eee->curr_punch_peer);
    HASH_ADD_PEER(eee->known_peers, eee->curr_punch_peer);
    pthread_mutex_unlock(&eee->punch_access);
    return 0;
}

static int juice_punching(n2n_edge_t *eee)
{
    size_t msg_type;
    char sdp[N2N_MSG_BUF_SIZE];
    char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
    char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
    fd_set rfds;
    juice_state_t state;
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    juice_init_socket(eee);
    juice_create_agent(eee);
    juice_get_local_description(ptr->juice_agent, sdp, N2N_MSG_BUF_SIZE);
    traceEvent(TRACE_NORMAL, "Local SDP\n%s\n", sdp);
    /* Send SDP to supernode */
retry:
    if (punch_stop) {
        juice_destory_agent(eee);
        return -1;
    }
    juice_send_sdp(eee, sdp);
    /* Wait for remote SDP */
    msg_type = juice_recv_process(eee, MSG_TYPE_JUICE_SDP);
    if (msg_type != MSG_TYPE_JUICE_SDP) {
        traceEvent(TRACE_WARNING,"JUICE => Unknow MSG type %d \n", msg_type);
        goto retry;
    }

    FD_ZERO(&rfds);
    FD_SET(ptr->sock, &rfds);

    juice_gather_candidates(ptr->juice_agent);
    /* Wait to receive all candidates */
    while(1){
        msg_type = juice_recv_process(eee, MSG_TYPE_JUICE_CANDIDATE);
        if (msg_type < 0 || punch_stop) {
            break;
        }
        state = juice_get_state(ptr->juice_agent);
        if(state == JUICE_STATE_COMPLETED || state == JUICE_STATE_FAILED) {
            traceEvent(TRACE_WARNING, "Juice Completed\n");
            break;
        }
    }

    state = juice_get_state(ptr->juice_agent);
    if(state != JUICE_STATE_COMPLETED){
        traceEvent(TRACE_WARNING, "Punching finished unsuccessfuly (state: %s)\n", juice_state_to_string(state));
        juice_destory_agent(eee);
        return -1;
    }

    if ((juice_get_selected_addresses(ptr->juice_agent,
                                    local,
                                    JUICE_MAX_CANDIDATE_SDP_STRING_LEN,
                                    remote,
                                    JUICE_MAX_CANDIDATE_SDP_STRING_LEN) != 0))
    {
        traceEvent(TRACE_WARNING, "Failed to read selected addresses\n");
        juice_destory_agent(eee);
        return -1;
    }
    traceEvent(TRACE_INFO, "Local candidate  : %s\n", local);
    traceEvent(TRACE_INFO, "Remote candidate : %s\n", remote);
    /* Set P2P socket and address */
    if (eee->curr_punch_peer == NULL) {
        juice_destory_agent(eee);
        return -1;
    }
    juice_destory_agent(eee);
    if (juice_set_p2p_sock(eee, remote) < 0) {
        return -1;
    }

    return 0;
}

static int juice_lose(n2n_edge_t *eee)
{
    return 0;
}

static int juice_win(n2n_edge_t *eee)
{
    return 0;
}

static void juice_stop(n2n_edge_t *eee)
{
    struct sockaddr_in peer_addr;    
    khala_juice_punch_t *ptr;

    ptr = (khala_juice_punch_t *)eee->curr_punch->ptr;
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_addr.s_addr = htonl(eee->conf.bind_address);
    peer_addr.sin_port = htons(JUICE_EX_PORT);

    sendto(ptr->sock, EDGE_CMD_STOP, strlen(EDGE_CMD_STOP), 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
}

static void juice_cleanup(n2n_edge_t *eee)
{
    return;
}

static void juice_paris(n2n_sn_t *sss, struct sn_community *comm, n2n_punch_pairs_t *pairs, sendto_sock_t sendto_sock)
{
    n2n_common_t cmn;
    uint8_t encbuf[N2N_SN_PKTBUF_SIZE];
    uint8_t encbuf2[N2N_SN_PKTBUF_SIZE];
    size_t encx = 0, encx2 = 0;

    juice_SDP_t sdp, sdp2;
    memset(&sdp, 0, sizeof(juice_SDP_t));
    memset(&sdp2, 0, sizeof(juice_SDP_t));

    cmn.ttl = N2N_DEFAULT_TTL;
    cmn.pc = n2n_juice_sdp;
    cmn.flags = N2N_FLAGS_FROM_SUPERNODE;
    memcpy(cmn.community, comm->community, sizeof(n2n_community_t));

    /* to edge2 */
    encx = 0;
    encode_mac(sdp.peerMac, &encx, pairs->edge1->mac_addr);
    encx = 0;
    encode_mac(sdp.srcMac, &encx, pairs->edge2->mac_addr);
    memcpy(sdp.sdp, pairs->edge1->sdp, N2N_MSG_BUF_SIZE);
    encx = 0;
    encode_SDP(encbuf, &encx, &cmn, &sdp);
    

    /* to edge1 */
    encx2 = 0;
    encode_mac(sdp2.peerMac, &encx2, pairs->edge2->mac_addr);
    encx2 = 0;
    encode_mac(sdp2.srcMac, &encx2, pairs->edge1->mac_addr);
    memcpy(sdp2.sdp, pairs->edge2->sdp, N2N_MSG_BUF_SIZE);
    encx2 = 0;
    encode_SDP(encbuf2, &encx2, &cmn, &sdp2);

    sendto_sock(sss, sss->sock, (struct sockaddr *)&pairs->edge2->punch_sock, encbuf, encx);
    sendto_sock(sss, sss->sock, (struct sockaddr *)&pairs->edge1->punch_sock, encbuf2, encx2);

    sendto_sock(sss, sss->sock, (struct sockaddr *)&pairs->edge2->punch_sock, encbuf, encx);
    sendto_sock(sss, sss->sock, (struct sockaddr *)&pairs->edge1->punch_sock, encbuf2, encx2);

    sendto_sock(sss, sss->sock, (struct sockaddr *)&pairs->edge2->punch_sock, encbuf, encx);
    sendto_sock(sss, sss->sock, (struct sockaddr *)&pairs->edge1->punch_sock, encbuf2, encx2);

    pairs->edge1->ok = 2;
    pairs->edge2->ok = 2;

}

khala_punch_t juice_punch = {
    .name = "JUICE",
    .type = EDGE_JUICE_CAPS,
    .punch_loop = EDGE_JUICE_MAX_RETRY,
    .punching = juice_punching,
    .punch_lose = juice_lose,
    .punch_win = juice_win,
    .punch_stop = juice_stop,
    .punch_cleanup = juice_cleanup,
    .paris_fn = juice_paris,
    .ptr = &juice,
};

/* Juice End */