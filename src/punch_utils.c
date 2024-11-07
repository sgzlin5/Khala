#include "n2n.h"
#include "network_traffic_filter.h"
#include "edge_utils_win32.h"

bool punch_stop;
/* Common */
static ssize_t sendto_ex_sock(n2n_edge_t *eee, const void * buf, size_t len)
{
    struct sockaddr_in peer_addr;
    ssize_t sent = 0;

    if (eee->ex_sock < 0) {
        return 0;
    }

    fill_sockaddr((struct sockaddr *) &peer_addr, sizeof(peer_addr), &(eee->curr_sn->sock));
    sent = sendto(eee->ex_sock, buf, len, 0, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr_in));
    if (sent < 0 && errno) {
        char * c = strerror(errno);
        traceEvent(TRACE_ERROR, "ex sendto supernode failed (%d) %s", errno, c);
    }
    return sent;
}

static void edge_init_ex_sock(n2n_edge_t *eee)
{
    struct sockaddr_in peer_addr;
    u_int opt = 1;

    if (eee->ex_sock < 0) {
        eee->ex_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        setsockopt(eee->ex_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(socklen_t));
        setsockopt(eee->ex_sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(socklen_t));
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons(EDGE_EX_PORT);
        peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        bind(eee->ex_sock,(struct sockaddr*) &peer_addr, sizeof(peer_addr));
    }
}

static void edge_close_ex_sock(n2n_edge_t *eee)
{
    if (eee->ex_sock > 0) {
        closesocket(eee->ex_sock);
        eee->ex_sock = -1;
    }
}

/* 
1. Send Hello -> Supernode
2. Receive Punch Method <- Supernode
3. Run n4 or juice
*/
static void edge_send_hello(n2n_edge_t *eee)
{
    n2n_common_t common;
    n2n_PUNCH_HELLO_t hello;
    size_t idx;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};

    memset(&common, 0, sizeof(common));
    memset(&hello, 0, sizeof(hello));
    common.ttl = N2N_DEFAULT_TTL;
    common.pc = n2n_punch_hello;
    common.flags = 0;
    memcpy(common.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    idx = 0;
    encode_mac(hello.srcMac, &idx, eee->device.mac_addr);
    idx = 0;
    encode_mac(hello.peerMac, &idx, eee->curr_punch_peer->mac_addr);
    idx = 0;
    encode_PUNCH_HELLO(pktbuf, &idx, &common, &hello);
    sendto_ex_sock(eee, pktbuf, idx);
}

static int edge_stop_cmd(uint8_t *pktbuf)
{
    if (!strncmp(pktbuf, EDGE_CMD_STOP, strlen(EDGE_CMD_STOP))) {
        traceEvent(TRACE_NORMAL," <= Edge is stopping");
        return 1;
    }
    return 0;
}

static size_t edge_recv_process(n2n_edge_t  *eee)
{
    struct sockaddr_in sender_sock;
    socklen_t slen;
    uint8_t  pktbuf[N2N_PKT_BUF_SIZE];
    ssize_t recvlen;
    n2n_common_t cmn;
    size_t idx;
    size_t msg_type = 0;
    uint8_t from_supernode;
    int rc = 0;
    fd_set readfds;
    struct timeval wait_time;

    memset(pktbuf, 0, N2N_PKT_BUF_SIZE);
    FD_ZERO(&readfds);
    FD_SET(eee->ex_sock, &readfds);
    slen = sizeof(sender_sock);

    wait_time.tv_sec = 10;
    wait_time.tv_usec = 0;

    rc = select(eee->ex_sock + 1, &readfds, NULL, NULL, &wait_time);
    if (rc > 0) {
        recvlen = recvfrom(eee->ex_sock, pktbuf, N2N_PKT_BUF_SIZE, 0, (struct sockaddr *)&sender_sock, &slen);
        if(recvlen < 0) {
            traceEvent(TRACE_WARNING, "ex recvfrom failed: %d - %s", errno, strerror(errno));
            return msg_type;
        }
        if (edge_stop_cmd(pktbuf)) {
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
            traceEvent(TRACE_WARNING, "Ex Sock not from Supernode");
            return msg_type;
        }

        if(0 == memcmp(cmn.community, eee->conf.community_name, N2N_COMMUNITY_SIZE)) {
            switch(msg_type) {
                case MSG_TYPE_PUNCH_METHOD: {
                    n2n_PUNCH_METHOD_t method;

                    memset(&method, 0, sizeof(n2n_PUNCH_METHOD_t));
                    decode_PUNCH_METHOD(&method, &cmn, pktbuf, &recvlen, &idx);
                    eee->curr_punch_type = method.punch_method;
                    traceEvent(TRACE_DEBUG, "Rx MSG_TYPE_PUNCH_METHOD [%d]", eee->curr_punch_type);
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

static int edge_get_punch_type(n2n_edge_t *eee)
{
    ssize_t msg_type;
    khala_punch_t *punch;
    n2n_desc_t name;

    edge_send_hello(eee);
    msg_type = edge_recv_process(eee);
    if (msg_type != MSG_TYPE_PUNCH_METHOD) {
        traceEvent(TRACE_NORMAL," => Unknow MSG type %d \n", msg_type);
        return -1;
    }
    memset(name, 0, sizeof(n2n_desc_t));
    punch_type_to_string(eee->curr_punch_type, name);
    HASH_FIND_PUNCH(eee->punch_list, name, punch);
    traceEvent(TRACE_NORMAL," => Punch type %d \n", eee->curr_punch_type);
    if (punch == NULL) {
        traceEvent(TRACE_NORMAL," => Unknow Punch type %d \n", eee->curr_punch_type);
        return -1;
    }
    eee->curr_punch = punch;
    return 0;
}

static void edge_punch_cleanup(n2n_edge_t *eee)
{
    if (eee->curr_punch != NULL) {
        eee->curr_punch->punch_cleanup(eee);
    }
    edge_close_ex_sock(eee);
    eee->curr_punch_peer = NULL;
    eee->curr_punch = NULL;
    eee->conf.punch_status = (eee->conf.punch_status != edge_punch_win) ? edge_punch_ready : edge_punch_win;
}

static void edge_send_change_method(n2n_edge_t *eee)
{
    n2n_common_t common;
    n2n_PUNCH_CHANGE_t change;
    size_t idx;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};

    memset(&common, 0, sizeof(common));
    memset(&change, 0, sizeof(change));
    common.ttl = N2N_DEFAULT_TTL;
    common.pc = n2n_change_method;
    common.flags = 0;
    memcpy(common.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    idx = 0;
    encode_mac(change.srcMac, &idx, eee->device.mac_addr);
    idx = 0;
    encode_mac(change.peerMac, &idx, eee->curr_punch_peer->mac_addr);
    idx = 0;
    encode_PUNCH_CHANGE(pktbuf, &idx, &common, &change);
    sendto_ex_sock(eee, pktbuf, idx);
}

static void edge_send_paris_done(n2n_edge_t *eee)
{
    n2n_common_t common;
    n2n_PUNCH_DONE_t done;
    size_t idx;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE] = {0};

    memset(&common, 0, sizeof(common));
    memset(&done, 0, sizeof(done));
    common.ttl = N2N_DEFAULT_TTL;
    common.pc = n2n_punch_done;
    common.flags = 0;
    memcpy(common.community, eee->conf.community_name, N2N_COMMUNITY_SIZE);

    idx = 0;
    encode_mac(done.srcMac, &idx, eee->device.mac_addr);
    idx = 0;
    encode_mac(done.peerMac, &idx, eee->curr_punch_peer->mac_addr);
    idx = 0;
    encode_PUNCH_DONE(pktbuf, &idx, &common, &done);
    sendto_ex_sock(eee, pktbuf, idx);
}

static void *punching_thread(void *data)
{
    uint8_t cnt = 0;
    int ret = -1;
    n2n_edge_t  *eee = (n2n_edge_t*)data;
    struct peer_info *peer = NULL;
    n2n_mac_t tmp_mac;

    edge_init_ex_sock(eee);
    memcpy(&tmp_mac, eee->curr_punch_peer->mac_addr, sizeof(n2n_mac_t));
    /* Try punch 20 times, if failed we never punch this peer anymore */
    while(1) {
        /* If receive MSG_TYPE_REGISTER it will remove from pending peers */
        if (punch_stop) {
            traceEvent(TRACE_NORMAL, " => Punch Stop \n");
            break;
        }
        ret = edge_get_punch_type(eee);
        if (ret < 0) {
            traceEvent(TRACE_WARNING," Failed to get our Punch method, try again \n");
            continue;
        }
        pthread_mutex_lock(&eee->punch_access);
        HASH_FIND_PEER(eee->pending_peers, tmp_mac, peer);
        pthread_mutex_unlock(&eee->punch_access);
        if (peer == NULL || eee->curr_punch == NULL) {
            traceEvent(TRACE_WARNING, "Error Punch ending");
            break;
        }
        if (eee->conf.punch_status == edge_peer_lost) {
            pthread_mutex_lock(&eee->punch_access);
            HASH_DEL(eee->pending_peers, eee->curr_punch_peer);
            free(eee->curr_punch_peer);
            pthread_mutex_unlock(&eee->punch_access);
            traceEvent(TRACE_NORMAL, " => Punch Lost \n");
            break;
        }
        eee->last_punch = time(NULL);
        traceEvent(TRACE_NORMAL," ==> Punch %d\n", cnt + 1);
        if (eee->curr_punch != NULL && cnt > eee->curr_punch->punch_loop) {
            traceEvent(TRACE_NORMAL, " => Punch Lose \n");
            eee->curr_punch_peer->punch_status = peer_punch_lose;
            eee->failed_times++;
            break;
        }

        /* Get Punch Method from Supernode, Start punching */
        ret = eee->curr_punch->punching(eee);
        if (ret == 0) {
            eee->curr_punch->punch_win(eee);
            eee->curr_punch_peer->punch_status = peer_punch_win;
            eee->conf.punch_status = edge_punch_win;
            traceEvent(TRACE_NORMAL, " => Punch Win \n");
            break;
        } else {
            eee->curr_punch->punch_lose(eee);
        }

        if (eee->conf.punch_status == edge_punch_win) {
            break;
        }
        cnt++;
    }

    if (eee->curr_punch_peer != NULL && 
        eee->curr_punch_peer->punch_status == peer_punch_lose && 
        eee->failed_times < METHOD_NUM) {
        /* Change punch method if lose */
        edge_send_change_method(eee);
        eee->curr_punch_peer->punch_status = peer_not_punched;
    } else {
        /* Send punch done to delete paris */
        edge_send_paris_done(eee);
    }
    edge_punch_cleanup(eee);
    if (punch_stop) {
        traceEvent(TRACE_NORMAL, "cleanup punching pool");
    }

    traceEvent(TRACE_NORMAL, "punching loop exit");

    return NULL;
}

/* Common End */
int punch_create_thread(n2n_edge_t  *eee)
{
    int ret;
    punch_stop = false;

    if (eee->curr_punch_peer != NULL) {
        ret = pthread_create(&eee->punch_thread_id, NULL, punching_thread, (void *)eee);
        if (ret) {
            traceEvent(TRACE_WARNING, "punch_create_thread failed to create punching thread with error number %d", ret);
            return ret;
        }

        return 0;
    }
    return -1;
}

/* Add new punching method here */
void edge_punch_init_list(n2n_edge_t *eee)
{
    HASH_ADD_PUNCH(eee->punch_list, &n4_punch);
    HASH_ADD_PUNCH(eee->punch_list, &juice_punch);
}

void edge_punch_clean_list(n2n_edge_t *eee)
{
    khala_punch_t *scan, *tmp;

    HASH_ITER(hh, eee->punch_list, scan, tmp) {
        HASH_DEL(eee->punch_list, scan);
    };
}

void sn_punch_init_list(n2n_sn_t *sss)
{
    HASH_ADD_PUNCH(sss->punch_list, &n4_punch);
    HASH_ADD_PUNCH(sss->punch_list, &juice_punch);
}

void sn_punch_clean_list(n2n_sn_t *sss)
{
    khala_punch_t *scan, *tmp;

    HASH_ITER(hh, sss->punch_list, scan, tmp) {
        HASH_DEL(sss->punch_list, scan);
    };
}