#ifndef _PUNCH_N4_
#define _PUNCH_N4_
#include <stdbool.h>

#define EDGE_DEFAULT_MAX_SOCKET     (25)
#define EDGE_DEFAULT_PORT_OFFSET    (20)
#define EDGE_CMD_PUNCH              "05!BBSn4"
#define EDGE_POOL_START             (1)
#define EDGE_POOL_HEAD              (0)
#define EDGE_N4_MAX_RETRY           (10)
#define EDGE_N4_HNAT_PORT_GAP       (200)
#define EDGE_N4_EHAT_PORT_GAP       (20)

#define EDGE_N4_HOLDER              (1)
#define EDGE_N4_VISITOR             (2)

#define EDGE_VISITOR_PORT_COUNT     (600)


typedef struct khala_n4_punch {
    int                              punch_pool[EDGE_DEFAULT_MAX_SOCKET]; /* pool[0] used to exchange info via supernode */
    uint16_t                         punch_port;
    struct sockaddr_in               punch_addr;
    int                              local_type;
    uint16_t                         min_port;
    uint16_t                         max_port;
    uint16_t                         peer_min_port;
    uint16_t                         peer_max_port;
} khala_n4_punch_t;

extern khala_punch_t n4_punch;
#endif
