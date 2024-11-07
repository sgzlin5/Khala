#ifndef _PUNCH_JUICE_
#define _PUNCH_JUICE_
#include <stdbool.h>

typedef struct khala_juice_punch {
    int sock;
    uint32_t    local_port;
    juice_agent_t                    *juice_agent;
    juice_config_t                   juice_conf;
    juice_turn_server_t              turn_server;
} khala_juice_punch_t;

#define JUICE_EX_PORT                (63000)
#define EDGE_JUICE_MAX_RETRY         (5)

extern khala_punch_t juice_punch;
#endif
