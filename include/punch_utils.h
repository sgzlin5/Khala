#ifndef _PUNCH_UTILS_
#define _PUNCH_UTILS_
#include <stdbool.h>
#include "punch_n4.h"
#include "punch_juice.h"

int punch_create_thread(n2n_edge_t  *eee);
void edge_punch_init_list(n2n_edge_t *eee);
void edge_punch_clean_list(n2n_edge_t *eee);
void sn_punch_init_list(n2n_sn_t *sss);
void sn_punch_clean_list(n2n_sn_t *sss);
extern bool punch_stop;
#endif
