/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGNFQ_LOOP_H
#define FALGNFQ_LOOP_H

#include "falgnfq-config.h"

struct falgnfq_loop;
typedef struct falgnfq_loop FalgnfqLoop;

FalgnfqLoop*    falgnfq_loop_new        (FalgnfqConfig *config);
int             falgnfq_loop_run        (FalgnfqLoop *loop);
void            falgnfq_loop_free       (FalgnfqLoop *loop);

#endif /* FALGNFQ_LOOP_H */
