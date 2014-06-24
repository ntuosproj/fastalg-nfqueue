/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGNFQ_RNG_H
#define FALGNFQ_RNG_H

#include <stdint.h>

int             falgnfq_rng_new         (void);
uint32_t        falgnfq_rng_gen         (int fd);
void            falgnfq_rng_free        (int fd);

#endif /* FALGNFQ_RNG_H */
