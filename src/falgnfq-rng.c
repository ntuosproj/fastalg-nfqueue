/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgnfq-rng.h"
#include "falgnfq-private.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int falgnfq_rng_new (void) {
    return open ("/dev/urandom", O_RDONLY);
}

uint32_t falgnfq_rng_gen (int fd) {
    uint32_t rn;
    ssize_t r = read (fd, &rn, sizeof (rn));

    if (r != sizeof (rn)) {
        error ("Error while reading from the random number generator");
        if_debug (1) {
            error ("DEVELOPER_MODE: UNEXPECTED ERROR, ABORT NOW!");
            abort ();
        }
    }

    return rn;
}

void falgnfq_rng_free (int fd) {
    close (fd);
}
