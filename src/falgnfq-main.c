/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgnfq-config.h"
#include "falgnfq-loop.h"
#include "falgnfq-private.h"

#include <locale.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


int falgnfq_ndebug;
int falgnfq_exit;

static void usage (const char* name) {
    printf (
        "Usage:   %s family queue_num protocol default_mark "
        "[[param1 mark1] [param2 mark2] ...]\n"
        "Example: %s ipv4 0 http 1 a.csie.org 2 b.csie.org 3\n", name, name);
    exit (0);
}

int main (int argc, char *argv[]) {

    setlocale (LC_ALL, "");
    tzset ();

    char *name = strrchr (argv[0], '/');
    if (name == NULL) {
        name = argv[0];
    } else {
        name++;
    }

    if (getenv ("NDEBUG")) {
        falgnfq_ndebug = 1;
    }

    // No argument -> usage()
    if (argc <= 1) {
        usage (name);
    }

    // TODO: Use getopt()
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            usage (name);
        }
    }

    char *error;
    FalgnfqConfig *config;
    FalgnfqLoop *loop;

    config = falgnfq_config_new_from_arg (argc, argv, false, &error);
    if (config == NULL) {
        fprintf (stderr, "%s: %s\nType `%s -h\' to read the help message\n",
            name, error, name);
        free (error);
        exit (1);
    }

    loop = falgnfq_loop_new (config);
    if (loop == NULL) {
        exit (1);
    }

    falgnfq_loop_run (loop);
    falgnfq_loop_free (loop);
    falgnfq_config_free (config);

    return 0;
}
