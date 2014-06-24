/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgnfq-config.h"
#include "falgnfq-loop.h"
#include "falgnfq-private.h"

#include <locale.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


unsigned int falgnfq_debug;
volatile int falgnfq_exit;

static void falgnfq_exit_setter (int signo) {
    falgnfq_exit = 1;
}

static void usage (const char* name) {
    printf (
        "Usage:   %s family queue_num protocol default_mark "
        "[[param1 mark1 host1 port1] [param2 mark2 host2 port2] ...]\n"
        "Example: %s ipv4 0 http 1 "
        "a.csie.org 2 192.168.1.92 80 "
        "b.csie.org 3 192.168.1.93 80\n", name, name);
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

#ifdef NDEBUG
    falgnfq_debug = 0;
#else
    if (getenv ("NDEBUG")) {
        falgnfq_debug = 0;
    } else {
        char *debug_level_str = getenv ("FALGNFQ_DEBUG");
        if (debug_level_str) {
            int debug_level = atoi (debug_level_str);
            falgnfq_debug = debug_level < 0 ? 1 : (unsigned int)debug_level;
        } else {
            falgnfq_debug = 1;
        }

        debug (" ::: DEVELOPER_MODE :::");
        debug ("Set NDEBUG in your environment to suppress all debug meesage");
        debug ("Use FALGNFQ_DEBUG to set the debug level");
        debug ("Current debug level is %u", falgnfq_debug);
    }

    struct sigaction sa_int;
    sa_int.sa_handler = falgnfq_exit_setter;
    sa_int.sa_flags = 0;
    sigemptyset (&sa_int.sa_mask);
    sigaction (SIGINT, &sa_int, NULL);
#endif

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
