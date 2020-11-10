/**
 * @file    bperf_user.c
 * @author  Srimanta Barua <srimanta.barua1@gmail.com>
 * @date    05 November 2020
 * @version 0.1
 * @brief   Userspace application to read data exported by kernel
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch_def_macro.h"

#define PATH_ENABLED "/sys/kernel/bperf/enabled"
#define PATH_NUM_PMC "/sys/kernel/bperf/num_pmc"
#define PATH_PMC_FMT "/sys/kernel/bperf/pmc%u"
#define PATH_DATA    "/dev/bperf"
#define QUOTE(x)     "\"" x "\""

static const char *events[] = {
#define __BPERF_PER_EVENT(x, y) #x "." #y,
    __BPERF_DO_FOR_EACH_EVENT
#undef __BPERF_PER_EVENT
    NULL,
};

static bool is_known_event(const char *event) {
    for (size_t i = 0; events[i]; i++) {
        if (!strcmp(event, events[i])) {
            return true;
        }
    }
    return false;
}

static unsigned get_num_pmc() {
    unsigned ret;
    FILE *f;
    if (!(f = fopen(PATH_NUM_PMC, "r"))) {
        perror("Error: failed to open path " QUOTE(PATH_NUM_PMC));
        exit(1);
    }
    if (fscanf(f, "%u", &ret) != 1) {
        perror("Error: failed to read number of PMCs from " QUOTE(PATH_NUM_PMC));
        fclose(f);
        exit(1);
    }
    fclose(f);
    return ret;
}

static void enable() {
    int fd, ret;
    if ((fd = open(PATH_ENABLED, O_WRONLY)) <= 0) {
        perror("Error: failed to open path " QUOTE(PATH_ENABLED));
        exit(1);
    }
    if (write(fd, "enable", 6) < 0) {
        perror("Error: failed to enable perf counting");
        close(fd);
    }
    close(fd);
}

static void disable() {
    int fd, ret;
    if ((fd = open(PATH_ENABLED, O_WRONLY)) <= 0) {
        perror("Error: failed to open path " QUOTE(PATH_ENABLED));
        exit(1);
    }
    if (write(fd, "disable", 7) < 0) {
        perror("Error: failed to disable perf counting");
        close(fd);
    }
    close(fd);
}

static void set_pmc_event(unsigned pmc_id, const char *event) {
    char buffer[128];
    snprintf(buffer, sizeof(buffer), PATH_PMC_FMT, pmc_id);

    int fd, ret;
    if ((fd = open(buffer, O_WRONLY)) <= 0) {
        fprintf(stderr, "Error: failed to open pmc event file \"%s\": %s\n", buffer, strerror(errno));
        exit(1);
    }
    if (write(fd, event, strlen(event)) < 0) {
        fprintf(stderr, "Error: failed to enable event \"%s\": %s\n", event, strerror(errno));
        close(fd);
    }
    close(fd);
}

static void print_usage(char *const progname) {
    fprintf(stderr,
            "Usage: %s [OPTION] [EVENT]\n"
            "Start profiling the specified events. Use Ctrl-C (SIGINT) to stop profiling.\n\n"
            "Options:\n"
            "    -h, --help               - show this help\n"
            "    -l, --list               - list available events\n"
            "    -o, --output OUTPUT      - set output file path. bperf_output.csv by default\n"
            "    -i, --interval INTERVAL  - set sampling interval (in ms). 20ms by default\n",
            progname);
}

static void list_events() {
    fprintf(stderr, "Events:\n");
    for (size_t i = 0; events[i]; i++) {
        fprintf(stderr, "    %s\n", events[i]);
    }
}

static const char *output_path = "bperf_output.csv";
static long sample_interval = 20;
static bool should_stop = false;
static unsigned num_pmc = 0;

static void parse_args(int argc, char *const *argv) {
    char *const progname = argv[0];
    char *tmp;
    int c, index = 0;
    unsigned pmc_id = 0;
    static struct option long_opts[] = {
        { "help",     no_argument,       NULL, 'h' },
        { "list",     no_argument,       NULL, 'l' },
        { "output",   required_argument, NULL, 'o' },
        { "interval", required_argument, NULL, 'i' },
        { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "hlo:i:", long_opts, &index)) >= 0) {
        switch (c) {
        case 'l':
            list_events();
            exit(0);
        case 'o':
            output_path = optarg;
            break;
        case 'i':
            sample_interval = strtol(optarg, &tmp, 10);
            if (sample_interval <= 0 || tmp == optarg || *tmp != '\0') {
                fprintf(stderr, "Error: invalid interval: %s\n", optarg);
                exit(1);
            }
            break;
        case 'h':
            print_usage(progname);
            exit(0);
        default:
            print_usage(progname);
            exit(1);
        }
    }

    while (optind < argc && pmc_id < num_pmc) {
        if (!is_known_event(argv[optind])) {
            fprintf(stderr, "Error: unknown event: \"%s\"\n", argv[optind]);
            exit(1);
        }
        set_pmc_event(pmc_id, argv[optind]);
        optind++;
        pmc_id++;
    }
}

static void sig_handler(int sig) {
    if (sig == SIGINT) {
        should_stop = true;
    }
}

int main(int argc, char *const *argv) {
    disable();
    num_pmc = get_num_pmc();

    parse_args(argc, argv);
    fprintf(stderr, "Profiling with interval %ld ms and writing output to %s ...\n",
            sample_interval, output_path);
    signal(SIGINT, sig_handler);

    enable();

    while (!should_stop) {
        // Read event data
    }

    disable();

    return 0;
}
