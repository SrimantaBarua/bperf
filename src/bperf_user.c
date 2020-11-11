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

#define PATH_ENABLED   "/sys/kernel/bperf/enabled"
#define PATH_NUM_PMC   "/sys/kernel/bperf/num_pmc"
#define PATH_NUM_FIXED "/sys/kernel/bperf/num_fixed"
#define PATH_NUM_CORES "/sys/kernel/bperf/num_cores"
#define PATH_PMC_FMT   "/sys/kernel/bperf/pmc%u"
#define PATH_DATA      "/dev/bperf"

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

static unsigned read_number(const char *path, const char *errmsg) {
    unsigned ret;
    FILE *f;
    if (!(f = fopen(path, "r"))) {
        fprintf(stderr, "Error: failed to open path \"%s\": %s\n", path, strerror(errno));
        exit(1);
    }
    if (fscanf(f, "%u", &ret) != 1) {
        fprintf(stderr, "Error: %s: %s\n", errmsg, strerror(errno));
        fclose(f);
        exit(1);
    }
    fclose(f);
    return ret;
}

static unsigned get_num_pmc() {
    return read_number(PATH_NUM_PMC, "failed to read number of PMCs");
}

static unsigned get_num_fixed() {
    return read_number(PATH_NUM_FIXED, "failed to read number of fixed counters");
}

static unsigned get_num_cores() {
    return read_number(PATH_NUM_CORES, "failed to read number of cores");
}

static void write_str(const char *path, const char *str, size_t len, const char *errmsg) {
    int fd, ret;
    if ((fd = open(path, O_WRONLY)) <= 0) {
        fprintf(stderr, "Error: failed to open path \"%s\": %s\n", path, strerror(errno));
        exit(1);
    }
    if (write(fd, str, len) < 0) {
        fprintf(stderr, "Error: %s: %s\n", errmsg, strerror(errno));
        close(fd);
    }
    close(fd);
}

static void enable() {
    write_str(PATH_ENABLED, "enable", strlen("enable"), "failed to enable perf counting");
}

static void disable() {
    write_str(PATH_ENABLED, "disable", strlen("disable"), "failed to disable perf counting");
}

static void set_pmc_event(unsigned pmc_id, const char *event) {
    char path_buffer[128], errmsg_buffer[256];
    snprintf(path_buffer, sizeof(path_buffer), PATH_PMC_FMT, pmc_id);
    snprintf(errmsg_buffer, sizeof(errmsg_buffer), "failed to enable event \"%s\"", event);
    write_str(path_buffer, event, strlen(event), errmsg_buffer);
}

static void print_usage(char *const progname) {
    printf("Usage: %s [OPTION] [EVENT]\n"
           "Start profiling the specified events. Use Ctrl-C (SIGINT) to stop profiling.\n\n"
           "Options:\n"
           "    -h, --help               - show this help\n"
           "    -l, --list               - list available events\n"
           "    -o, --output OUTPUT      - set output file path. bperf_output.csv by default\n"
           "    -i, --interval INTERVAL  - set sampling interval (in ms). 20ms by default\n",
           progname);
}

static void list_events() {
    printf("Events:\n");
    for (size_t i = 0; events[i]; i++) {
        printf("    %s\n", events[i]);
    }
}

static const char *output_path = "bperf_output.csv";
static long sample_interval    = 20;
static bool should_stop        = false;
static unsigned num_pmc        = 0;
static unsigned num_fixed      = 0;
static unsigned num_cores      = 0;

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
                printf("Error: invalid interval: %s\n", optarg);
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
            printf("Error: unknown event: \"%s\"\n", argv[optind]);
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
    num_fixed = get_num_fixed();
    num_cores = get_num_cores();

    parse_args(argc, argv);
    printf("Profiling with interval %ld ms and writing output to %s ...\n",
            sample_interval, output_path);
    signal(SIGINT, sig_handler);

    char *line = NULL, *tmp;
    size_t line_size = 0;
    FILE *event_fp = fopen(PATH_DATA, "r");
    if (!event_fp) {
        perror("Error: failed to open \"" PATH_DATA "\" to read events");
        exit(1);
    }

    FILE *out_fp = fopen(output_path, "w");
    if (!out_fp) {
        fprintf(stderr, "Error: failed to open \"%s\" to write data: %s\n", output_path, strerror(errno));
        exit(1);
    }

    double ts_ms;

    enable();
    atexit(disable);

#define READ_LINE() do { \
    if (getline(&line, &line_size, event_fp) < 0 || !line) { \
        perror("Error: failed to read events"); \
        fclose(event_fp); \
        fclose(out_fp); \
        exit(1); \
    } \
} while(0)

    while (!should_stop) {
        // Read timestamp line
        READ_LINE();
        ts_ms = strtod(line, &tmp) / 1000000.0; // ns -> ms
        if (tmp == line || *tmp != '\n') {
            fprintf(stderr, "Error: failed to read timestamp\n");
            fclose(event_fp);
            fclose(out_fp);
            exit(1);
        }
        fprintf(out_fp, "%f", ts_ms);

        // Read event lines
        while (!should_stop) {
            READ_LINE();
            if (line[0] == '=') {
                break;
            }

            tmp = strtok(line, " "); // Event name
            while ((tmp = strtok(NULL, " "))) {
                fprintf(out_fp, ",%s", tmp);
            }

            fputc('\n', out_fp);
        }
    }

#undef READ_LINE

    fclose(event_fp);
    fclose(out_fp);

    return 0;
}
