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
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "arch_def_macro.h"

#define PATH_ENABLED    "/sys/kernel/bperf/enabled"
#define PATH_NUM_PMC    "/sys/kernel/bperf/num_pmc"
#define PATH_NUM_FIXED  "/sys/kernel/bperf/num_fixed"
#define PATH_NUM_CORES  "/sys/kernel/bperf/num_cores"
#define PATH_CPU_FAMILY "/sys/kernel/bperf/cpu_family"
#define PATH_CPU_MODEL  "/sys/kernel/bperf/cpu_model"
#define PATH_PMC_FMT    "/sys/kernel/bperf/pmc%u"
#define PATH_DATA       "/dev/bperf"

#define PMC(x, y, ev, um)                   { #x "." #y }
#define PMC_CMASK(x, y, ev, um, cm)         PMC(x, y, ev, um)
#define PMC_EDG(x, y, ev, um)               PMC(x, y, ev, um)
#define PMC_CMASK_INV(x, y, ev, um, cm)     PMC(x, y, ev, um)
#define PMC_CMASK_EDG(x, y, ev, um, cm)     PMC(x, y, ev, um)
#define PMC_CMASK_INV_EDG(x, y, ev, um, cm) PMC(x, y, ev, um)

struct bperf_event_tuple {
    const char *name;
};

#include "arch_events.c"

#undef PMC
#undef PMC_CMASK
#undef PMC_EDG
#undef PMC_CMASK_INV
#undef PMC_CMASK_EDG
#undef PMC_CMASK_INV_EDG

static size_t max(size_t a, size_t b) {
    return a > b ? a : b;
}

static bool is_known_event(unsigned family, unsigned model, const char *event) {
    size_t evi, archi, n_archs = sizeof(EVENTS) / sizeof(EVENTS[0]);
    for (archi = 0; archi < n_archs; archi++) {
        if (EVENTS[archi].family != family || EVENTS[archi].model != model) {
            continue;
        }
        for (evi = 0; EVENTS[archi].events[evi].name; evi++) {
            if (!strcmp(EVENTS[archi].events[evi].name, event)) {
                return true;
            }
        }
    }
    return false;
}

static void write_number(const char *path, unsigned num, const char *errmsg) {
    FILE *f;
    if (!(f = fopen(path, "w"))) {
        fprintf(stderr, "Error: failed to open path \"%s\": %s\n", path, strerror(errno));
        exit(1);
    }
    fprintf(f, "%u", num);
    fclose(f);
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

static unsigned get_cpu_family() {
    return read_number(PATH_CPU_FAMILY, "failed to read cpu family");
}

static unsigned get_cpu_model() {
    return read_number(PATH_CPU_MODEL, "failed to read cpu model");
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

static void list_events(unsigned family, unsigned model) {
    size_t evi, archi, n_archs = sizeof(EVENTS) / sizeof(EVENTS[0]);
    for (archi = 0; archi < n_archs; archi++) {
        if (EVENTS[archi].family != family || EVENTS[archi].model != model) {
            continue;
        }
        printf("Events:\n");
        for (evi = 0; EVENTS[archi].events[evi].name; evi++) {
            printf("    %s\n", EVENTS[archi].events[evi].name);
        }
        return;
    }
    fprintf(stderr, "Error: unsupported architecture: DisplayFamily_Display_Model = %02x_%02x\n", family, model);
}

static bool is_arch_supported(unsigned family, unsigned model) {
    size_t archi, n_archs = sizeof(EVENTS) / sizeof(EVENTS[0]);
    for (archi = 0; archi < n_archs; archi++) {
        if (EVENTS[archi].family == family && EVENTS[archi].model == model) {
            return true;
        }
    }
    return false;
}

static const char *output_path = "bperf_output.csv";
static bool should_stop        = false;
static int sample_interval     = 20;
static unsigned num_pmc        = 0;
static unsigned num_fixed      = 0;
static unsigned num_cores      = 0;
static unsigned cpu_family     = 0;
static unsigned cpu_model      = 0;

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
            list_events(cpu_family, cpu_model);
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
        if (!is_known_event(cpu_family, cpu_model, argv[optind])) {
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

static size_t write_buffer(char **buf, size_t *sz, size_t off, const char *fmt, ...) {
    char *tmp;
    size_t ret, newsz;
    va_list args;
    va_start(args, fmt);
    if ((ret = vsnprintf(*buf + off, *sz - off, fmt, args)) >= *sz - off) {
        va_end(args);
        newsz = off + ret + 1;
        if (!(tmp = realloc(*buf, newsz))) {
            perror("Error: realloc()");
            exit(1);
        }
        *buf = tmp;
        *sz = newsz;
        va_start(args, fmt);
        ret = vsnprintf(*buf + off, *sz - off, fmt, args);
    }
    va_end(args);
    return ret;
}

static void write_first_line(FILE *event_fp, FILE *out_fp, char **line, size_t *line_size, double *ts_base, double *ts_ms) {
    char *tmp;
    unsigned i;

#define READ_LINE() do { \
    if (getline(line, line_size, event_fp) < 0 || !*line) { \
        perror("Error: failed to read events"); \
        fclose(event_fp); \
        fclose(out_fp); \
        exit(1); \
    } \
} while(0)

    // First line
    if (!should_stop) {
        // Read timestamp line
        READ_LINE();
        *ts_base = strtod(*line, &tmp) / 1000000.0; // ns -> ms
        *ts_ms = 0.0;
        if (tmp == *line || *tmp != '\n') {
            fprintf(stderr, "Error: failed to read timestamp\n");
            fclose(event_fp);
            fclose(out_fp);
            exit(1);
        }
        fprintf(out_fp, "time (ms)");

        // Read event lines, and ignore data
        while (!should_stop) {
            READ_LINE();
            if ((*line)[0] == '=') {
                break;
            }

            tmp = strtok(*line, " "); // Event name
            for (i = 0; i < num_cores; i++) {
                fprintf(out_fp, ",%s-%u", tmp, i);
            }
        }

        fputc('\n', out_fp);
    }

#undef READ_LINE

}

int main(int argc, char *const *argv) {
    disable();
    num_pmc = get_num_pmc();
    num_fixed = get_num_fixed();
    num_cores = get_num_cores();
    cpu_family = get_cpu_family();
    cpu_model = get_cpu_model();

    if (!is_arch_supported(cpu_family, cpu_model)) {
        fprintf(stderr, "Error: unsupported architecture: DisplayFamily_Display_Model = %02x_%02x\n", cpu_family, cpu_model);
        exit(1);
    }

    parse_args(argc, argv);
    printf("Profiling with interval %d ms and writing output to %s ...\n", sample_interval, output_path);
    signal(SIGINT, sig_handler);

    char *line = NULL, *tmp, *out_line = NULL;
    size_t line_size = 0, out_line_size = 0, offset;
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

    double ts_ms, ts_base, ts_last, data;

    enable();
    atexit(disable);

    write_first_line(event_fp, out_fp, &line, &line_size, &ts_base, &ts_ms);
    ts_ms = ts_base;

#define READ_LINE() do { \
    if (getline(&line, &line_size, event_fp) < 0 || !line) { \
        perror("Error: failed to read events"); \
        fclose(event_fp); \
        fclose(out_fp); \
        exit(1); \
    } \
} while(0)

    // All other lines
    while (!should_stop) {
        offset = 0;

        // Read timestamp line
        READ_LINE();
        ts_last = ts_ms;
        ts_ms = round(strtod(line, &tmp) / 1000000.0 - ts_base); // ns -> ms
        if (tmp == line || *tmp != '\n') {
            fprintf(stderr, "Error: failed to read timestamp\n");
            fclose(event_fp);
            fclose(out_fp);
            exit(1);
        }
        offset += write_buffer(&out_line, &out_line_size, offset, "%0.lf", ts_ms);

        // Read event lines
        while (!should_stop) {
            READ_LINE();
            if (line[0] == '=') {
                break;
            }

            tmp = strtok(line, " "); // Event name
            while ((tmp = strtok(NULL, " "))) {
                if (*tmp == '\n') {
                    continue;
                }
                data = (strtod(tmp, NULL) * sample_interval) / (ts_ms - ts_last);
                offset += write_buffer(&out_line, &out_line_size, offset, ",%0.3lf", data);
            }
        }

        if (!should_stop) {
            fprintf(out_fp, "%s\n", out_line);
        }
    }

#undef READ_LINE

    free(line);
    free(out_line);

    fclose(event_fp);
    fclose(out_fp);

    return 0;
}
