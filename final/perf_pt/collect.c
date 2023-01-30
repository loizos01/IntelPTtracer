#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include <time.h>
#include <intel-pt.h>
#include <linux/perf_event.h>

#define SYSFS_PT_TYPE "/sys/bus/event_source/devices/intel_pt/type"
#define MAX_PT_TYPE_STR 8

#define MAX_OPEN_PERF_TRIES 50000
#define OPEN_PERF_WAIT_NSECS 10000000 // 1/100 of a second.

#define AUX_BUF_WAKE_RATIO 0.5

#ifndef INFTIM
#define INFTIM -1
#endif

/*
 * Stores all information about the collector.
 */
struct perf_ctx
{
    int perf_fd;         // FD used to talk to the perf API.
    void *aux_buf;       // Ptr to the start of the the AUX buffer.
    size_t aux_bufsize;  // The size of the AUX buffer's mmap(2).
    void *base_buf;      // Ptr to the start of the base buffer.
    size_t base_bufsize; // The size the base buffer's mmap(2).
};

struct stats_config
{
    bool pinfo;
    bool pinst;
    bool pbuff;
    bool praw;
    bool psyscall;
} stats;

struct perf_collector_config
{
    size_t data_bufsize;          // Data buf size (in pages).
    size_t aux_bufsize;           // AUX buf size (in pages).
    size_t initial_trace_bufsize; // Initial capacity (in bytes) of a
                                  // trace storage buffer.
};

// Private prototypes.
static int open_perf(size_t, pid_t traceepid, struct stats_config *);

// Exposed Prototypes.
struct perf_ctx *perf_init_collector(struct perf_collector_config *, pid_t traceepid, struct stats_config *);
bool perf_free_collector(struct perf_ctx *tr_ctx);

/*
 * Opens the perf file descriptor and returns it.
 *
 * Returns a file descriptor, or -1 on error.
 */
static int
open_perf(size_t aux_bufsize, pid_t traceepid, struct stats_config *stats)
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    // attr.size = sizeof(struct perf_event_attr);

    int ret = -1;

    // Get the perf "type" for Intel PT.
    FILE *pt_type_file = fopen(SYSFS_PT_TYPE, "r");
    if (pt_type_file == NULL)
    {
        printf("Error: openning perf 'type' file descriptor");
        ret = -1;
        goto clean;
    }
    char pt_type_str[MAX_PT_TYPE_STR];
    if (fgets(pt_type_str, sizeof(pt_type_str), pt_type_file) == NULL)
    {
        printf("Error: reading perf 'type'");
        ret = -1;
        goto clean;
    }
    attr.type = atoi(pt_type_str);
    if (stats->pinfo)
        printf("Intel PT type: %d\n", attr.type);

    attr.config = 0x300e601;

    // Exclude the kernel.
    attr.exclude_kernel = 1;

    // Exclude the hyper-visor.
    attr.exclude_hv = 1;

    // Start disabled.
    attr.disabled = 1;

    // No skid.
    attr.precise_ip = 3;

    // Notify for every sample.
    attr.watermark = 1;
    attr.wakeup_watermark = 1;

    // Generate a PERF_RECORD_AUX sample when the AUX buffer is almost full.
    attr.aux_watermark = (size_t)((double)aux_bufsize * getpagesize()) * AUX_BUF_WAKE_RATIO;

    // Acquire file descriptor through which to talk to Intel PT. This syscall
    // could return EBUSY, meaning another process or thread has locked the
    // Perf device.
    struct timespec wait_time = {0, OPEN_PERF_WAIT_NSECS};

    // pid_t target_tid = syscall(__NR_gettid);
    for (int tries = MAX_OPEN_PERF_TRIES; tries > 0; tries--)
    {
        ret = syscall(SYS_perf_event_open, &attr, traceepid, -1, -1, 0);
        if ((ret == -1) && (errno == EBUSY))
        {
            nanosleep(&wait_time, NULL); // Doesn't matter if this is interrupted.
        }
        else
        {
            break;
        }
    }

    if (ret == -1)
    {
        printf("Error openning perf_event");
    }

clean:
    if ((pt_type_file != NULL) && (fclose(pt_type_file) == -1))
    {
        ret = -1;
    }

    return ret;
}

/*
 * --------------------------------------
 * Functions exposed to the outside world
 * --------------------------------------
 */

/*
 * Initialise a collector context.
 */
struct perf_ctx *
perf_init_collector(struct perf_collector_config *tr_conf, pid_t traceepid, struct stats_config *stats)
{
    struct perf_ctx *tr_ctx = NULL;
    bool failing = false;

    // Allocate and initialise collector context.
    tr_ctx = malloc(sizeof(*tr_ctx));
    if (tr_ctx == NULL)
    {
        printf("Error: allocating collector");
        failing = true;
        goto clean;
    }

    // Set default values.
    memset(tr_ctx, 0, sizeof(*tr_ctx));
    tr_ctx->perf_fd = -1;

    // Obtain a file descriptor through which to speak to perf.
    tr_ctx->perf_fd = open_perf(tr_conf->aux_bufsize, traceepid, stats);
    if (tr_ctx->perf_fd == -1)
    {
        printf("Error: obtaining a perf_event file descriptor");
        failing = true;
        goto clean;
    }

    // Allocate mmap(2) buffers for speaking to perf.
    //
    // We mmap(2) two separate regions from the perf file descriptor into our
    // address space:
    //
    // 1) The base buffer (tr_ctx->base_buf), which looks like this:
    //
    // -----------------------------------
    // | header  |       data buffer     |
    // -----------------------------------
    //           ^ header->data_offset
    //
    // 2) The AUX buffer (tr_ctx->aux_buf), which is a simple array of bytes.
    //
    // The AUX buffer is where the kernel exposes control flow packets, whereas
    // the data buffer is used for all other kinds of packet.

    // Allocate the base buffer.
    //
    // Data buffer is preceded by one management page (the header), hence `1 +
    // data_bufsize'.
    int page_size = getpagesize();
    // printf("\n%d\n",page_size);
    tr_ctx->base_bufsize = (1 + tr_conf->data_bufsize) * page_size;
    tr_ctx->base_buf = mmap(NULL, tr_ctx->base_bufsize, PROT_WRITE, MAP_SHARED, tr_ctx->perf_fd, 0);

    if (tr_ctx->base_buf == MAP_FAILED)
    {
        printf("Error: mapping base buffer");
        failing = true;
        goto clean;
    }

    // Populate the header part of the base buffer.
    struct perf_event_mmap_page *base_header = tr_ctx->base_buf;
    base_header->aux_offset = base_header->data_offset + base_header->data_size;
    base_header->aux_size = tr_ctx->aux_bufsize =
        tr_conf->aux_bufsize * page_size;

    // Allocate the AUX buffer.
    //
    // Mapped R/W so as to have a saturating ring buffer.
    tr_ctx->aux_buf = mmap(NULL, base_header->aux_size, PROT_READ | PROT_WRITE,
                           MAP_SHARED, tr_ctx->perf_fd, base_header->aux_offset);
    if (tr_ctx->aux_buf == MAP_FAILED)
    {
        printf("Error: mapping aux buffer");
        failing = true;
        goto clean;
    }

clean:
    if (failing && (tr_ctx != NULL))
    {
        perf_free_collector(tr_ctx);
        return NULL;
    }
    return tr_ctx;
}

/*
 * Clean up and free a perf_ctx and its contents.
 *
 * Returns true on success or false otherwise.
 */
bool perf_free_collector(struct perf_ctx *tr_ctx)
{
    int ret = true;

    if ((tr_ctx->aux_buf) &&
        (munmap(tr_ctx->aux_buf, tr_ctx->aux_bufsize) == -1))
    {
        printf("Error: unmapping aux buffer");
        ret = false;
    }
    if ((tr_ctx->base_buf) &&
        (munmap(tr_ctx->base_buf, tr_ctx->base_bufsize) == -1))
    {
        printf("Error: unmapping base buffer");
        ret = false;
    }
    if (tr_ctx->perf_fd >= 0)
    {
        close(tr_ctx->perf_fd);
        tr_ctx->perf_fd = -1;
    }
    if (tr_ctx != NULL)
    {
        free(tr_ctx);
    }
    return ret;
}
