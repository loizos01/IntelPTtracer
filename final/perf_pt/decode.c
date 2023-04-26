#define _GNU_SOURCE

#include <stdio.h>
#include <intel-pt.h>
#include <pt_cpu.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <link.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#include "ptxed_util.c"
#include "analyse_exec_flow.c"
#include "pt_cpu.c"
#include "pt_cpuid.c"
#include "load_elf.c"

// Storage for executed instructions
struct pt_insn execInst[1000000];

// Private prototypes
static int extract_base(const char *, uint64_t *);

// Public prototypes.
void *init_inst_decoder(void *buf, uint64_t len,
                        int *decoder_status,
                        const char *current_exe, struct stats_config *stats);
bool decode_trace(struct pt_insn_decoder *decoder, int *decoder_status, struct stats_config *stats);
void free_insn_decoder(struct pt_insn_decoder *);

static int extract_base(const char *arg, uint64_t *base)
{
    char *sep, *rest;

    sep = strrchr(arg, ':');
    if (sep)
    {
        uint64_t num;

        if (!sep[1])
            return 0;

        errno = 0;
        num = strtoull(sep + 1, &rest, 0);
        if (errno || *rest)
            return 0;

        *base = num;
        *sep = 0;
        return 1;
    }

    return 0;
}

/*
 * Get ready to retrieve instructions from a PT trace using the code of the
 * current process for control flow recovery.
 *
 * Accepts a raw buffer `buf` of length `len`.
 *
 * `current_exe` is an absolute path to an on-disk executable from which to
 * load the main executable's (i.e. not a shared library's) code.
 *
 * `*decoder_status` will be updated to reflect the status of the decoder after
 * it has been synchronised.
 *
 * Returns a pointer to a configured libipt block decoder or NULL on error.
 */
void *
init_inst_decoder(void *buf, uint64_t len,
                  int *decoder_status, const char *current_exe, struct stats_config *stats)
{
    bool failing = false;
    if (stats->praw)
        bufferFd = fopen("buffer.out", "w+");

    struct pt_config config;
    memset(&config, 0, sizeof(config));

    // pt_config_init(&config);

    config.size = sizeof(config);
    config.begin = buf;
    config.end = buf + len;

    // Decode for the current CPU.
    struct pt_insn_decoder *decoder = NULL;
    int rv = pt_cpu_read(&config.cpu);
    if (rv != pte_ok)
    {
        printf("Error: reading cpu");
        failing = true;
        goto clean;
    }

    // Work around CPU bugs.
    if (config.cpu.vendor)
    {
        rv = pt_cpu_errata(&config.errata, &config.cpu);
        if (rv < 0)
        {
            printf("Error: working around bugs");
            failing = true;
            goto clean;
        }
    }

    // Instantiate a decoder.
    decoder = pt_insn_alloc_decoder(&config);
    if (decoder == NULL)
    {
        printf("Error: instantiating decoder");
        failing = true;
        goto clean;
    }

    // Sync the decoder.
    *decoder_status = pt_insn_sync_forward(decoder);
    if (*decoder_status == -pte_eos)
    {
        // There were no blocks in the stream. The user will find out on next
        // call to hwt_ipt_next_block().
        goto clean;
    }
    else if (*decoder_status < 0)
    {
        printf("Error: synchronising decoder");
        failing = true;
        goto clean;
    }

    // Build and load a memory image from which to recover control flow.
    struct pt_image *image = pt_image_alloc(NULL);
    if (image == NULL)
    {
        printf("Error: allocating image");
        failing = true;
        goto clean;
    }
    // Use image cache to speed up decoding.
    struct pt_image_section_cache *iscache = pt_iscache_alloc(NULL);

    if (iscache == NULL)
    {
        printf("Error: allocating cache");
        failing = true;
        goto clean;
    }

    int64_t base;
    base = 0ull;

    int errcode = extract_base(current_exe, &base);
    if (errcode < 0)
    {
        printf("Error: Extracting base");
        failing = true;
        goto clean;
    }

    errcode = load_elf(iscache, image, current_exe, base, "ptxed_util");

    rv = pt_insn_set_image(decoder, image);
    if (rv < 0)
    {
        printf("Error: setting image to decoder");
        failing = true;
        goto clean;
    }

clean:
    if (failing)
    {
        pt_insn_free_decoder(decoder);
        return NULL;
    }
    return decoder;
}

/*
 *
 * Decodes intel PT
 *
 */
bool decode_trace(struct pt_insn_decoder *decoder, int *decoder_status, struct stats_config *stats)
{
    xed_state_t xed;
    if (stats->pinst)
    {
        xed_state_zero(&xed);
        xed_tables_init();
    }

    uint64_t offset, sync;

    offset = 0ull;
    int errcode;

    int status = *decoder_status;
    struct pt_insn insn;

    // Used to keep track of the number of instructions
    int counter = 0;

    /* Initialize the IP - we use it for error reporting. */
    insn.ip = 0ull;

    for (;;)
    {
        status = drain_events_insn(decoder, status);
        if (status < 0)
        {
            printf("Drain Events error ");
            break;
        }

        if (status & pts_eos)
        {
            // printf("[End of trace]\n");
            break;
        }

        errcode = pt_insn_get_offset(decoder, &offset);
        if (errcode < 0)
        {
            printf("Get offset error");
            break;
        }

        status = pt_insn_next(decoder, &insn, sizeof(insn));
        if (status < 0)
        {
            /* Even in case of errors, we may have succeeded
             * in decoding the current instruction.
             */
            print_insn(&insn, &xed, offset);
            printf("Error fetching instruction\n");
        }

        execInst[counter] = insn;
        counter++;

        if (stats->pinst)
            print_insn(&insn, &xed, offset);

        if (stats->praw)
            print_raw_insn_file(&insn);

    }

    /* We shouldn't break out of the loop without an error. */
    if (!status)
        status = -pte_internal;

    /* We're done when we reach the end of the trace stream. */
    if (status == -pte_eos)
    {
        printf("Error with end of trace stream\n");
        return false;
    }

    /* Checks whether we have enough allocated
     *  memory to store the captured instructions.
     */
    if (counter > 1000000)
    {
        printf("Counter too large");
        return 0;
    }

    if (!exec_flow_analysis(execInst, counter))
    {
        printf("Rop chain detected\n");
        return false;
    }
    else
    {
        if (stats->psyscall)
        {
            printf("Syscall safe\n");
        }
    }
    return true;
}

/*
 * Free an instruction decoder and its image.
 */
void free_insn_decoder(struct pt_insn_decoder *decoder)
{
    if (decoder != NULL)
    {
        pt_insn_free_decoder(decoder);
    }
}
