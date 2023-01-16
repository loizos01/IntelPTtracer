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
#include <hwtracer_util.h>
#include "ptxed_util_insn.c"

#include "pt_cpu.c"
#include "pt_cpuid.c"
#include "hwtracer_private.h"

#define VDSO_NAME "linux-vdso.so.1"


typedef struct load_self_image_args {
    struct pt_image *image;
    int vdso_fd;
    char *vdso_filename;
    struct hwt_cerror *err;
    const char *current_exe;
    struct  pt_image_section_cache *iscache;
}load_self_image_args;

load_self_image_args load_args;

// Private prototypes.

static bool load_self_image(struct load_self_image_args *);
static int load_self_image_cb(struct dl_phdr_info *, size_t, void *);


// Public prototypes.
void * hwt_ipt_init_inst_decoder(void *buf, uint64_t len, int vdso_fd, char *vdso_filename,
                           int *decoder_status, struct hwt_cerror *err,
                           const char *current_exe);
bool hwt_ipt_print_inst(struct pt_insn_decoder *decoder, int *decoder_status, struct hwt_cerror *err,struct ptxed_stats *stats,struct  pt_image_section_cache *iscache);
void hwt_ipt_free_block_decoder(struct pt_block_decoder *);

/*
 * Dump the VDSO code into the open file descriptor `fd`, starting at `vaddr`
 * and of size `len` into a temp file.
 *
 * Returns true on success or false otherwise.
 */
bool 
hwt_ipt_dump_vdso(int fd, uint64_t vaddr, size_t len, struct hwt_cerror *err)
{
    size_t written = 0;
    while (written != len) {
        int wrote = write(fd, (void *) vaddr + written, len - written);
        if (wrote == -1) {
            hwt_set_cerr(err, hwt_cerror_errno, errno);
            return false;
        }
        written += wrote;
    }

    return true;
}

/*
 * Get ready to retrieve the basic blocks from a PT trace using the code of the
 * current process for control flow recovery.
 *
 * Accepts a raw buffer `buf` of length `len`.
 *
 * `vdso_fd` is an open file descriptor for the filename `vdso_filename`. This
 * is where the VDSO code will be written. libipt will read this file lazily,
 * so it's up to the caller to make sure this file lives long enough for their
 * purposes.
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
hwt_ipt_init_inst_decoder(void *buf, uint64_t len, int vdso_fd, char *vdso_filename,
                           int *decoder_status, struct hwt_cerror *err,
                           const char *current_exe) {
    bool failing = false;
    bufferFd = fopen("buffer.out", "w+");  
    // Make a block decoder configuration.
    struct pt_config config;
    memset(&config, 0, sizeof(config));
    //pt_config_init(&config);
    config.size = sizeof(config);
    config.begin = buf;
    config.end = buf + len;

    // Decode for the current CPU.
    struct pt_insn_decoder *decoder = NULL;
    int rv = pt_cpu_read(&config.cpu);
    if (rv != pte_ok) {
        hwt_set_cerr(err, hwt_cerror_ipt, -rv);
        failing = true;
        goto clean;
    }

    // Work around CPU bugs.
    if (config.cpu.vendor) {
        rv = pt_cpu_errata(&config.errata, &config.cpu);
        if (rv < 0) {
            hwt_set_cerr(err, hwt_cerror_ipt, -rv);
            failing = true;
            goto clean;
        }
    }

    // Instantiate a decoder.
    decoder = pt_insn_alloc_decoder(&config);
    if (decoder == NULL) {
        hwt_set_cerr(err, hwt_cerror_unknown, 0);
        failing = true;
        goto clean;
    }
    

    // Sync the decoder.
    *decoder_status = pt_insn_sync_forward(decoder);
    if (*decoder_status == -pte_eos) {
        // There were no blocks in the stream. The user will find out on next
        // call to hwt_ipt_next_block().
        goto clean;
    } else if (*decoder_status < 0) {
        hwt_set_cerr(err, hwt_cerror_ipt, -*decoder_status);
        failing = true;
        goto clean;
    }

    // Build and load a memory image from which to recover control flow.
    struct pt_image *image = pt_image_alloc(NULL);
    if (image == NULL) {
        hwt_set_cerr(err, hwt_cerror_unknown, 0);
        failing = true;
        goto clean;
    }

    // Use image cache to speed up decoding.
    struct pt_image_section_cache *iscache = pt_iscache_alloc(NULL);


    if(iscache == NULL) {
        hwt_set_cerr(err, hwt_cerror_unknown, 0);
        failing = true;
        goto clean;
    }

    load_args = (load_self_image_args){image, vdso_fd, vdso_filename,err, current_exe, iscache};

    if (!load_self_image(&load_args)) {
        failing = true;
        goto clean;
    }

    rv = pt_insn_set_image(decoder, image);
    if (rv < 0) {
        hwt_set_cerr(err, hwt_cerror_ipt, -rv);
        failing = true;
        goto clean;
    }

clean:
    if (failing) {
        pt_insn_free_decoder(decoder);
        return NULL;
    }
    return decoder;
}

/*
 * Updates `*first_instr` and `*last_instr` with the address of the first and last
 * instructions of the next block in the instruction stream.
 *
 * If first instruction address is 0, this indicates that the end of
 * the instruction stream has been reached.
 *
 * `*decoder_status` will be updated with the new decoder status after the operation.
 *
 * Returns true on success or false otherwise. Upon failure, `*first_instr` and
 * `*last_instr` are undefined.
 */
bool
hwt_ipt_print_inst(struct pt_insn_decoder *decoder, int *decoder_status, struct hwt_cerror *err,struct ptxed_stats *stats,struct  pt_image_section_cache *iscache) {
    xed_state_t xed;
    uint64_t offset, sync;
    xed_state_zero(&xed);
    offset = 0ull;
    sync = 0ull;
    int errcode;
    int status = *decoder_status;
    struct pt_insn insn;
	/* Initialize the IP - we use it for error reporting. */
	insn.ip = 0ull;

		for (;;) {
			status = drain_events_insn(decoder, status);
			if (status < 0)
                break;				

			if (status & pts_eos) {
					printf("[end of trace]\n");

				status = -pte_eos;
				break;
			}

            	errcode = pt_insn_get_offset(decoder, &offset);
				if (errcode < 0)
					break;

			status = pt_insn_next(decoder, &insn, sizeof(insn));
			if (status < 0) {
				/* Even in case of errors, we may have succeeded
				 * in decoding the current instruction.
				 */
				print_insn(&insn, &xed,offset);
                    /*
					if (stats)
						stats->insn += 1;

					if (options->check)
						check_insn(&insn, offset);
                        */
				}
           	print_insn(&insn, &xed, offset);
            print_raw_insn_file(&insn);
		}


		

		/* We shouldn't break out of the loop without an error. */
		if (!status)
			status = -pte_internal;

		/* We're done when we reach the end of the trace stream. */
		if (status == -pte_eos)
            printf("error with ent");
    

    return true;
}


/*
 * Loads the libipt image `image` with the code of the current process.
 *
 * Returns true on success or false otherwise.
 */
static bool
load_self_image(struct load_self_image_args *args)
{
    if (dl_iterate_phdr(load_self_image_cb, args) != 0) {
        return false;
    }
    printf("\n");
    if (fsync(args->vdso_fd) == -1) {
        hwt_set_cerr(args->err, hwt_cerror_errno, errno);
        return false;
    }

    return true;
}

/*
 * The callback for `load_self_image()`, called once for each program header.
 *
 * Returns 1 to stop iterating, and in our case to indicate an error. Returns 0
 * on success and to continue iterating. See dl_iterate_phdr(3) for information
 * on this interface.
 */
static int
load_self_image_cb(struct dl_phdr_info *info, size_t size, void *data)
{
     ElfW(Phdr) phdr;
    ElfW(Half) i;

    (void) size; // Unused. Silence warning.
    struct load_self_image_args *args = data;
    struct hwt_cerror *err = args->err;

    const char *filename = info->dlpi_name;
    bool vdso = false;
    if (!*filename) {
        // On Linux, an empty name means that it is the executable itself.
        filename = args->current_exe;
    } else {
        vdso = strcmp(filename, VDSO_NAME) == 0;
    }

    printf("%s\n",filename);

    for (i = 0; i < info->dlpi_phnum; i++) {
        phdr = info->dlpi_phdr[i];
        // Ensure we only use loadable and executable sections.
        if ((phdr.p_type != PT_LOAD) || (!(phdr.p_flags & PF_X))) {
            continue;
        }

        uint64_t vaddr = info->dlpi_addr + phdr.p_vaddr;
        uint64_t offset;

        // Load the code into the libipt image.
        //
        // The VDSO is special. It doesn't exist on-disk as a regular library,
        // but rather it is a set of pages shared with the kernel.
        //
        // XXX Since libipt currently requires us to load from a file, we have
        // to dump the VDSO to disk and have libipt load it back in.
        //
        // Discussion on adding libipt support for loading from memory here:
        // https://github.com/01org/processor-trace/issues/37
        if (vdso) {
            int rv = hwt_ipt_dump_vdso(args->vdso_fd, vaddr, phdr.p_filesz, err);
            if (!rv) {
                return 1;
            }
            filename = args->vdso_filename;
            offset = 0;
        } else {
            offset = phdr.p_offset;
        }

        int isid = pt_iscache_add_file(args->iscache, filename, offset, phdr.p_filesz, vaddr);
        if (isid < 0) {
            return 1;
        }

        int rv = pt_image_add_cached(args->image, args->iscache, isid, NULL);
        if (rv < 0) {
            hwt_set_cerr(err, hwt_cerror_ipt, -rv);
            return 1;
        }
    }

    return 0;
}

/*
 * Free a block decoder and its image.
 */
void
hwt_ipt_free_insn_decoder(struct pt_insn_decoder *decoder) {
    if (decoder != NULL) {
        pt_insn_free_decoder(decoder);
    }
}

/*
 * Indicates if the specified error code is the overflow code.
 * This exists to avoid copying (and keeping in sync) the ipt error code on the
 * Rust side.
 */
bool
hwt_ipt_is_overflow_err(int err) {
    return err == pte_overflow;
}
