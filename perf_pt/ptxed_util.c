#include <intel-pt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <pt_cpu.h>
#include <xed-interface.h>

/* A collection of statistics. */
struct ptxed_stats {
	/* The number of instructions. */
	uint64_t insn;

	/* The number of blocks.
	 *
	 * This only applies to the block decoder.
	 */
	uint64_t blocks;

	/* A collection of flags saying which statistics to collect/print. */
	uint32_t flags;
};

/*
Private Prototypes
*/
static void diagnose(struct pt_block_decoder *decoder, uint64_t ip,
		     const char *errtype, int errcode);
static void diagnose_block(struct pt_block_decoder *decoder,
			   const char *errtype, int errcode,
			   const struct pt_block *block,
			   struct  pt_image_section_cache *iscache);
static int xed_next_ip(uint64_t *pip, const xed_decoded_inst_t *inst,
		       uint64_t ip);
static void xed_print_insn(const xed_decoded_inst_t *inst, uint64_t ip);
static int block_fetch_insn(struct pt_insn *insn, const struct pt_block *block,
			    uint64_t ip, struct pt_image_section_cache *iscache);     
static xed_machine_mode_enum_t translate_mode(enum pt_exec_mode mode);  
static void print_raw_insn(const struct pt_insn *insn);
static void print_block(struct pt_block_decoder *decoder,
			const struct pt_block *block,
			const struct ptxed_stats *stats,
			uint64_t offset,
			struct pt_image_section_cache *iscache);
static int drain_events_block(struct pt_block_decoder *decoder, uint64_t *time,
			      int status);                    

/*
Public Prototypes
*/
void decode_block(struct pt_block_decoder *decoder,
			 struct ptxed_stats *stats,
			 struct  pt_image_section_cache *iscache);




static void print_raw_insn(const struct pt_insn *insn)
{
	uint8_t length, idx;

	if (!insn) {
		printf("[internal error]");
		return;
	}

	length = insn->size;
	if (sizeof(insn->raw) < length)
		length = sizeof(insn->raw);

	for (idx = 0; idx < length; ++idx)
		printf(" %02x", insn->raw[idx]);

	for (; idx < pt_max_insn_size; ++idx)
		printf("   ");
}

static int drain_events_block(struct pt_block_decoder *decoder, uint64_t *time,
			      int status)
{
	int errcode;

	if (!decoder || !time)
		return -pte_internal;


	while (status & pts_event_pending) {
		struct pt_event event;
		uint64_t offset;

		offset = 0ull;
		errcode = pt_blk_get_offset(decoder, &offset);
		if (errcode < 0)
			return errcode;

		status = pt_blk_event(decoder, &event, sizeof(event));
		if (status < 0)
			return status;

		*time = event.tsc;
	}

	return status;
}


static void diagnose(struct pt_block_decoder *decoder, uint64_t ip,
		     const char *errtype, int errcode)
{
	int err;
	uint64_t pos;

	err = -pte_internal;
	pos = 0ull;
	
	err = pt_blk_get_offset(decoder, &pos);

	if (err < 0) {
		printf("could not determine offset: %s\n",
		       pt_errstr(pt_errcode(err)));
		printf("[?, %" PRIx64 ": %s: %s]\n", ip, errtype,
		       pt_errstr(pt_errcode(errcode)));
	} else
		printf("[%" PRIx64 ", %" PRIx64 ": %s: %s]\n", pos,
		       ip, errtype, pt_errstr(pt_errcode(errcode)));
}

static int xed_next_ip(uint64_t *pip, const xed_decoded_inst_t *inst,
		       uint64_t ip)
{
	xed_uint_t length, disp_width;

	if (!pip || !inst)
		return -pte_internal;

	length = xed_decoded_inst_get_length(inst);
	if (!length) {
		printf("[xed error: failed to determine instruction length]\n");
		return -pte_bad_insn;
	}

	ip += length;

	/* If it got a branch displacement it must be a branch.
	 *
	 * This includes conditional branches for which we don't know whether
	 * they were taken.  The next IP won't be used in this case as a
	 * conditional branch ends a block.  The next block will start with the
	 * correct IP.
	 */
	disp_width = xed_decoded_inst_get_branch_displacement_width(inst);
	if (disp_width)
		ip += (uint64_t) (int64_t)
			xed_decoded_inst_get_branch_displacement(inst);

	*pip = ip;
	return 0;
}

static void xed_print_insn(const xed_decoded_inst_t *inst, uint64_t ip)
{
	xed_print_info_t pi;
	char buffer[256];
	xed_bool_t ok;

	if (!inst) {
		printf(" [internal error]");
		return;
	}

	//Print raw instruction
	/*
	xed_uint_t length, i;

	length = xed_decoded_inst_get_length(inst);
	for (i = 0; i < length; ++i)
		printf(" %02x", xed_decoded_inst_get_byte(inst, i));

	for (; i < pt_max_insn_size; ++i)
		printf("   ");
	*/

	xed_init_print_info(&pi);
	pi.p = inst;
	pi.buf = buffer;
	pi.blen = sizeof(buffer);
	pi.runtime_address = ip;

	//AT&T syntax
	//pi.syntax = XED_SYNTAX_ATT;
	
	ok = xed_format_generic(&pi);
	if (!ok) {
		printf(" [xed print error]");
		return;
	}

	printf("  %s", buffer);
}



static int block_fetch_insn(struct pt_insn *insn, const struct pt_block *block,
			    uint64_t ip, struct pt_image_section_cache *iscache)
{
	if (!insn || !block)
		return -pte_internal;

	/* We can't read from an empty block. */
	if (!block->ninsn)
		return -pte_invalid;

	memset(insn, 0, sizeof(*insn));
	insn->mode = block->mode;
	insn->isid = block->isid;
	insn->ip = ip;

	/* The last instruction in a block may be truncated. */
	if ((ip == block->end_ip) && block->truncated) {
		if (!block->size || (sizeof(insn->raw) < (size_t) block->size))
			return -pte_bad_insn;

		insn->size = block->size;
		memcpy(insn->raw, block->raw, insn->size);
	} else {
		int size;

		size = pt_iscache_read(iscache, insn->raw, sizeof(insn->raw),
				       insn->isid, ip);
		if (size < 0)
			return size;

		insn->size = (uint8_t) size;
	}

	return 0;
}

/*
Identifies processor instruction set mode that we are decoding
*/
static xed_machine_mode_enum_t translate_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return XED_MACHINE_MODE_INVALID;

	case ptem_16bit:
		return XED_MACHINE_MODE_LEGACY_16;

	case ptem_32bit:
		return XED_MACHINE_MODE_LEGACY_32;

	case ptem_64bit:
		return XED_MACHINE_MODE_LONG_64;
	}

	return XED_MACHINE_MODE_INVALID;
}



static void print_block(struct pt_block_decoder *decoder,
			const struct pt_block *block,
			const struct ptxed_stats *stats,
			uint64_t offset,struct pt_image_section_cache *iscache)
{
	xed_machine_mode_enum_t mode;
	xed_state_t xed;
	uint64_t ip;
	uint16_t ninsn;

	if (!block) {
		printf("[internal error]\n");
		return;
	}

	mode = translate_mode(block->mode);
    //The mode, and addresses widths are enumerations that specify the number of bits. 
	xed_state_init2(&xed, mode, XED_ADDRESS_WIDTH_INVALID);

	/* There's nothing to do for empty blocks. */
	ninsn = block->ninsn;
	if (!ninsn)
		return;

	ip = block->ip;
	for (;;) {
		struct pt_insn insn;
		xed_decoded_inst_t inst;
		xed_error_enum_t xederrcode;
		int errcode;

		//Print offset
		//printf("%016" PRIx64 "  ", offset);

		//Print time
		//printf("%016" PRIx64 "  ", time);

		if (block->speculative)
			printf("? ");

		printf("%016" PRIx64, ip);

        //Updates insn with ip instruction in block.
		errcode = block_fetch_insn(&insn, block, ip, iscache);
		if (errcode < 0) {
			printf(" [fetch error: %s]\n",
			       pt_errstr(pt_errcode(errcode)));
			break;
		}

        /*
        Zero the decode structure, but set the machine state/mode information.
        Re-initializes all operands.
        */
		xed_decoded_inst_zero_set_mode(&inst, &xed);

        //Main interface to the decoder.
		xederrcode = xed_decode(&inst, insn.raw, insn.size);
		if (xederrcode != XED_ERROR_NONE) {
			print_raw_insn(&insn);

			printf(" [xed decode error: (%u) %s]\n", xederrcode,
			       xed_error_enum_t2str(xederrcode));
			break;
		}

		xed_print_insn(&inst, insn.ip);

		printf("\n");

		ninsn -= 1;
		if (!ninsn)
			break;

		errcode = xed_next_ip(&ip, &inst, ip);
		if (errcode < 0) {
			diagnose(decoder, ip, "reconstruct error", errcode);
			break;
		}
	}

	/* Decode should have brought us to @block->end_ip. */
	if (ip != block->end_ip)
		diagnose(decoder, ip, "reconstruct error", -pte_nosync);
}

static void diagnose_block(struct pt_block_decoder *decoder,
			   const char *errtype, int errcode,
			   const struct pt_block *block,
			   struct  pt_image_section_cache *iscache)
{
	uint64_t ip;
	int err;

	if (!block) {
		printf("ptxed: internal error");
		return;
	}

	/* Determine the IP at which to report the error.
	 *
	 * Depending on the type of error, the IP varies between that of the
	 * last instruction in @block or the next instruction outside of @block.
	 *
	 * When the block is empty, we use the IP of the block itself,
	 * i.e. where the first instruction should have been.
	 */
	if (!block->ninsn)
		ip = block->ip;
	else {
		ip = block->end_ip;

		switch (errcode) {
		case -pte_nomap:
		case -pte_bad_insn: {
			struct pt_insn insn;
			xed_decoded_inst_t inst;
			xed_error_enum_t xederr;

			/* Decode failed when trying to fetch or decode the next
			 * instruction.  Since indirect or conditional branches
			 * end a block and don't cause an additional fetch, we
			 * should be able to reach that IP from the last
			 * instruction in @block.
			 *
			 * We ignore errors and fall back to the IP of the last
			 * instruction.
			 */
			err = block_fetch_insn(&insn, block, ip,iscache);
			if (err < 0)
				break;

			xed_decoded_inst_zero(&inst);
			xed_decoded_inst_set_mode(&inst,
						  translate_mode(insn.mode),
						  XED_ADDRESS_WIDTH_INVALID);

			xederr = xed_decode(&inst, insn.raw, insn.size);
			if (xederr != XED_ERROR_NONE)
				break;

			(void) xed_next_ip(&ip, &inst, insn.ip);
		}
			break;

		default:
			break;
		}
	}

	diagnose(decoder, ip, errtype, errcode);
}


void decode_block(struct pt_block_decoder *decoder,
			 struct ptxed_stats *stats,
			 struct  pt_image_section_cache *iscache)
{
	uint64_t offset, sync, time;

	if (!decoder) {
		printf("[internal error]\n");
		return;
	}

	offset = 0ull;
	sync = 0ull;
	time = 0ull;
	for (;;) {
		struct pt_block block;
		int status;
		int errcode;
		/* Initialize IP and ninsn - we use it for error reporting. */
		block.ip = 0ull;
		block.ninsn = 0u;
		status = pt_blk_sync_forward(decoder);

		if (status < 0) {
			uint64_t new_sync;
			int errcode;

			//printf("status %d PTE_EOS %d",status, -pte_eos);

			if (status == -pte_eos)
				break;

			diagnose_block(decoder, "sync error", status, &block,iscache);

			/* Let's see if we made any progress.  If we haven't,
			 * we likely never will.  Bail out.
			 *
			 * We intentionally report the error twice to indicate
			 * that we tried to re-sync.  Maybe it even changed.
			 */
			
			errcode = pt_blk_get_offset(decoder, &new_sync);
			if (errcode < 0 || (new_sync <= sync))
				break;

			sync = new_sync;
			continue;
		}
		for (;;) {
			status = drain_events_block(decoder, &time, status);
			if (status < 0)
				break;

			if (status & pts_eos) {
				if (!(status & pts_ip_suppressed))
					printf("[end of trace]\n");

				status = -pte_eos;
				break;
			}

				errcode = pt_blk_get_offset(decoder, &offset);
				if (errcode < 0)
					break;

			status = pt_blk_next(decoder, &block, sizeof(block));
			if (status < 0) {
				/* Even in case of errors, we may have succeeded
				 * in decoding some instructions.
				 */
				if (block.ninsn) {
					if (stats) {
						stats->insn += block.ninsn;
						stats->blocks += 1;
					}
					print_block(decoder, &block, stats,offset,iscache);
				}
				break;
			}

			if (stats) {
				stats->insn += block.ninsn;
				stats->blocks += 1;
			}
				print_block(decoder, &block, stats,offset,iscache);
		}

		/* We shouldn't break out of the loop without an error. */
		if (!status)
			status = -pte_internal;

		/* We're done when we reach the end of the trace stream. */
		if (status == -pte_eos)
			break;

		diagnose_block(decoder, "error", status, &block,iscache);
	}
}



