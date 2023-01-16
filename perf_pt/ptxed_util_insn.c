#include <intel-pt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <pt_cpu.h>
#include <xed-interface.h>

FILE  *bufferFd;

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
static const char *print_exec_mode(enum pt_exec_mode mode);
static int xed_next_ip(uint64_t *pip, const xed_decoded_inst_t *inst,
		       uint64_t ip);
static void xed_print_insn(const xed_decoded_inst_t *inst, uint64_t ip);
static int block_fetch_insn(struct pt_insn *insn, const struct pt_block *block,
			    uint64_t ip, struct pt_image_section_cache *iscache);     
static xed_machine_mode_enum_t translate_mode(enum pt_exec_mode mode);  
static void print_raw_insn(const struct pt_insn *insn);
static void print_raw_insn_file(const struct pt_insn *insn);
static void print_block(struct pt_block_decoder *decoder,
			const struct pt_block *block,
			const struct ptxed_stats *stats,
			uint64_t offset,
			struct pt_image_section_cache *iscache);
static int drain_events_insn(struct pt_insn_decoder  *decoder,int status);               


static const char *print_exec_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return "<unknown>";

	case ptem_16bit:
		return "16-bit";

	case ptem_32bit:
		return "32-bit";

	case ptem_64bit:
		return "64-bit";
	}

	return "<invalid>";
}

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
	printf("             ");
	length = insn->size;
	if (sizeof(insn->raw) < length)
		length = sizeof(insn->raw);

	for (idx = 0; idx < length; ++idx)
		printf("%02x",insn->raw[idx]);

	for (; idx < pt_max_insn_size; ++idx)
		printf("   ");
}



static void print_raw_insn_file(const struct pt_insn *insn)
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
		fprintf(bufferFd,"%02x", insn->raw[idx]);

	for (; idx < pt_max_insn_size; ++idx)
		fprintf(bufferFd,"   ");
	fprintf(bufferFd,"\n");
}

static int drain_events_insn(struct pt_insn_decoder *decoder,int status)
{
	int errcode;
	while (status & pts_event_pending) {
		struct pt_event event;
		uint64_t offset;

		offset = 0ull;

		errcode = pt_insn_get_offset(decoder, &offset);
		if (errcode < 0)
			return errcode;

		status = pt_insn_event(decoder, &event, sizeof(event));
		if (status < 0)
			return status;

	}

	return status;
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

	printf(" %s ", buffer);
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



static void print_insn(const struct pt_insn *insn, xed_state_t *xed, uint64_t offset)
{
	if (!insn) {
		printf("[internal error]\n");
		return;
	}

	//printf("%016" PRIx64 " ", offset);

	printf("%016" PRIx64, insn->ip);


		xed_machine_mode_enum_t mode;
		xed_decoded_inst_t inst;
		xed_error_enum_t errcode;

		mode = translate_mode(insn->mode);

		xed_state_set_machine_mode(xed, mode);
		xed_decoded_inst_zero_set_mode(&inst, xed);

		errcode = xed_decode(&inst, insn->raw, insn->size);
		switch (errcode) {
		case XED_ERROR_NONE:
			xed_print_insn(&inst, insn->ip);
			break;

		default:
			print_raw_insn(insn);

			printf(" [xed decode error: (%u) %s]", errcode,
			       xed_error_enum_t2str(errcode));
			break;
		}

	printf("\n");
}

