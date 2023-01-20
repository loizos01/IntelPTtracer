#include <intel-pt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <pt_cpu.h>
#include <xed/xed-interface.h>

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
static void xed_print_insn(const xed_decoded_inst_t *inst, uint64_t ip);
static xed_machine_mode_enum_t translate_mode(enum pt_exec_mode mode);  
static void print_raw_insn(const struct pt_insn *insn);
static void print_raw_insn_file(const struct pt_insn *insn);
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

	print_exec_mode(insn->mode);
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

