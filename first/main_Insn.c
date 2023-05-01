#define _GNU_SOURCE
#include "perf_pt/util.c"
#include "perf_pt/hwtracer_private.h"
#include "perf_pt/collect_tracee.c"
#include "perf_pt/decode_insn_tracee.c"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/hw_breakpoint.h>
#include <sys/user.h>
#include <link.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)



//Data,Aux,Trace buffer sizes
#define  PERF_PT_DFLT_DATA_BUFSIZE  64
#define  PERF_PT_DFLT_AUX_BUFSIZE  1024
#define  PERF_PT_DFLT_INITIAL_TRACE_BUFSIZE  1024 * 1024

struct hwt_perf_collector_config pptConf = {
	.data_bufsize = PERF_PT_DFLT_DATA_BUFSIZE,
	.aux_bufsize = PERF_PT_DFLT_AUX_BUFSIZE,
	.initial_trace_bufsize = PERF_PT_DFLT_INITIAL_TRACE_BUFSIZE	
};


void write_memory(void* addr, size_t size, char* filename){
    void* readout = malloc(size);
    memcpy(readout, addr, size);
    FILE* fd = fopen(filename, "wb");
    fwrite(readout, 1, size, fd);
    fclose(fd);
    free(readout);
}


struct hwt_cerror pptCerror;
struct hwt_perf_trace pptTrace;

struct ptxed_stats stats;

char *vdsoFn= VDSO_NAME;
const char *curr_exe = "/home/ucy-lab216/Desktop/prettylady/first/dummy.out";



int main(int argc, char **argv) { 

   if (argc <= 1)
        FATAL("too few arguments: %d", argc);

    pid_t traceepid = fork();
    switch (traceepid) {
        case -1: /* error */
            FATAL("%s", strerror(errno));
        case 0:  /* child */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* Because we're now a tracee, execvp will block until the parent
             * attaches and allows us to continue. */
            execvp(argv[1], argv + 1);
            FATAL("%s", strerror(errno));
    }


//Wait for tracee to stop
waitpid(traceepid, 0, 0);

ptrace(PTRACE_SETOPTIONS, traceepid, 0, PTRACE_O_TRACEEXIT);

int dec_status;

FILE  *vdsoFd = fopen(vdsoFn, "w+");   
int vdsoFd_int = fileno(vdsoFd);


struct  hwt_perf_ctx *tracer = hwt_perf_init_collector(&pptConf,&pptCerror,traceepid);
if(tracer==NULL)
   printf("Collector error");


printf("perf_fd %d\n", tracer->perf_fd);  

struct pt_insn_decoder *decoder;
bool first=true;

for(;;){

ioctl(tracer->perf_fd, PERF_EVENT_IOC_RESET, 0);
ioctl(tracer->perf_fd, PERF_EVENT_IOC_ENABLE, 0);
       
/* Enter next system call */
if (ptrace(PTRACE_SYSCALL, traceepid, 0, 0) == -1)
   FATAL("%s", strerror(errno));

if (waitpid(traceepid, 0, 0) == -1)
    FATAL("%s", strerror(errno));

ioctl(tracer->perf_fd, PERF_EVENT_IOC_DISABLE, 0);

 /* Gather system call arguments */
struct user_regs_struct regs;
if (ptrace(PTRACE_GETREGS, traceepid, 0, &regs) == -1)
   FATAL("%s", strerror(errno));

long syscall = regs.orig_rax;
/* Print a representation of the system call */
fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
       		(long)regs.r10, (long)regs.r8,  (long)regs.r9);
/*
write_memory(tracer->aux_buf, tracer->aux_bufsize, "aux");
write_memory(tracer->base_buf, tracer->base_bufsize, "base");
*/

if(first){
   first=false;
   decoder = hwt_ipt_init_inst_decoder(tracer->aux_buf,tracer->aux_bufsize,vdsoFd_int,vdsoFn,&dec_status,&pptCerror,curr_exe);
   if(decoder==NULL)
      printf("error: decoder initialization\n");
}else{
   int dec_status = pt_insn_sync_set(decoder,0);
    if (dec_status == -pte_eos) {
        // There were no blocks in the stream. The user will find out on next
        // call to hwt_ipt_next_block().
        printf("no blocks");
    } else if (dec_status < 0) {
       printf("sync error");
    }
}

if(!hwt_ipt_print_inst(decoder,&dec_status,&pptCerror,&stats,load_args.iscache)){
   printf("error: printing instructions");
}

/* Run system call and stop on exit */
if (ptrace(PTRACE_SYSCALL, traceepid, 0, 0) == -1)
   FATAL("%s", strerror(errno));
if (waitpid(traceepid, 0, 0) == -1)
   FATAL("%s", strerror(errno));

} //End loop



/*
   write_memory(tracer->aux_buf, tracer->aux_bufsize, "aux");
   write_memory(tracer->base_buf, tracer->base_bufsize, "base");
*/ 
   
   /*
   printf("\n%ld\n",tracer->aux_bufsize);
   printf("\n%ld\n",tracer->base_bufsize);
*/


   //printf("Decoder status %d\n",dec_status);



   //decode_block(decoder,&stats,load_args.iscache);
hwt_ipt_free_insn_decoder(decoder);

if(!hwt_perf_free_collector(tracer,&pptCerror))
	   printf("error: Freeing Tracer\n");
 }
