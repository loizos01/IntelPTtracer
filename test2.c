#include "perf_pt/util.c"
#include "perf_pt/perf_pt_private.h"
#include "perf_pt/collect.c"
#include "perf_pt/decode.c"
//Data,Aux,Trace buffer sizes
#define  PERF_PT_DFLT_DATA_BUFSIZE  64
#define  PERF_PT_DFLT_AUX_BUFSIZE  1024
#define  PERF_PT_DFLT_INITIAL_TRACE_BUFSIZE  1024 * 1024

struct perf_pt_config pptConf = {
	.data_bufsize = PERF_PT_DFLT_DATA_BUFSIZE,
	.aux_bufsize = PERF_PT_DFLT_AUX_BUFSIZE,
	.initial_trace_bufsize = PERF_PT_DFLT_INITIAL_TRACE_BUFSIZE	
};

struct perf_pt_cerror pptCerror;
struct perf_pt_trace pptTrace;

char *vdsoFn= VDSO_NAME;
const char *curr_exe = "/mnt/expansion/lnicol01/prettylady/a.out";

int main(int argc, char **argv) { 
    struct tracer_ctx *tracer = perf_pt_init_tracer(&pptConf,&pptCerror);
    //printf("perf_fd %d", tracer->perf_fd);  

    if(!perf_pt_start_tracer(tracer,&pptTrace,&pptCerror)){
	    printf("error : Starting Tracer\n");
     }

    //dummy code to trigger branch taken/not taken events
    int a = 0;
    while(a < 4000) {
  
    a += 1;
    }
   
   if(!perf_pt_stop_tracer(tracer,&pptCerror))
	printf("errror : Stopping tracer\n"); 

   void *buffer =malloc(sizeof(*tracer));
   if(buffer == NULL)
	   printf("insufficient space");
   uint64_t len = sizeof(*tracer);
   printf("%"PRIu64"\n", len);
   int *dec_status=NULL;
   FILE  *vdsoFd = fopen(vdsoFn, "w+");   
   int vdsoFd_int = fileno(vdsoFd);  
   struct pt_block_decoder *decoder = perf_pt_init_block_decoder(buffer,len,vdsoFd_int,vdsoFn,dec_status,&pptCerror,curr_exe);

  if(decoder == NULL)
	printf("error: decoder initialization\n");




   if(!perf_pt_free_tracer(tracer,&pptCerror))
	   printf("error: Freeing Tracer\n");
 }
