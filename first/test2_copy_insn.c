#define _GNU_SOURCE
#include "perf_pt/util.c"
#include "perf_pt/hwtracer_private.h"
#include "perf_pt/collect.c"
#include "perf_pt/decode_insn.c"
#include <link.h>



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
const char *curr_exe = "/home/ucy-lab216/Desktop/prettylady/a.out";



int main(int argc, char **argv) { 
    struct  hwt_perf_ctx *tracer = hwt_perf_init_collector(&pptConf,&pptCerror);
    if(tracer==NULL)
         printf("Collector error");
   printf("perf_fd %d\n", tracer->perf_fd);  

   ioctl(tracer->perf_fd, PERF_EVENT_IOC_RESET, 0);
   ioctl(tracer->perf_fd, PERF_EVENT_IOC_ENABLE, 0);

   int a=0;
   for(int i=0;i<4;i++){
    a++;
   }
  
   ioctl(tracer->perf_fd, PERF_EVENT_IOC_DISABLE, 0);


   write_memory(tracer->aux_buf, tracer->aux_bufsize, "aux");
   write_memory(tracer->base_buf, tracer->base_bufsize, "base");
   
   printf("\n%ld\n",tracer->aux_bufsize);
   printf("\n%ld\n",tracer->base_bufsize);

   int dec_status;

   FILE  *vdsoFd = fopen(vdsoFn, "w+");   
   int vdsoFd_int = fileno(vdsoFd);


   struct pt_insn_decoder *decoder = hwt_ipt_init_inst_decoder(tracer->aux_buf,tracer->aux_bufsize,vdsoFd_int,vdsoFn,&dec_status,&pptCerror,curr_exe);

   if(decoder==NULL)
      printf("error: decoder initialization\n");

   //printf("Decoder status %d\n",dec_status);

   if(!hwt_ipt_print_inst(decoder,&dec_status,&pptCerror,&stats,load_args.iscache)){
      printf("error: printing instructions");
   }


   //decode_block(decoder,&stats,load_args.iscache);
   
   //while(true){}
   hwt_ipt_free_insn_decoder(decoder);

   if(!hwt_perf_free_collector(tracer,&pptCerror))
	   printf("error: Freeing Tracer\n");
 }
