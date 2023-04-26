#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "perf_pt/util.c"
#include "perf_pt/hwtracer_private.h"
#include "perf_pt/decode.c"
#include <link.h>
#define PAGE_SIZE sysconf(_SC_PAGESIZE)

void write_memory(void* addr, size_t size, char* filename){
    void* readout = malloc(size);
    memcpy(readout, addr, size);
    FILE* fd = fopen(filename, "wb");
    fwrite(readout, 1, size, fd);
    fclose(fd);
    free(readout);
}

char *vdsoFn= VDSO_NAME;
const char *curr_exe = "/home/ucy-lab216/Desktop/prettylady/a.out";
struct hwt_cerror pptCerror;
struct ptxed_stats stats;

int main(int argc, char **argv) {
    struct perf_event_attr pe;
    int fd;

    memset(&pe, 0, sizeof(pe));
    pe.type = 8;
    pe.size = sizeof(pe);
    pe.config = 0x300e603; // perf record -vv -e intel_pt/cyc/u
    pe.disabled = 1;
    pe.exclude_kernel = 1;   
   
    fd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd == -1) {
        fprintf(stderr, "Error opening leader %llx\n", pe.config);
        exit(EXIT_FAILURE);
    }

    struct perf_event_mmap_page *header;
    void *base, *data, *aux;
    int n, m;
    n = 5;
    m = 5;
   
    base = mmap(NULL, (1+(1 << n)) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED){
        printf("MAP_FAILED\n");
        return -1;
    }

    header = base;
    data = base + header->data_offset;

    header->aux_offset = header->data_offset + header->data_size;
    header->aux_size   = (1 << m) * PAGE_SIZE;

    aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, fd, header->aux_offset);
    if (aux == MAP_FAILED) {
        printf("MAP_FAILED\n");
        return -1;
    }

  

    sleep(1);

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);


    int a = 0;
    while(a < 5) {
  
    a += 1;
    }

    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    //dummy code to trigger branch taken/not taken events
   uint64_t first_inst;
   uint64_t last_inst;

   int dec_status;

   FILE  *vdsoFd = fopen(vdsoFn, "w+");   
   int vdsoFd_int = fileno(vdsoFd);

   struct pt_block_decoder *decoder = hwt_ipt_init_block_decoder(aux,header->aux_size ,vdsoFd_int,vdsoFn,&dec_status,&pptCerror,curr_exe);

   if(decoder==NULL)
      printf("error: decoder initialization\n");

   //printf("Decoder status %d\n",dec_status);
   for(int i=0;i<24;i++){
      if(!hwt_ipt_next_block(decoder,&dec_status,&first_inst,&last_inst,&pptCerror,&stats,load_args.iscache)){
         printf("error: getting next block");
      }

      printf("First Instruction: %016"PRIx64" Last Instruction %016"PRIx64"\n\n",first_inst,last_inst);
   }

   

   hwt_ipt_free_block_decoder(decoder);

/*
    write_memory(aux, header->aux_size, "aux");
    write_memory(data, header->data_size, "data");
    write_memory(base, (1+(1<<n)) * PAGE_SIZE, "base");
    close(fd);*/
}
