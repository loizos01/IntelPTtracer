#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <link.h>

#include <time.h>

#include "perf_pt/collect.c"
#include "perf_pt/decode.c"


//Compile
// gcc -L /usr/local/lib/ main.c  -lipt -lxed

#define FATAL(...)                             \
   do                                          \
   {                                           \
      fprintf(stderr, "strace: " __VA_ARGS__); \
      fputc('\n', stderr);                     \
      exit(EXIT_FAILURE);                      \
   } while (0)

// Data,Aux,Trace buffer sizes
#define PERF_PT_DFLT_DATA_BUFSIZE 64
#define PERF_PT_DFLT_AUX_BUFSIZE 1024
#define PERF_PT_DFLT_INITIAL_TRACE_BUFSIZE 1024 * 1024

#define MAXLIST 100

char* parsedArgs[MAXLIST];

struct perf_collector_config pptConf = {
    .data_bufsize = PERF_PT_DFLT_DATA_BUFSIZE,
    .aux_bufsize = PERF_PT_DFLT_AUX_BUFSIZE,
    .initial_trace_bufsize = PERF_PT_DFLT_INITIAL_TRACE_BUFSIZE};

void write_memory(void *addr, size_t size, char *filename)
{
   void *readout = malloc(size);
   memcpy(readout, addr, size);
   FILE *fd = fopen(filename, "wb");
   fwrite(readout, 1, size, fd);
   fclose(fd);
   free(readout);
}

void print_help()
{
   printf("usage: ./a.out [<Path to Tracee elf file>] [<options>]\n\n");
   printf("options:\n\n");
   printf("--depth [numOfInstructions]          preceding number of instructions to check\n");
   printf("--pinfo                              print Intel Pt information\n");
   printf("--pinst                              print traced instructions in x86[-64]\n");
   printf("--pbuff                              print AUX and Base buffers\n");
   printf("--praw                               print raw instructions in buffer.out file\n");
   printf("--psyscall                           print system call chain\n");
   printf("--step                               Step through the syscalls\n");
   printf("--ptracetime                         print intel Pt trace time and exit\n");
   printf("--panalysetime                       print analysis time\n\n");
   return;
}

int main(int argc, char **argv)
{
   int pArgs=0;
   
   clock_t begin;
   clock_t end;
   double time_spent;

   if (argc <= 1)
      FATAL("too few arguments: %d", argc);

   if (argc > 1)
   {
      char *arg;

      int i=0;
      for(i=1;i<argc;i++){
         arg = argv[i];

         if(arg[0]!='-')
            break;

         if (strcmp(arg, "--help") == 0)
         {
            print_help();
            return 0;
            continue;
         }
         if (strcmp(arg, "-h") == 0)
         {
            print_help();
            return 0;
            continue;
         }
         if (strcmp(arg, "--depth") == 0)
         {
            if (argc <= i) {
            fprintf(stderr,
               "--depth: missing argument.\n");
               return 1;
            }
            stats.limited=true;
            stats.depth = atoi(argv[++i]);
            continue;
         }
         if (strcmp(arg, "--pinfo") == 0)
         {
            stats.pinfo = true;
            continue;
         }
         if (strcmp(arg, "--pinst") == 0)
         {
            stats.pinst = true;
            continue;
         }
         if (strcmp(arg, "--pbuff") == 0)
         {
            stats.pbuff = true;
            continue;
         }
         if (strcmp(arg, "--praw") == 0)
         {
            stats.praw = true;
            continue;
         }
         if (strcmp(arg, "--psyscall") == 0)
         {
            stats.psyscall = true;
            continue;
         }
         if (strcmp(arg, "--step") == 0)
         {
            stats.step = true;
            continue;
         }
         if (strcmp(arg, "--ptracetime") == 0)
         {
            stats.ptracetime = true;
            continue;
         }
         if (strcmp(arg, "--panalysetime") == 0)
         {
            stats.panalysetime = true;
            continue;
         }

         printf("unknown option: %s\n", arg);
         return 0;
      }

      pArgs=i;
   }

   pid_t traceepid = fork();

   switch (traceepid)
   {
   case -1: /* error */
      FATAL("%s", strerror(errno));
   case 0: /* child */
      ptrace(PTRACE_TRACEME, 0, 0, 0);
      /* Because we're now a tracee, execvp will block until the parent
       * attaches and allows us to continue. */
      execvp(argv[pArgs], argv+(pArgs+1));
      FATAL("%s", strerror(errno));
   }

   // Wait for tracee to stop
   waitpid(traceepid, 0, 0);

   ptrace(PTRACE_SETOPTIONS, traceepid, 0, PTRACE_O_TRACEEXIT);

   int dec_status;
   struct pt_insn_decoder *decoder;
   bool first = true;

   //
   struct perf_ctx *tracer = perf_init_collector(&pptConf, traceepid, &stats);
   if (tracer == NULL)
      printf("Collector error");

   if (stats.pinfo)
   {
      printf("perf_fd %d\n", tracer->perf_fd);
   }

   if (stats.pinfo)
   {
      printf("Aux Buffer size: %ld\n", tracer->aux_bufsize);
      printf("Base Buffer size: %ld\n", tracer->base_bufsize);
   }
   
   //Prints the time it takes to trace the program
   if(stats.ptracetime){
         
         ioctl(tracer->perf_fd, PERF_EVENT_IOC_RESET, 0);
         ioctl(tracer->perf_fd, PERF_EVENT_IOC_ENABLE, 0);

         begin =clock();
         ptrace(PTRACE_CONT,traceepid,0,0);
         end =clock();

         ioctl(tracer->perf_fd, PERF_EVENT_IOC_DISABLE, 0);

         time_spent = (double)(end-begin) / CLOCKS_PER_SEC;
         printf("%f second\n",time_spent);

         return 0;
   }

   if(stats.panalysetime){
      begin=clock();
   }

   //Main tracing loop
   for (;;)
   {
      ioctl(tracer->perf_fd, PERF_EVENT_IOC_RESET, 0);
      ioctl(tracer->perf_fd, PERF_EVENT_IOC_ENABLE, 0);

      /* Enter next system call */
      if (ptrace(PTRACE_SYSCALL, traceepid, 0, 0) == -1)
      {
         // Tracee is dead, this is triggered when tracee finish executing
         if (errno == ESRCH)
            break;
         FATAL("%s", strerror(errno));
      }

      if (waitpid(traceepid, 0, 0) == -1)
      {
         // Tracee is dead, this is triggered when tracee finish executing
         if (errno == ESRCH)
            break;
         FATAL("%s", strerror(errno));
      }

      ioctl(tracer->perf_fd, PERF_EVENT_IOC_DISABLE, 0);

      if (stats.psyscall)
      {
         /* Gather system call arguments */
         struct user_regs_struct regs;
         if (ptrace(PTRACE_GETREGS, traceepid, 0, &regs) == -1)
         {
            // Tracee is dead, this is triggered when tracee finish executing
            if (errno == ESRCH)
               break;
            FATAL("%s", strerror(errno));
         }

         long syscall = regs.orig_rax;
         /* Print a representation of the system call */
         fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)\n",
                 syscall,
                 (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
                 (long)regs.r10, (long)regs.r8, (long)regs.r9);
         if(stats.step){
             printf("Press any character to continue\n");
             getchar();
         }
      }

      if (stats.pbuff)
      {
         write_memory(tracer->aux_buf, tracer->aux_bufsize, "aux");
         write_memory(tracer->base_buf, tracer->base_bufsize, "base");
      }

      if (first)
      {
         first = false;
         decoder = init_inst_decoder(tracer->aux_buf, tracer->aux_bufsize, &dec_status, argv[pArgs], &stats);
         if (decoder == NULL)
            printf("error: decoder initialization\n");
      }
      else
      {
         int dec_status = pt_insn_sync_set(decoder, 0);
         if (dec_status == -pte_eos)
         {
            // There were no blocks in the stream. The user will find out on next
            // call to hwt_ipt_next_block().
            printf("no blocks");
         }
         else if (dec_status < 0)
         {
            printf("sync error");
         }
      }

      if (!decode_trace(decoder, &dec_status, &stats))
         {
            ptrace(PTRACE_KILL, traceepid, 0, 0);
            return 0;
         } 
      if(stats.step){
         printf("Press any character to continue\n");
         getchar();
      }
      

      /* Run system call and stop on exit */
      if (ptrace(PTRACE_SYSCALL, traceepid, 0, 0) == -1)
      {
         // Tracee is dead, this is triggered when tracee finish executing
         if (errno == ESRCH)
            break;
         FATAL("%s", strerror(errno));
      }
      if (waitpid(traceepid, 0, 0) == -1)
      {
         // Tracee is dead, this is triggered when tracee finish executing
         if (errno == ESRCH)
            break;
         FATAL("%s", strerror(errno));
      }

   } // End loop


   if(stats.panalysetime){
      end=clock();
      time_spent = (double)(end-begin) / CLOCKS_PER_SEC;
      printf("%f second\n",time_spent);

   }

   printf("No attacks found!\n");

   free_insn_decoder(decoder);

   if (!perf_free_collector(tracer))
      printf("error: Freeing Tracer\n");
}
