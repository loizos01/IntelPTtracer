//https://github.com/skeeto/ptrace-examples Base code
//https://github.com/intel/libipt/blob/master/doc/howto_capture.md

#define _POSIX_C_SOURCE 200112L

/* C standard library */
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* POSIX */
#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

/* Linux */
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <linux/hw_breakpoint.h>
#include <sys/ptrace.h>
#include <unistd.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

int
main(int argc, char **argv)
{
    
    struct perf_event_attr attr;

    //perf_event_mmap_page
    struct perf_event_mmap_page *header;
    void *base, *data, *aux;    

    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = <ready type>(9); /* /sys/bus/event_source/devices/intel_pt/type */

    attr.exclude_kernel = 1;


   if (argc <= 1)
        FATAL("too few arguments: %d", argc);

    pid_t pid = fork();
    switch (pid) {
        case -1: /* error */
            FATAL("%s", strerror(errno));
        case 0:  /* child */
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            /* Because we're now a tracee, execvp will block until the parent
             * attaches and allows us to continue. */
            execvp(argv[1], argv + 1);
            FATAL("%s", strerror(errno));
	    

    }

    /* parent */
    waitpid(pid, 0, 0); // sync with execvp
    
    int fd;
    fd = syscall(SYS_perf_event_open, &attr, <pid>, -1, -1, 0);

    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
		



    for (;;) {
        /* Enter next system call */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Gather system call arguments */
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
            FATAL("%s", strerror(errno));
        long syscall = regs.orig_rax;
	
        /* Print a representation of the system call */
        /*
	fprintf(stderr, "%ld(%ld, %ld, %ld, %ld, %ld, %ld)",
                syscall,
                (long)regs.rdi, (long)regs.rsi, (long)regs.rdx,
       		(long)regs.r10, (long)regs.r8,  (long)regs.r9);
	*/

	/*ROP detection goes here*/
	
	
   	 base = mmap(NULL, (1+2**n) * PAGE_SIZE, PROT_WRITE, MAP_SHARED, fd, 0);
	 if (base == MAP_FAILED)
        	return <handle data mmap error>();

	 header = base;
	 data = base + header->data_offset;

	 header->aux_offset = header->data_offset + header->data_size;
	 header->aux_size   = (2**m) * PAGE_SIZE;

	 aux = mmap(NULL, header->aux_size, PROT_READ, MAP_SHARED, fd,header->aux_offset);
	 if (aux == MAP_FAILED)
        	return <handle aux mmap error>();



        /* Run system call and stop on exit */
        if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));
        if (waitpid(pid, 0, 0) == -1)
            FATAL("%s", strerror(errno));

        /* Get system call result */
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            fputs(" = ?\n", stderr);
            if (errno == ESRCH)
                exit(regs.rdi); // system call was _exit(2) or similar
            FATAL("%s", strerror(errno));
        }

        /* Print system call result */
        //printf(stderr, " = %ld\n", (long)regs.rax);
    }
}
