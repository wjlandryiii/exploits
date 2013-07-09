
all: perf_ptmx_arm rootperms.text

perf_ptmx_arm: perf_ptmx_arm.c
	gcc -o perf_ptmx_arm perf_ptmx_arm.c

rootperms.text: rootperms.elf
	objcopy -O binary --only-section=.text rootperms.elf rootperms.text

rootperms.elf: rootperms.o
	ld -o rootperms.elf rootperms.o

rootperms.o: rootperms.s
	as -o rootperms.o rootperms.s

clean:
	rm perf_ptmx_arm rootperms.text rootperms.elf rootperms.o
