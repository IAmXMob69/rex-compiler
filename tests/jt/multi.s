# A PIE switch whose bounds check is in each block that enters the table code
# (clang -O3 does this): a ja that falls into it and a jbe that jumps to it,
# both after cmp $3 on the zero-extended index. REX reads the table; the
# variants in tests/dyn.sh (a different bound, no zero-extension, a plain
# jmp in) must be refused with E401.
	.text
	.globl	sw
	.type	sw, @function
sw:
	test	%esi, %esi
	jz	.Lother
	mov	%edi, %ecx
	cmp	$3, %ecx
	ja	.Ldef
.Lload:
	lea	.Ltab(%rip), %rdx
	movslq	(%rdx,%rcx,4), %rax
	add	%rdx, %rax
	jmp	*%rax
.Lother:
	lea	1(%rdi), %ecx
	cmp	$3, %ecx
	jbe	.Lload
.Ldef:	mov	$-1, %eax
	ret
.L0:	mov	$11, %eax
	ret
.L1:	mov	$23, %eax
	ret
.L2:	mov	$37, %eax
	ret
.L3:	mov	$41, %eax
	ret
	.size	sw, .-sw
	.section	.rodata
	.align 4
.Ltab:
	.long	.L0-.Ltab
	.long	.L1-.Ltab
	.long	.L2-.Ltab
	.long	.L3-.Ltab
	.text
	.globl	main
	.type	main, @function
main:
	push	%rbx
	xor	%ebx, %ebx
	mov	$-3, %edi
.Lm:	push	%rdi
	mov	%edi, %esi
	and	$1, %esi
	call	sw
	pop	%rdi
	imul	$7, %ebx, %ebx
	add	%eax, %ebx
	inc	%edi
	cmp	$6, %edi
	jl	.Lm
	mov	%ebx, %eax
	pop	%rbx
	ret
	.size	main, .-main
	.section	.note.GNU-stack,"",@progbits
