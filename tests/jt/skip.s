# A PIE switch whose bounds check can be skipped: the jz goes straight to
# the table load with an unchecked index. REX must refuse (E401), since
# the table read is only safe after the ja.
	.text
	.globl	sw
	.type	sw, @function
sw:
	test	%esi, %esi
	jz	.Lload
	cmp	$3, %edi
	ja	.Ldef
.Lload:
	mov	%edi, %eax
	lea	.Ltab(%rip), %rdx
	movslq	(%rdx,%rax,4), %rax
	add	%rdx, %rax
	jmp	*%rax
.L0:	mov	$11, %eax
	ret
.L1:	mov	$23, %eax
	ret
.L2:	mov	$37, %eax
	ret
.L3:	mov	$41, %eax
	ret
.Ldef:	mov	$-1, %eax
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
	mov	$2, %edi
	mov	$1, %esi
	call	sw
	ret
	.size	main, .-main
	.section	.note.GNU-stack,"",@progbits
