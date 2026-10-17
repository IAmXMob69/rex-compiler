# an rsp read of a pushed slot; must refuse (E402)
# irr() from tests/dyn.sh, gcc -O1 output edited by hand; main sweeps its inputs
	.text
	.globl	g
	.type	g, @function
g:
	leal	1(%rdi,%rdi,2), %eax
	ret
	.size	g, .-g
	.globl	irr
	.type	irr, @function
irr:
	pushq	%r13
	pushq	%r12
	pushq	%rbp
	pushq	%rbx
	movl	%edi, %r13d
	movl	%esi, %ebp
	movl	%edi, %ebx
	andl	$1, %ebx
	jne	.L7
	movl	%ebx, %r12d
.L4:
	pushq	%r12
	movl	(%rsp), %edi
	popq	%r12
	call	g
	addl	%eax, %ebx
	addl	$1, %r12d
	jmp	.L6
.L7:
	movl	$0, %r12d
	movl	$0, %ebx
	jmp	.L6
.L8:
	movl	%eax, %ebp
.L6:
	leal	0(%rbp,%rbx), %edi
	call	g
	xorl	%eax, %ebx
	cmpl	%r13d, %r12d
	jl	.L4
	testb	$4, %bl
	je	.L2
	leal	-1(%rbp), %eax
	movl	$0, %r12d
	testl	%ebp, %ebp
	jg	.L8
.L2:
	movl	%ebx, %eax
	popq	%rbx
	popq	%rbp
	popq	%r12
	popq	%r13
	ret
	.size	irr, .-irr
	.globl	main
	.type	main, @function
main:
	pushq	%r12
	pushq	%rbp
	pushq	%rbx
	movl	$0, %r12d
	movl	$0, %eax
.L11:
	movl	$-2, %ebx
.L12:
	movl	%eax, %ebp
	sall	$5, %ebp
	subl	%eax, %ebp
	movl	%ebx, %esi
	movl	%r12d, %edi
	call	irr
	addl	%ebp, %eax
	addl	$1, %ebx
	cmpl	$5, %ebx
	jne	.L12
	addl	$1, %r12d
	cmpl	$12, %r12d
	jne	.L11
	movl	%eax, %edx
	movl	$2190262207, %ecx
	imulq	%rcx, %rdx
	shrq	$39, %rdx
	imull	$251, %edx, %ecx
	subl	%ecx, %eax
	popq	%rbx
	popq	%rbp
	popq	%r12
	ret
	.size	main, .-main
	.section	.note.GNU-stack,"",@progbits
