	.global _start
	.hidden _start
	.type   _start,@function
_start:
	mr      3, 1
	clrrwi	1, 1, 4
	li	0, 0
	stwu	1, -16(1)
	mtlr	0
	stw	0, 0(1)
	b	_main
	.size   _start, .-_start
	.end    _start
