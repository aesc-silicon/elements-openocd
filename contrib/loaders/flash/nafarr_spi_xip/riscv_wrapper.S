/* SPDX-License-Identifier: GPL-2.0-or-later */

		.section .text.entry
		.global _start
_start:
		lla		sp, stack_end
		jal		flash_nafarr_spi_xip
		ebreak

		.section .data
		.balign 4
stack:
		.fill	32, 4, 0
stack_end:
