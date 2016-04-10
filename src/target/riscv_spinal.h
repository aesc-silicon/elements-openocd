#ifndef __RISCV_SPINAL_H__
#define __RISCV_SPINAL_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/jtag.h>
#include <target/register.h>
#include <target/target.h>
#include <target/breakpoints.h>
#include <target/target_type.h>
#include <helper/time_support.h>
#include <helper/fileio.h>
#include "target.h"
#include "target_type.h"

#include <jtag/jtag.h>



static int riscv_spinal_read_memory(struct target *target, uint32_t address,
			       uint32_t size, uint32_t count, uint8_t *buffer);
#endif /* __RISCV_SPINAL_H__ */
