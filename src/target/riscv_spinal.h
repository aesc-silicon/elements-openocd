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

#define NO_SINGLE_STEP		0
#define SINGLE_STEP		1

#define RISCV_SPINAL_BREAK_INST 0x00100073

static int riscv_spinal_read_memory(struct target *target, uint32_t address, uint32_t size, uint32_t count, uint8_t *buffer);
static int riscv_spinal_write32(struct target *target, uint32_t address,uint32_t data);
static int riscv_spinal_read32(struct target *target, uint32_t address,uint32_t *data);
static int riscv_spinal_halt(struct target *target);
#endif /* __RISCV_SPINAL_H__ */
