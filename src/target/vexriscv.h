#ifndef __vexriscv_H__
#define __vexriscv_H__

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

#define vexriscv_BREAK_INST 0x00100073

static int vexriscv_read_memory(struct target *target, uint32_t address, uint32_t size, uint32_t count, uint8_t *buffer);
static int vexriscv_write32(struct target *target, uint32_t address,uint32_t data);
static int vexriscv_read32(struct target *target, uint32_t address,uint32_t *data);
static void vexriscv_write32_no_execute(struct target *target, uint32_t address,uint32_t data);
static void vexriscv_read32_no_execute(struct target *target, uint32_t address,uint32_t *data,uint8_t *flags);
static void vexriscv_read_rsp_splited(struct target *target,uint32_t *data,uint8_t* flags);
static int vexriscv_check_rsp_Flags(uint8_t flags);
static int vexriscv_halt(struct target *target);
#endif /* __vexriscv_H__ */
