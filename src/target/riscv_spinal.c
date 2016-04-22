/***************************************************************************
 *   Copyright (C) 2015 by Esben Haabendal                                 *
 *   eha@deif.com                                                          *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 ***************************************************************************/
#include "riscv_spinal.h"

enum riscv_spinal_reg_nums {
	RISCV_SPINAL_REG_R0 = 0,
	RISCV_SPINAL_REG_R1,
	RISCV_SPINAL_REG_R2,
	RISCV_SPINAL_REG_R3,
	RISCV_SPINAL_REG_R4,
	RISCV_SPINAL_REG_R5,
	RISCV_SPINAL_REG_R6,
	RISCV_SPINAL_REG_R7,
	RISCV_SPINAL_REG_R8,
	RISCV_SPINAL_REG_R9,
	RISCV_SPINAL_REG_R10,
	RISCV_SPINAL_REG_R11,
	RISCV_SPINAL_REG_R12,
	RISCV_SPINAL_REG_R13,
	RISCV_SPINAL_REG_R14,
	RISCV_SPINAL_REG_R15,
	RISCV_SPINAL_REG_R16,
	RISCV_SPINAL_REG_R17,
	RISCV_SPINAL_REG_R18,
	RISCV_SPINAL_REG_R19,
	RISCV_SPINAL_REG_R20,
	RISCV_SPINAL_REG_R21,
	RISCV_SPINAL_REG_R22,
	RISCV_SPINAL_REG_R23,
	RISCV_SPINAL_REG_R24,
	RISCV_SPINAL_REG_R25,
	RISCV_SPINAL_REG_R26,
	RISCV_SPINAL_REG_R27,
	RISCV_SPINAL_REG_R28,
	RISCV_SPINAL_REG_R29,
	RISCV_SPINAL_REG_R30,
	RISCV_SPINAL_REG_R31,
	RISCV_SPINAL_REG_PC,
	RISCV_SPINAL_REG_FLAGS,
	RISCV_SPINAL_NUM_CORE_REGS
};


#define RISCV_SPINAL_FLAGS_RESET 1<<0
#define RISCV_SPINAL_FLAGS_HALT 1<<1
#define RISCV_SPINAL_FLAGS_PIP_EMPTY 1<<2
#define RISCV_SPINAL_FLAGS_PIP_FLUSH 1<<2
#define RISCV_SPINAL_FLAGS_IS_IN_BREAKPOINT 1<<3
#define RISCV_SPINAL_FLAGS_STEP 1<<4
#define RISCV_SPINAL_FLAGS_PC_INC 1<<5
#define RISCV_SPINAL_FLAGS_ICACHE_FLUSH 1<<8



#define FALSE 0
#define TRUE 1


struct riscv_spinal_common {
	struct jtag_tap *tap;
	struct reg_cache *core_cache;
	uint32_t core_regs[RISCV_SPINAL_NUM_CORE_REGS];
	int nb_regs;
	struct riscv_spinal_core_reg *arch_info;
	uint32_t cpuAddress;
};

static inline struct riscv_spinal_common *
target_to_riscv_spinal(struct target *target)
{
	return (struct riscv_spinal_common *)target->arch_info;
}

struct riscv_spinal_core_reg {
	const char *name;
	uint32_t list_num;   /* Index in register cache */
	uint32_t spr_num;    /* Number in architecture's SPR space */
	uint32_t inHaltOnly;
	struct target *target;
	struct riscv_spinal_common *riscv_spinal_common;
};


struct riscv_spinal_core_reg_init {
	const char *name;
	uint32_t spr_num;    /* Number in architecture's SPR space */
	uint32_t inHaltOnly;
};


static struct riscv_spinal_core_reg *riscv_spinal_core_reg_list_arch_info;


static const struct riscv_spinal_core_reg_init riscv_spinal_init_reg_list[] = {
	/*{"zero"    	  , 0   + 0*4, TRUE},
	{"ra"	      , 0   + 1*4, TRUE},
	{"sp"	      , 0   + 2*4, TRUE},
	{"gp"	      , 0   + 3*4, TRUE},
	{"tp"	      , 0   + 4*4, TRUE},
	{"t0"	      , 0   + 5*4, TRUE},
	{"t1"	      , 0   + 6*4, TRUE},
	{"t2"	      , 0   + 7*4, TRUE},
	{"fp"	      , 0   + 8*4, TRUE},
	{"s1"	      , 0   + 9*4, TRUE},
	{"a0"	      , 0   + 10*4, TRUE},
	{"a1"	      , 0   + 11*4, TRUE},
	{"a2"	      , 0   + 12*4, TRUE},
	{"a3"	      , 0   + 13*4, TRUE},
	{"a4"	      , 0   + 14*4, TRUE},
	{"a5"	      , 0   + 15*4, TRUE},
	{"a6"	      , 0   + 16*4, TRUE},
	{"a7"	      , 0   + 17*4, TRUE},
	{"s2"	      , 0   + 18*4, TRUE},
	{"s3"	      , 0   + 19*4, TRUE},
	{"s4"	      , 0   + 20*4, TRUE},
	{"s5"	      , 0   + 21*4, TRUE},
	{"s6"	      , 0   + 22*4, TRUE},
	{"s7"	      , 0   + 23*4, TRUE},
	{"s8"	      , 0   + 24*4, TRUE},
	{"s9"	      , 0   + 25*4, TRUE},
	{"s10"	      , 0   + 26*4, TRUE},
	{"s11"	      , 0   + 27*4, TRUE},
	{"t3"	      , 0   + 28*4, TRUE},
	{"t4"	      , 0   + 29*4, TRUE},
	{"t5"	      , 0   + 30*4, TRUE},
	{"t6"	      , 0   + 31*4, TRUE},*/
	{"x0"    	  , 0   + 0*4, TRUE},
	{"x1"	      , 0   + 1*4, TRUE},
	{"x2"	      , 0   + 2*4, TRUE},
	{"x3"	      , 0   + 3*4, TRUE},
	{"x4"	      , 0   + 4*4, TRUE},
	{"x5"	      , 0   + 5*4, TRUE},
	{"x6"	      , 0   + 6*4, TRUE},
	{"x7"	      , 0   + 7*4, TRUE},
	{"x8"	      , 0   + 8*4, TRUE},
	{"x9"	      , 0   + 9*4, TRUE},
	{"x10"	      , 0   + 10*4, TRUE},
	{"x11"	      , 0   + 11*4, TRUE},
	{"x12"	      , 0   + 12*4, TRUE},
	{"x13"	      , 0   + 13*4, TRUE},
	{"x14"	      , 0   + 14*4, TRUE},
	{"x15"	      , 0   + 15*4, TRUE},
	{"x16"	      , 0   + 16*4, TRUE},
	{"x17"	      , 0   + 17*4, TRUE},
	{"x18"	      , 0   + 18*4, TRUE},
	{"x19"	      , 0   + 19*4, TRUE},
	{"x20"	      , 0   + 20*4, TRUE},
	{"x21"	      , 0   + 21*4, TRUE},
	{"x22"	      , 0   + 22*4, TRUE},
	{"x23"	      , 0   + 23*4, TRUE},
	{"x24"	      , 0   + 24*4, TRUE},
	{"x25"	      , 0   + 25*4, TRUE},
	{"x26"	      , 0   + 26*4, TRUE},
	{"x27"	      , 0   + 27*4, TRUE},
	{"x28"	      , 0   + 28*4, TRUE},
	{"x29"	      , 0   + 29*4, TRUE},
	{"x30"	      , 0   + 30*4, TRUE},
	{"x31"	      , 0   + 31*4, TRUE},
	{"pc"       , 512 + 1*4, TRUE},
	{"flags"    , 512 + 0*4, FALSE},
	{"ft0"	    , 0   + 0*4, FALSE},
	{"ft1"	    , 0   + 0*4, FALSE},
	{"ft2"	    , 0   + 0*4, FALSE},
	{"ft3"	    , 0   + 0*4, FALSE},
	{"ft4"	    , 0   + 0*4, FALSE},
	{"ft5"	    , 0   + 0*4, FALSE},
	{"ft6"	    , 0   + 0*4, FALSE},
	{"ft7"	    , 0   + 0*4, FALSE},
	{"fs0"	    , 0   + 0*4, FALSE},
	{"fs1"	    , 0   + 0*4, FALSE},
	{"fa0"	    , 0   + 0*4, FALSE},
	{"fa1"	    , 0   + 0*4, FALSE},
	{"fa2"	    , 0   + 0*4, FALSE},
	{"fa3"	    , 0   + 0*4, FALSE},
	{"fa4"	    , 0   + 0*4, FALSE},
	{"fa5"	    , 0   + 0*4, FALSE},
	{"fa6"	    , 0   + 0*4, FALSE},
	{"fa7"	    , 0   + 0*4, FALSE},
	{"fs2"	    , 0   + 0*4, FALSE},
	{"fs3"	    , 0   + 0*4, FALSE},
	{"fs4"	    , 0   + 0*4, FALSE},
	{"fs5"	    , 0   + 0*4, FALSE},
	{"fs6"	    , 0   + 0*4, FALSE},
	{"fs7"	    , 0   + 0*4, FALSE},
	{"fs8"	    , 0   + 0*4, FALSE},
	{"fs9"	    , 0   + 0*4, FALSE},
	{"fs10"	    , 0   + 0*4, FALSE},
	{"fs11"	    , 0   + 0*4, FALSE},
	{"ft8"	    , 0   + 0*4, FALSE},
	{"ft9"	    , 0   + 0*4, FALSE},
	{"ft10"	    , 0   + 0*4, FALSE},
	{"ft11"	    , 0   + 0*4, FALSE},
	{"fflags"	, 0   + 0*4, FALSE},
	{"frm"		, 0   + 0*4, FALSE},
	{"fcsr"		, 0   + 0*4, FALSE},
	{"cycle"		, 0   + 0*4, FALSE},
	{"time"		, 0   + 0*4, FALSE},
	{"instret"	, 0   + 0*4, FALSE},
	{"stats"		, 0   + 0*4, FALSE},
	{"uarch0"	, 0   + 0*4, FALSE},
	{"uarch1"	, 0   + 0*4, FALSE},
	{"uarch2"	, 0   + 0*4, FALSE},
	{"uarch3"	, 0   + 0*4, FALSE},
	{"uarch4"	, 0   + 0*4, FALSE},
	{"uarch5"	, 0   + 0*4, FALSE},
	{"uarch6"	, 0   + 0*4, FALSE},
	{"uarch7"	, 0   + 0*4, FALSE},
	{"uarch8"	, 0   + 0*4, FALSE},
	{"uarch9"	, 0   + 0*4, FALSE},
	{"uarch10"	, 0   + 0*4, FALSE},
	{"uarch11"	, 0   + 0*4, FALSE},
	{"uarch12"	, 0   + 0*4, FALSE},
	{"uarch13"	, 0   + 0*4, FALSE},
	{"uarch14"	, 0   + 0*4, FALSE},
	{"uarch15"	, 0   + 0*4, FALSE},
	{"sstatus"	, 0   + 0*4, FALSE},
	{"stvec"		, 0   + 0*4, FALSE},
	{"sie"		, 0   + 0*4, FALSE},
	{"stimecmp"	, 0   + 0*4, FALSE},
	{"sscratch"	, 0   + 0*4, FALSE},
	{"sepc"		, 0   + 0*4, FALSE},
	{"sip"		, 0   + 0*4, FALSE},
	{"sptbr"		, 0   + 0*4, FALSE},
	{"sasid"		, 0   + 0*4, FALSE},
	{"cyclew"	, 0   + 0*4, FALSE},
	{"timew"		, 0   + 0*4, FALSE},
	{"instretw"	, 0   + 0*4, FALSE},
	{"stime"		, 0   + 0*4, FALSE},
	{"scause"	, 0   + 0*4, FALSE},
	{"sbadaddr"	, 0   + 0*4, FALSE},
	{"stimew"	, 0   + 0*4, FALSE},
	{"mstatus"	, 0   + 0*4, FALSE},
	{"mtvec"		, 0   + 0*4, FALSE},
	{"mtdeleg"	, 0   + 0*4, FALSE},
	{"mie"		, 0   + 0*4, FALSE},
	{"mtimecmp"	, 0   + 0*4, FALSE},
	{"mscratch"	, 0   + 0*4, FALSE},
	{"mepc"		, 0   + 0*4, FALSE},
	{"mcause"	, 0   + 0*4, FALSE},
	{"mbadaddr"	, 0   + 0*4, FALSE},
	{"mip"		, 0   + 0*4, FALSE},
	{"mtime"		, 0   + 0*4, FALSE},
	{"mcpuid"	, 0   + 0*4, FALSE},
	{"mimpid"	, 0   + 0*4, FALSE},
	{"mhartid"	, 0   + 0*4, FALSE},
	{"mtohost"	, 0   + 0*4, FALSE},
	{"mfromhost"	, 0   + 0*4, FALSE},
	{"mreset"	, 0   + 0*4, FALSE},
	{"send_ipi"	, 0   + 0*4, FALSE},
	{"cycleh"	, 0   + 0*4, FALSE},
	{"timeh"		, 0   + 0*4, FALSE},
	{"instreth"	, 0   + 0*4, FALSE},
	{"cyclehw"	, 0   + 0*4, FALSE},
	{"timehw"	, 0   + 0*4, FALSE},
	{"instrethw", 0   + 0*4, FALSE},
	{"stimeh"	, 0   + 0*4, FALSE},
	{"stimehw"	, 0   + 0*4, FALSE},
	{"mtimeh"	, 0   + 0*4, FALSE}


};


static int riscv_spinal_create_reg_list(struct target *target)
{
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);

	LOG_DEBUG("-");		

	riscv_spinal_core_reg_list_arch_info = malloc(ARRAY_SIZE(riscv_spinal_init_reg_list) *
				       sizeof(struct riscv_spinal_core_reg));

	for (int i = 0; i < (int)ARRAY_SIZE(riscv_spinal_init_reg_list); i++) {
		riscv_spinal_core_reg_list_arch_info[i].name = riscv_spinal_init_reg_list[i].name;
		riscv_spinal_core_reg_list_arch_info[i].spr_num = riscv_spinal_init_reg_list[i].spr_num;
		riscv_spinal_core_reg_list_arch_info[i].inHaltOnly = riscv_spinal_init_reg_list[i].inHaltOnly;
		riscv_spinal_core_reg_list_arch_info[i].list_num = i;
		riscv_spinal_core_reg_list_arch_info[i].target = NULL;
		riscv_spinal_core_reg_list_arch_info[i].riscv_spinal_common = NULL;
	}

	riscv_spinal->nb_regs = ARRAY_SIZE(riscv_spinal_init_reg_list);

	//struct riscv_spinal_core_reg new_reg;
	//new_reg.target = NULL;
	//new_reg.riscv_spinal_common = NULL;

	return ERROR_OK;
}


static int riscv_spinal_target_create(struct target *target, Jim_Interp *interp)
{
	printf("YOLO riscv_spinal_target_create\n");
	if (target->tap == NULL)
		return ERROR_FAIL;

	struct riscv_spinal_common *riscv_spinal = calloc(1, sizeof(struct riscv_spinal_common));
	target->arch_info = riscv_spinal;
	riscv_spinal->cpuAddress = 0xF0001000;
	riscv_spinal->tap = target->tap;
	riscv_spinal_create_reg_list(target);


	return ERROR_OK;
}

//TODO
static int riscv_spinal_get_core_reg(struct reg *reg)
{
	struct riscv_spinal_core_reg *riscv_spinal_reg = reg->arch_info;
	struct target *target = riscv_spinal_reg->target;
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);

	if(reg->number >= RISCV_SPINAL_NUM_CORE_REGS){
		*(uint32_t*)reg->value = 0xFFFFFFFF;
		reg->valid = 1;
		reg->dirty = 0;
		return ERROR_OK;
	}
	LOG_DEBUG("-");

	if (riscv_spinal_reg->inHaltOnly && target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	struct reg* regAccess = reg;
	if(reg->number == RISCV_SPINAL_REG_R2)
		regAccess = &target->reg_cache->reg_list[RISCV_SPINAL_REG_R8];  //TODO gdb workaround about SP and FP info locals
	int rsp =  riscv_spinal_read32(target,riscv_spinal->cpuAddress + riscv_spinal_core_reg_list_arch_info[regAccess->number].spr_num,reg->value);
	if(rsp != ERROR_OK) return rsp;

	if(reg->number == RISCV_SPINAL_REG_PC){
		rsp = riscv_spinal_get_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS]);
		if (rsp != ERROR_OK) return rsp;
		uint32_t flags = *((uint32_t*)riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS].value);

		if(!(flags & RISCV_SPINAL_FLAGS_IS_IN_BREAKPOINT)){
			if(flags & RISCV_SPINAL_FLAGS_PC_INC){
				*(uint32_t*)reg->value += 4;
			}
		}
	}
	reg->valid = 1;
	reg->dirty = 0;
	return ERROR_OK;
}
//TODO
static int riscv_spinal_set_core_reg(struct reg *reg, uint8_t *buf)
{
	struct riscv_spinal_core_reg *riscv_spinal_reg = reg->arch_info;
	struct target *target = riscv_spinal_reg->target;
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	uint32_t value = buf_get_u32(buf, 0, 32);
	if(reg->number >= RISCV_SPINAL_NUM_CORE_REGS){
		return ERROR_OK;
	}

	LOG_DEBUG("-");

	if (riscv_spinal_reg->inHaltOnly && target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (riscv_spinal_reg->list_num < RISCV_SPINAL_NUM_CORE_REGS) {
		*((uint32_t*)reg->value) = *((uint32_t*)buf);
		int rsp = riscv_spinal_write32(target,riscv_spinal->cpuAddress + riscv_spinal_core_reg_list_arch_info[reg->number].spr_num,value);
		if(rsp != ERROR_OK) return rsp;
	} else {
		LOG_ERROR("ERROR, try to write unexisting CPU register");
		return ERROR_FAIL;
	}

	return ERROR_OK;
}
static int riscv_spinal_get32_core_reg(struct reg *reg,uint32_t *data){
	int rsp = riscv_spinal_get_core_reg(reg);
	*data = *((uint32_t*)reg->value);
	return rsp;
}
static int riscv_spinal_set32_core_reg(struct reg *reg, uint32_t data){
	return riscv_spinal_set_core_reg(reg,(uint8_t*)&data);
}

static const struct reg_arch_type riscv_spinal_reg_type = {
	.get = riscv_spinal_get_core_reg,
	.set = riscv_spinal_set_core_reg,
};

static struct reg_cache *riscv_spinal_build_reg_cache(struct target *target)
{
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	struct reg_cache **cache_p = register_get_last_cache_p(&target->reg_cache);
	struct reg_cache *cache = malloc(sizeof(struct reg_cache));
	struct reg *reg_list = calloc(riscv_spinal->nb_regs, sizeof(struct reg));
	struct riscv_spinal_core_reg *arch_info =
		malloc((riscv_spinal->nb_regs) * sizeof(struct riscv_spinal_core_reg));


	LOG_DEBUG("-");

	/* Build the process context cache */
	cache->name = "OpenRISC 1000 registers";
	cache->next = NULL;
	cache->reg_list = reg_list;
	cache->num_regs = riscv_spinal->nb_regs;
	(*cache_p) = cache;
	riscv_spinal->core_cache = cache;
	riscv_spinal->arch_info = arch_info;

	for (int i = 0; i < riscv_spinal->nb_regs; i++) {
		arch_info[i] = riscv_spinal_core_reg_list_arch_info[i];
		arch_info[i].target = target;
		arch_info[i].riscv_spinal_common = riscv_spinal;
		reg_list[i].name = riscv_spinal_core_reg_list_arch_info[i].name;
		reg_list[i].feature = NULL;
		reg_list[i].group = NULL;
		reg_list[i].size = 32;
		reg_list[i].value = calloc(1, 4);
		reg_list[i].dirty = 0;
		reg_list[i].valid = 0;
		reg_list[i].type = &riscv_spinal_reg_type;
		reg_list[i].arch_info = &arch_info[i];
		reg_list[i].number = i;
		reg_list[i].exist = true;
	}

	return cache;
}

static void riscv_spinal_set_instr(struct jtag_tap *tap, uint32_t new_instr)
{
	struct scan_field field;

	//if (buf_get_u32(tap->cur_instr, 0, tap->ir_length) == new_instr)
	//	return;

	field.num_bits = tap->ir_length;
	uint8_t *t = calloc(DIV_ROUND_UP(field.num_bits, 8), 1);
	field.out_value = t;
	buf_set_u32(t, 0, field.num_bits, new_instr);
	field.in_value = NULL;
	jtag_add_ir_scan(tap, &field, TAP_IDLE);
	free(t);
}
/*
static void ls1_sap_set_instr(struct jtag_tap *tap, uint32_t new_instr)
{
	struct scan_field field;

	//if (buf_get_u32(tap->cur_instr, 0, tap->ir_length) == new_instr)
		//return;

	field.num_bits = tap->ir_length;
	uint8_t *t = calloc(DIV_ROUND_UP(field.num_bits, 8), 1);
	field.out_value = t;
	buf_set_u32(t, 0, field.num_bits, new_instr);
	field.in_value = NULL;
	jtag_add_ir_scan(tap, &field, TAP_IDLE);
	free(t);
}*/
static int riscv_spinal_init_target(struct command_context *cmd_ctx, struct target *target)
{
	printf("YOLO riscv_spinal_init_target\n");
	LOG_DEBUG("%s", __func__);


	riscv_spinal_build_reg_cache(target);

	return ERROR_OK;
}

static int riscv_spinal_arch_state(struct target *target)
{
	printf("YOLO riscv_spinal_arch_state\n");
	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}




static int riscv_spinal_save_context(struct target *target)
{
	LOG_DEBUG("-");

	return ERROR_OK;
}

static int riscv_spinal_restore_context(struct target *target)
{
	LOG_DEBUG("-");

	return ERROR_OK;
}


static int riscv_spinal_debug_entry(struct target *target)
{
	LOG_DEBUG("-");

	int retval = riscv_spinal_save_context(target);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling riscv_spinal_save_context");
		return retval;
	}
/*//TODO
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	uint32_t addr = riscv_spinal->core_regs[riscv_spinal_REG_NPC];

	if (breakpoint_find(target, addr))
		// Halted on a breakpoint, step back to permit executing the instruction there
		retval = riscv_spinal_set_core_reg(&riscv_spinal->core_cache->reg_list[riscv_spinal_REG_NPC],
					   (uint8_t *)&addr);
*/
	return retval;
}

static int riscv_spinal_halt(struct target *target)
{
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);

	LOG_DEBUG("target->state: %s",
		  target_state_name(target));

	if (target->state == TARGET_HALTED) {
		LOG_DEBUG("Target was already halted");
		return ERROR_OK;
	}

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("Target was in unknown state when halt was requested");

	if (target->state == TARGET_RESET) {
		if ((jtag_get_reset_config() & RESET_SRST_PULLS_TRST) &&
		    jtag_get_srst()) {
			LOG_ERROR("Can't request a halt while in reset if nSRST pulls nTRST");
			return ERROR_TARGET_FAILURE;
		} else {
			target->debug_reason = DBG_REASON_DBGRQ;
			return ERROR_OK;
		}
	}

	int retval = riscv_spinal_set32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS],RISCV_SPINAL_FLAGS_HALT);
	if (retval != ERROR_OK) {
		LOG_ERROR("Impossible to stall the CPU");
		return retval;
	}

	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}

static int riscv_spinal_is_running(struct target * target,uint32_t *running){
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	int rsp = riscv_spinal_get32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS],running);
	*running = (*running & RISCV_SPINAL_FLAGS_PIP_EMPTY) && !(*running & RISCV_SPINAL_FLAGS_IS_IN_BREAKPOINT); // || !(*running & RISCV_SPINAL_FLAGS_HALT)
	if (rsp != ERROR_OK) {
		LOG_ERROR("Error while calling riscv_spinal_is_cpu_running");
	}
	return rsp;
}

static int riscv_spinal_poll(struct target *target)
{
	int retval;

	uint32_t running;
	retval = riscv_spinal_is_running(target,&running);
	if (retval != ERROR_OK) {
		return retval;
	}

	/* check for processor halted */
	if (!running) {
		/* It's actually stalled, so update our software's state */
		if ((target->state == TARGET_RUNNING) ||
		    (target->state == TARGET_RESET)) {

			target->state = TARGET_HALTED;

			retval = riscv_spinal_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling riscv_spinal_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,
						    TARGET_EVENT_HALTED);
		} else if (target->state == TARGET_DEBUG_RUNNING) {
			target->state = TARGET_HALTED;

			retval = riscv_spinal_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling riscv_spinal_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,
						    TARGET_EVENT_DEBUG_HALTED);
		}
	} else { /* ... target is running */

		/* If target was supposed to be stalled, stall it again */
		if  (target->state == TARGET_HALTED) {

			target->state = TARGET_RUNNING;

			retval = riscv_spinal_halt(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling riscv_spinal_halt");
				return retval;
			}

			retval = riscv_spinal_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling riscv_spinal_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,
						    TARGET_EVENT_DEBUG_HALTED);
		}

		target->state = TARGET_RUNNING;

	}

	return ERROR_OK;
}

static int riscv_spinal_assert_reset(struct target *target)
{
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	printf("YOLO riscv_spinal_assert_reset\n");
	target->state = TARGET_RESET;

	int rsp = riscv_spinal_set32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS],RISCV_SPINAL_FLAGS_RESET | RISCV_SPINAL_FLAGS_HALT);
	if(rsp != ERROR_OK) return rsp;


	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int riscv_spinal_deassert_reset(struct target *target)
{
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	printf("YOLO riscv_spinal_deassert_reset\n");
	target->state = TARGET_RUNNING;

	int rsp = riscv_spinal_set32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS],RISCV_SPINAL_FLAGS_HALT);
	if(rsp != ERROR_OK) return rsp;

	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}



static void riscv_spinal_memory_cmd(struct jtag_tap *tap, uint32_t address,uint32_t data,int32_t size, int read)
{
	struct scan_field field;
	uint8_t cmd[10];

	riscv_spinal_set_instr(tap, 0x2);

	uint8_t inst = 0x00;
	switch(size){
	case 1:
		size = 0;
		data = data | (data<<8)  | (data<<16)  | (data<<24);
		break;
	case 2:
		size = 1;
		data = data | (data<<16);
		break;
	case 4:
		size = 2;
		break;
	default:
		assert(0);
		break;
	}
    uint8_t write = read ? 0 : 1;

	field.num_bits = 8+32+32+1+2;
	field.out_value = cmd;
	bit_copy(cmd,0,&inst,0,8);
	bit_copy(cmd,8,(uint8_t*)&address,0,32);
	bit_copy(cmd,40,(uint8_t*)&data,0,32);
	bit_copy(cmd,72,&write,0,1);
	bit_copy(cmd,73,(uint8_t*)&size,0,2);
	field.in_value = NULL;
	field.check_value = NULL;
	field.check_mask = NULL;
	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
}

static void riscv_spinal_read_rsp(struct jtag_tap *tap,uint8_t *value)
{
	struct scan_field field;
	riscv_spinal_set_instr(tap, 0x03);

	field.num_bits = 34;
	field.out_value = NULL;
	field.in_value = value;
	field.check_value = NULL;
	field.check_mask = NULL;
	jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
}

static int riscv_spinal_read_memory(struct target *target, uint32_t address,
			       uint32_t size, uint32_t count, uint8_t *buffer)
{
	int rsp;

	/*LOG_DEBUG("Reading memory at physical address 0x%" PRIx32
		  "; size %" PRId32 "; count %" PRId32, address, size, count);*/

	if (count == 0 || buffer == NULL)
		return ERROR_COMMAND_SYNTAX_ERROR;

	uint8_t *t = calloc(count*5, 1);
	uint8_t *tPtr = t;
	uint32_t idx = count;
	while (idx--) {
		riscv_spinal_memory_cmd(target->tap, address,address,size, 1);
		riscv_spinal_read_rsp(target->tap,tPtr);
		address += size;
		tPtr += size + 1;
	}
	rsp = jtag_execute_queue();

	idx = count;
	tPtr = t;
	while(idx--){
		if((tPtr[0] & 3) != 1) return ERROR_JTAG_DEVICE_ERROR; //"TAP communication problem"
		bit_copy(buffer,0,tPtr,2,size*8);
		tPtr += size + 1;
		buffer += size;
	}
	free(t);
	return rsp;
}

static int riscv_spinal_write_memory(struct target *target, uint32_t address,
				uint32_t size, uint32_t count,
				const uint8_t *buffer)
{
	printf("YOLO riscv_spinal_write_memory\n");
	/*LOG_DEBUG("Writing memory at physical address 0x%" PRIx32
		  "; size %" PRId32 "; count %" PRId32, address, size, count);*/


	if (count == 0 || buffer == NULL)
		return ERROR_COMMAND_SYNTAX_ERROR;

	while (count--) {
		riscv_spinal_memory_cmd(target->tap, address,*((uint32_t*)buffer),size, 0);
		address += size;
		buffer += size;
	}

	return jtag_execute_queue();
}

static int riscv_spinal_write32(struct target *target, uint32_t address,uint32_t data){
	return riscv_spinal_write_memory(target,address,4,1,(uint8_t*)&data);
}

static int riscv_spinal_read32(struct target *target, uint32_t address,uint32_t *data){
	return riscv_spinal_read_memory(target,address,4,1,(uint8_t*)data);
}

static int riscv_spinal_get_gdb_reg_list(struct target *target, struct reg **reg_list[],
			  int *reg_list_size, enum target_register_class reg_class)
{
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	printf("riscv_spinal_get_gdb_reg_list %d\n",reg_class);
	if (reg_class == REG_CLASS_GENERAL) {
		/* We will have this called whenever GDB connects. */
		/*int retval = riscv_spinal_save_context(target);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while calling riscv_spinalsave_context");
			return retval;
		}*/
		*reg_list_size = RISCV_SPINAL_NUM_CORE_REGS;
		/* this is free()'d back in gdb_server.c's gdb_get_register_packet() */
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));

		for (int i = 0; i < RISCV_SPINAL_NUM_CORE_REGS; i++)
			(*reg_list)[i] = &riscv_spinal->core_cache->reg_list[i];
	} else {
		printf("?????");
		*reg_list_size = riscv_spinal->nb_regs;
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));
		
		for (int i = 0; i < riscv_spinal->nb_regs; i++)
			(*reg_list)[i] = &riscv_spinal->core_cache->reg_list[i];
	}

	return ERROR_OK;

}

static int riscv_spinal_add_breakpoint(struct target *target,
			       struct breakpoint *breakpoint)
{
	uint32_t data;

	LOG_DEBUG("Adding breakpoint: addr 0x%08" PRIx32 ", len %d, type %d, set: %d, id: %" PRId32,
		  breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

	/* Only support SW breakpoints for now. */
	if (breakpoint->type == BKPT_HARD)
		LOG_ERROR("HW breakpoints not supported for now. Doing SW breakpoint.");

	/* Read and save the instruction */
	int retval = riscv_spinal_read32(target,
					 breakpoint->address,
					 &data);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while reading the instruction at 0x%08" PRIx32,
			   breakpoint->address);
		return retval;
	}

	if (breakpoint->orig_instr != NULL)
		free(breakpoint->orig_instr);

	breakpoint->orig_instr = malloc(breakpoint->length);
	memcpy(breakpoint->orig_instr, &data, breakpoint->length);

	/* Sub in the riscv_spinal trap instruction */
	retval = riscv_spinal_write32(target,
					  breakpoint->address,
					  RISCV_SPINAL_BREAK_INST);

	if (retval != ERROR_OK) {
		LOG_ERROR("Error while writing riscv_spinal_TRAP_INSTR at 0x%08" PRIx32,
			   breakpoint->address);
		return retval;
	}

	/* TODO invalidate instruction cache */

	return ERROR_OK;
}

static int riscv_spinal_remove_breakpoint(struct target *target,
				  struct breakpoint *breakpoint)
{
	LOG_DEBUG("Removing breakpoint: addr 0x%08" PRIx32 ", len %d, type %d, set: %d, id: %" PRId32,
		  breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

	/* Only support SW breakpoints for now. */
	if (breakpoint->type == BKPT_HARD)
		LOG_ERROR("HW breakpoints not supported for now. Doing SW breakpoint.");

	/* Replace the removed instruction */
	int retval = riscv_spinal_write32(target,
					  breakpoint->address,
					  *((uint32_t*)breakpoint->orig_instr));

	if (retval != ERROR_OK) {
		LOG_ERROR("Error while writing back the instruction at 0x%08" PRIx32,
			   breakpoint->address);
		return retval;
	}

	/* TODO invalidate instruction cache */

	return ERROR_OK;
}

//TODO look like instruction step when branch is strange
static int riscv_spinal_resume_or_step(struct target *target, int current,
			       uint32_t address, int handle_breakpoints,
			       int debug_execution, int step)
{

	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	struct breakpoint *breakpoint = NULL;
	uint32_t resume_pc;

	LOG_DEBUG("Addr: 0x%" PRIx32 ", stepping: %s, handle breakpoints %s\n",
		  address, step ? "yes" : "no", handle_breakpoints ? "yes" : "no");

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (!debug_execution)
		target_free_all_working_areas(target);

	/* current ? continue on current pc : continue at <address> */

	if (!current){
		resume_pc = address;
	}else{
		riscv_spinal_get32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_PC],&resume_pc);
	}

	riscv_spinal_set32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_PC],resume_pc);

	int retval = riscv_spinal_restore_context(target);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling riscv_spinal_restore_context");
		return retval;
	}


	/* The front-end may request us not to handle breakpoints */
	if (handle_breakpoints) {
		/* Single step past breakpoint at current address */
		breakpoint = breakpoint_find(target, resume_pc);
		if (breakpoint) {
			LOG_DEBUG("Unset breakpoint at 0x%08" PRIx32, breakpoint->address);
			retval = riscv_spinal_remove_breakpoint(target, breakpoint);
			if (retval != ERROR_OK)
				return retval;
		}
	}

	/* clear pipeline */
	retval = riscv_spinal_set32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS],RISCV_SPINAL_FLAGS_PIP_FLUSH | RISCV_SPINAL_FLAGS_ICACHE_FLUSH | RISCV_SPINAL_FLAGS_HALT);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while unstalling the CPU");
		return retval;
	}

	/* Unstall */
	retval = riscv_spinal_set32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS],(step ? RISCV_SPINAL_FLAGS_STEP : 0));
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while unstalling the CPU");
		return retval;
	}

	if (step)
		target->debug_reason = DBG_REASON_SINGLESTEP;
	else
		target->debug_reason = DBG_REASON_NOTHALTED;

	/* Registers are now invalid */
	register_cache_invalidate(riscv_spinal->core_cache);

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		LOG_DEBUG("Target resumed at 0x%08" PRIx32, resume_pc);
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		LOG_DEBUG("Target debug resumed at 0x%08" PRIx32, resume_pc);
	}

	return ERROR_OK;
}

static int riscv_spinal_resume(struct target *target, int current,
		uint32_t address, int handle_breakpoints, int debug_execution)
{
	return riscv_spinal_resume_or_step(target, current, address,
				   handle_breakpoints,
				   debug_execution,
				   NO_SINGLE_STEP);
}

static int riscv_spinal_step(struct target *target, int current,
		     uint32_t address, int handle_breakpoints)
{
	return riscv_spinal_resume_or_step(target, current, address,
				   handle_breakpoints,
				   0,
				   SINGLE_STEP);

}

static int riscv_spinal_examine(struct target *target)
{
	if (!target_was_examined(target)) {

		target_set_examined(target);

		uint32_t running;
		int retval = riscv_spinal_is_running(target,&running);

		if (retval != ERROR_OK) {
			LOG_ERROR("Couldn't read the CPU state");
			return retval;
		} else {
			if (running)
				target->state = TARGET_RUNNING;
			else {
				LOG_DEBUG("Target is halted");

				/* This is the first time we examine the target,
				 * it is stalled and we don't know why. Let's
				 * assume this is because of a debug reason.
				 */
				if (target->state == TARGET_UNKNOWN)
					target->debug_reason = DBG_REASON_DBGRQ;

				target->state = TARGET_HALTED;
			}
		}
	}

	return ERROR_OK;
}

static int riscv_spinal_soft_reset_halt(struct target *target)
{
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	LOG_DEBUG("-");

	int retval = riscv_spinal_set32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS],RISCV_SPINAL_FLAGS_HALT | RISCV_SPINAL_FLAGS_RESET);
	if (retval != ERROR_OK) {
		LOG_ERROR("soft_reset_halt ERROR");
		return retval;
	}
	retval = riscv_spinal_set32_core_reg(&riscv_spinal->core_cache->reg_list[RISCV_SPINAL_REG_FLAGS],RISCV_SPINAL_FLAGS_HALT);
	if (retval != ERROR_OK) {
		LOG_ERROR("soft_reset_halt ERROR");
		return retval;
	}
	return ERROR_OK;
}


static int riscv_spinal_add_watchpoint(struct target *target,
			       struct watchpoint *watchpoint)
{
	LOG_ERROR("%s: implement me", __func__);
	return ERROR_OK;
}

static int riscv_spinal_remove_watchpoint(struct target *target,
				  struct watchpoint *watchpoint)
{
	LOG_ERROR("%s: implement me", __func__);
	return ERROR_OK;
}

struct target_type riscv_spinal_target = {
	.name = "riscv_spinal",

	.target_create = riscv_spinal_target_create,
	.init_target = riscv_spinal_init_target,
	.examine = riscv_spinal_examine,

	.poll = riscv_spinal_poll,
	.arch_state = riscv_spinal_arch_state,
	.get_gdb_reg_list = riscv_spinal_get_gdb_reg_list,

	.halt = riscv_spinal_halt,
	.resume = riscv_spinal_resume,
	.step = riscv_spinal_step,

	.add_breakpoint = riscv_spinal_add_breakpoint,
	.remove_breakpoint = riscv_spinal_remove_breakpoint,
	.add_watchpoint = riscv_spinal_add_watchpoint,
	.remove_watchpoint = riscv_spinal_remove_watchpoint,

	.assert_reset = riscv_spinal_assert_reset,
	.deassert_reset = riscv_spinal_deassert_reset,
	.soft_reset_halt = riscv_spinal_soft_reset_halt,

	.read_memory = riscv_spinal_read_memory,
	.write_memory = riscv_spinal_write_memory,
};
