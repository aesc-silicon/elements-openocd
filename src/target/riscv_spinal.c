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

struct riscv_spinal {
	struct jtag_tap *tap;
};

#define RISCVSPINALNUMCOREREGS 33
/*
struct riscv_spinal_jtag {
	struct jtag_tap *tap;
	int riscv_spinal_jtag_inited;
	int riscv_spinal_jtag_module_selected;
	uint8_t *current_reg_idx;
	struct riscv_spinal_tap_ip *tap_ip;
	struct riscv_spinal_du *du_core;
	struct target *target;
};*/

struct riscv_spinal_common {
	//struct riscv_spinal_jtag jtag;
	struct reg_cache *core_cache;
	uint32_t core_regs[RISCVSPINALNUMCOREREGS];
	int nb_regs;
	struct riscv_spinal_core_reg *arch_info;
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
	struct target *target;
	struct riscv_spinal_common *riscv_spinal_common;
	const char *feature; /* feature name in XML tdesc file */
	const char *group;   /* register group in XML tdesc file */
};


struct riscv_spinal_core_reg_init {
	const char *name;
	uint32_t spr_num;    /* Number in architecture's SPR space */
	const char *feature; /* feature name in XML tdesc file */
	const char *group;   /* register group in XML tdesc file */
};


static struct riscv_spinal_core_reg *riscv_spinal_core_reg_list_arch_info;

static const struct riscv_spinal_core_reg_init riscv_spinal_init_reg_list[] = {
	{"r0"       , 0, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r1"       , 1, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r2"       , 2, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r3"       , 3, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r4"       , 4, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r5"       , 5, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r6"       , 6, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r7"       , 7, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r8"       , 8, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r9"       , 9, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r10"      , 10, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r11"      , 11, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r12"      , 12, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r13"      , 13, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r14"      , 14, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r15"      , 15, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r16"      , 16, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r17"      , 17, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r18"      , 18, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r19"      , 19, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r20"      , 20, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r21"      , 21, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r22"      , 22, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r23"      , 23, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r24"      , 24, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r25"      , 25, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r26"      , 26, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r27"      , 27, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r28"      , 28, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r29"      , 29, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r30"      , 30, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"r31"      , 31, "org.gnu.gdb.riscv_spinal.group0", NULL},
	{"pc"       , 32, "org.gnu.gdb.riscv_spinal.group0", NULL}

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
		riscv_spinal_core_reg_list_arch_info[i].group = riscv_spinal_init_reg_list[i].group;
		riscv_spinal_core_reg_list_arch_info[i].feature = riscv_spinal_init_reg_list[i].feature;
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

	struct riscv_spinal *riscv_spinal = calloc(1, sizeof(struct riscv_spinal));
	target->arch_info = riscv_spinal;
	riscv_spinal->tap = target->tap;
	riscv_spinal_create_reg_list(target);

	return ERROR_OK;
}

//TODO
static int riscv_spinal_get_core_reg(struct reg *reg)
{
	struct riscv_spinal_core_reg *riscv_spinal_reg = reg->arch_info;
	struct target *target = riscv_spinal_reg->target;

	LOG_DEBUG("-");

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	buf_set_u32(reg->value, 0, 32, 0x10000 + reg->number); //caca
	return ERROR_OK;//riscv_spinal_read_core_reg(target, riscv_spinal_reg->list_num);
}
//TODO
static int riscv_spinal_set_core_reg(struct reg *reg, uint8_t *buf)
{
	/*struct riscv_spinal_core_reg *riscv_spinal_reg = reg->arch_info;
	struct target *target = riscv_spinal_reg->target;
	struct riscv_spinal_common *riscv_spinal = target_to_riscv_spinal(target);
	struct riscv_spinal_du *du_core = riscv_spinal_to_du(riscv_spinal);
	uint32_t value = buf_get_u32(buf, 0, 32);

	LOG_DEBUG("-");

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (riscv_spinal_reg->list_num < riscv_spinalNUMCOREREGS) {
		buf_set_u32(reg->value, 0, 32, value);
		reg->dirty = 1;
		reg->valid = 1;
	} else {
		// This is an spr, write it to the HW 
		int retval = ERROR_OK;//du_core->riscv_spinal_jtag_write_cpu(&riscv_spinal->jtag,
				//			  riscv_spinal_reg->spr_num, 1, &value);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while writing spr 0x%08" PRIx32, riscv_spinal_reg->spr_num);
			return retval;
		}
	}*/

	return ERROR_OK;
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
	struct reg_feature *feature;

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

		feature = malloc(sizeof(struct reg_feature));
		feature->name = riscv_spinal_core_reg_list_arch_info[i].feature;
		reg_list[i].feature = feature;

		reg_list[i].group = riscv_spinal_core_reg_list_arch_info[i].group;
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




int counter = 0;
static int riscv_spinal_poll(struct target *target)
{
	int rsp = ERROR_OK;
	//printf("YOLO riscv_spinal_poll\n");
	if ((target->state == TARGET_UNKNOWN) ||
	    (target->state == TARGET_RUNNING) ||
	    (target->state == TARGET_DEBUG_RUNNING))
		target->state = TARGET_HALTED;

/*	uint32_t value;
	rsp = riscv_spinal_read_memory(target, 0x1234,  2, 1, (uint8_t *)&value);
	printf("Read:%x\n",value);*/
/*
	printf("IR length=%d\n",target->tap->ir_length);

	struct scan_field field;
	uint8_t  writeBuf[1];
	uint8_t  readBuf[1];
	ls1_sap_set_instr(target->tap, 0x11);


	writeBuf[0] = counter++;
	field.num_bits = 8 * 1;
	field.out_value = writeBuf;
	field.in_value = readBuf;
	field.check_value = NULL;
	field.check_mask = NULL;
	jtag_add_dr_scan(target->tap, 1, &field, TAP_IDLE);
	rsp = jtag_execute_queue();
	printf("%d -> %d\n",readBuf[0],writeBuf[0]);

	ls1_sap_set_instr(target->tap, 0x12);


	writeBuf[0] = counter++;
	field.num_bits = 8 * 1;
	field.out_value = NULL;
	field.in_value = readBuf;
	field.check_value = NULL;
	field.check_mask = NULL;
	jtag_add_dr_scan(target->tap, 1, &field, TAP_IDLE);
	rsp = jtag_execute_queue();
	printf("SW=%d\n",readBuf[0]);
	return rsp;*/
	return rsp;
}

static int riscv_spinal_halt(struct target *target)
{
	printf("YOLO riscv_spinal_halt\n");
	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int riscv_spinal_resume(struct target *target, int current, uint32_t address,
		int handle_breakpoints, int debug_execution)
{
	printf("YOLO riscv_spinal_resume\n");
	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int riscv_spinal_step(struct target *target, int current, uint32_t address,
				int handle_breakpoints)
{
	printf("YOLO  riscv_spinal_step\n");
	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int riscv_spinal_assert_reset(struct target *target)
{
	printf("YOLO riscv_spinal_assert_reset\n");
	target->state = TARGET_RESET;

	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int riscv_spinal_deassert_reset(struct target *target)
{
	printf("YOLO riscv_spinal_deassert_reset\n");
	target->state = TARGET_RUNNING;

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
	printf("YOLO riscv_spinal_read_memory\n");
	LOG_DEBUG("Reading memory at physical address 0x%" PRIx32
		  "; size %" PRId32 "; count %" PRId32, address, size, count);

	if (count == 0 || buffer == NULL)
		return ERROR_COMMAND_SYNTAX_ERROR;

	while (count--) {
		riscv_spinal_memory_cmd(target->tap, address,address,size, 1);
		uint8_t tmp[5];
		riscv_spinal_read_rsp(target->tap,tmp);
		rsp = jtag_execute_queue();
		bit_copy(buffer,0,tmp,2,size*8);
		address += size;
		buffer += size;
	}

	return rsp;
}

static int riscv_spinal_write_memory(struct target *target, uint32_t address,
				uint32_t size, uint32_t count,
				const uint8_t *buffer)
{
	printf("YOLO riscv_spinal_write_memory\n");
	LOG_DEBUG("Writing memory at physical address 0x%" PRIx32
		  "; size %" PRId32 "; count %" PRId32, address, size, count);


	if (count == 0 || buffer == NULL)
		return ERROR_COMMAND_SYNTAX_ERROR;

	while (count--) {
		riscv_spinal_memory_cmd(target->tap, address,*((uint32_t*)buffer),size, 0);
		address += size;
		buffer += size;
	}

	return jtag_execute_queue();
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
		*reg_list_size = RISCVSPINALNUMCOREREGS;
		/* this is free()'d back in gdb_server.c's gdb_get_register_packet() */
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));

		for (int i = 0; i < RISCVSPINALNUMCOREREGS; i++)
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



struct target_type riscv_spinal_target = {
	.name = "riscv_spinal",

	.target_create = riscv_spinal_target_create,
	.init_target = riscv_spinal_init_target,

	.poll = riscv_spinal_poll,
	.arch_state = riscv_spinal_arch_state,
	.get_gdb_reg_list = riscv_spinal_get_gdb_reg_list,

	.halt = riscv_spinal_halt,
	.resume = riscv_spinal_resume,
	.step = riscv_spinal_step,

	.assert_reset = riscv_spinal_assert_reset,
	.deassert_reset = riscv_spinal_deassert_reset,

	.read_memory = riscv_spinal_read_memory,
	.write_memory = riscv_spinal_write_memory,
};
