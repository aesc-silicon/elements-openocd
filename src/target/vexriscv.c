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
#include "vexriscv.h"

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <yaml.h>

#define vexriscv_FLAGS_RESET 1<<0
#define vexriscv_FLAGS_HALT 1<<1
#define vexriscv_FLAGS_PIP_BUSY 1<<2
#define vexriscv_FLAGS_HALTED_BY_BREAK 1<<3
#define vexriscv_FLAGS_STEP 1<<4

#define vexriscv_FLAGS_RESET_SET 1<<16
#define vexriscv_FLAGS_HALT_SET 1<<17

#define vexriscv_FLAGS_RESET_CLEAR 1<<24
#define vexriscv_FLAGS_HALT_CLEAR 1<<25

#define FALSE 0
#define TRUE 1

struct BusInfo{
	uint32_t flushInstructionsSize;
	uint32_t *flushInstructions;
};

struct vexriscv_common {
	struct jtag_tap *tap;
	struct reg_cache *core_cache;
	struct vexriscv_reg_mapping *regs;
	//uint32_t core_regs[vexriscv_NUM_CORE_REGS];
	uint32_t nb_regs;
	struct vexriscv_core_reg *arch_info;
	uint32_t dbgBase;
	int clientSocket;
	int useTCP;
	uint32_t readWaitCycles;
	char* cpuConfigFile;
	//uint32_t flags;
	struct BusInfo* iBus, *dBus;
};

static inline struct vexriscv_common *
target_to_vexriscv(struct target *target)
{
	return (struct vexriscv_common *)target->arch_info;
}

struct vexriscv_core_reg {
	const char *name;
	uint32_t list_num;   /* Index in register cache */
	uint32_t spr_num;    /* Number in architecture's SPR space */
	uint32_t inHaltOnly;
	struct target *target;
	struct vexriscv_common *vexriscv_common;
};


struct vexriscv_core_reg_init {
	const char *name;
	uint32_t spr_num;    /* Number in architecture's SPR space */
	uint32_t inHaltOnly;
};


static struct vexriscv_core_reg *vexriscv_core_reg_list_arch_info;

/*
enum vexriscv_reg_nums {
	vexriscv_REG_R0 = 0,
	vexriscv_REG_R1,
	vexriscv_REG_R2,
	vexriscv_REG_R3,
	vexriscv_REG_R4,
	vexriscv_REG_R5,
	vexriscv_REG_R6,
	vexriscv_REG_R7,
	vexriscv_REG_R8,
	vexriscv_REG_R9,
	vexriscv_REG_R10,
	vexriscv_REG_R11,
	vexriscv_REG_R12,
	vexriscv_REG_R13,
	vexriscv_REG_R14,
	vexriscv_REG_R15,
	vexriscv_REG_R16,
	vexriscv_REG_R17,
	vexriscv_REG_R18,
	vexriscv_REG_R19,
	vexriscv_REG_R20,
	vexriscv_REG_R21,
	vexriscv_REG_R22,
	vexriscv_REG_R23,
	vexriscv_REG_R24,
	vexriscv_REG_R25,
	vexriscv_REG_R26,
	vexriscv_REG_R27,
	vexriscv_REG_R28,
	vexriscv_REG_R29,
	vexriscv_REG_R30,
	vexriscv_REG_R31,
	vexriscv_REG_PC
};*/

struct vexriscv_reg_mapping{
	struct reg x0;
	struct reg x1;
	struct reg x2;
	struct reg x3;
	struct reg x4;
	struct reg x5;
	struct reg x6;
	struct reg x7;
	struct reg x8;
	struct reg x9;
	struct reg x10;
	struct reg x11;
	struct reg x12;
	struct reg x13;
	struct reg x14;
	struct reg x15;
	struct reg x16;
	struct reg x17;
	struct reg x18;
	struct reg x19;
	struct reg x20;
	struct reg x21;
	struct reg x22;
	struct reg x23;
	struct reg x24;
	struct reg x25;
	struct reg x26;
	struct reg x27;
	struct reg x28;
	struct reg x29;
	struct reg x30;
	struct reg x31;
	struct reg pc;
};

static const struct vexriscv_core_reg_init vexriscv_init_reg_list[] = {
	{"x0"    	  , 0   + 0*4, FALSE},
	{"x1"	      , 0   + 1*4, FALSE},
	{"x2"	      , 0   + 2*4, FALSE},
	{"x3"	      , 0   + 3*4, FALSE},
	{"x4"	      , 0   + 4*4, FALSE},
	{"x5"	      , 0   + 5*4, FALSE},
	{"x6"	      , 0   + 6*4, FALSE},
	{"x7"	      , 0   + 7*4, FALSE},
	{"x8"	      , 0   + 8*4, FALSE},
	{"x9"	      , 0   + 9*4, FALSE},
	{"x10"	      , 0   + 10*4, FALSE},
	{"x11"	      , 0   + 11*4, FALSE},
	{"x12"	      , 0   + 12*4, FALSE},
	{"x13"	      , 0   + 13*4, FALSE},
	{"x14"	      , 0   + 14*4, FALSE},
	{"x15"	      , 0   + 15*4, FALSE},
	{"x16"	      , 0   + 16*4, FALSE},
	{"x17"	      , 0   + 17*4, FALSE},
	{"x18"	      , 0   + 18*4, FALSE},
	{"x19"	      , 0   + 19*4, FALSE},
	{"x20"	      , 0   + 20*4, FALSE},
	{"x21"	      , 0   + 21*4, FALSE},
	{"x22"	      , 0   + 22*4, FALSE},
	{"x23"	      , 0   + 23*4, FALSE},
	{"x24"	      , 0   + 24*4, FALSE},
	{"x25"	      , 0   + 25*4, FALSE},
	{"x26"	      , 0   + 26*4, FALSE},
	{"x27"	      , 0   + 27*4, FALSE},
	{"x28"	      , 0   + 28*4, FALSE},
	{"x29"	      , 0   + 29*4, FALSE},
	{"x30"	      , 0   + 30*4, FALSE},
	{"x31"	      , 0   + 31*4, FALSE},
	{"pc"       , 512 + 1*4, FALSE},
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


static int vexriscv_create_reg_list(struct target *target)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);

	LOG_DEBUG("-");		

	vexriscv_core_reg_list_arch_info = malloc(ARRAY_SIZE(vexriscv_init_reg_list) *
				       sizeof(struct vexriscv_core_reg));

	for (int i = 0; i < (int)ARRAY_SIZE(vexriscv_init_reg_list); i++) {
		vexriscv_core_reg_list_arch_info[i].name = vexriscv_init_reg_list[i].name;
		vexriscv_core_reg_list_arch_info[i].spr_num = vexriscv_init_reg_list[i].spr_num;
		vexriscv_core_reg_list_arch_info[i].inHaltOnly = vexriscv_init_reg_list[i].inHaltOnly;
		vexriscv_core_reg_list_arch_info[i].list_num = i;
		vexriscv_core_reg_list_arch_info[i].target = NULL;
		vexriscv_core_reg_list_arch_info[i].vexriscv_common = NULL;
	}

	vexriscv->nb_regs = ARRAY_SIZE(vexriscv_init_reg_list);


	return ERROR_OK;
}


static int vexriscv_target_create(struct target *target, Jim_Interp *interp)
{
	LOG_DEBUG("vexriscv_target_create\n");
	if (target->tap == NULL)
		return ERROR_FAIL;

	struct vexriscv_common *vexriscv = calloc(1, sizeof(struct vexriscv_common));
	target->arch_info = vexriscv;
	vexriscv->dbgBase = target->dbgbase;
	vexriscv->tap = target->tap;
	vexriscv->clientSocket = 0;
	vexriscv->readWaitCycles = 10;
	vexriscv_create_reg_list(target);


	return ERROR_OK;
}

int vexriscv_write_regfile(struct target* target, bool execute,uint32_t regId,uint32_t value){
	if(value & 0xFFFFF800){ //Require LUI
		uint32_t high = value & 0xFFFFF000, low = value & 0x00000FFF;
		if(low & 0x800){
			high += 0x1000;
		}
		if(low){ //require ADDI
			vexriscv_pushInstruction(target, false , 0x37 | (regId << 7) | high); //LUI regId, high
			return vexriscv_pushInstruction(target, execute , 0x13 | (regId << 7) | (regId << 15) | (low << 20));//ADDI regId, regId, low
		} else {
			return vexriscv_pushInstruction(target, execute , 0x37 | (regId << 7) | high); //LUI regId, high
		}
	}else {
		return vexriscv_pushInstruction(target,execute , 0x13 | (regId << 7) | (6 << 12) | (value << 20)); //ORI regId, x0, value
	}
}




static int vexriscv_get_core_reg(struct reg *reg)
{
	struct vexriscv_core_reg *vexriscv_reg = reg->arch_info;
	struct target *target = vexriscv_reg->target;

	if (vexriscv_reg->inHaltOnly && target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if(!reg->valid){
		if(reg->number < 32){
			return ERROR_FAIL;
		}else if(reg->number == 32){
			vexriscv_pushInstruction(target, false, 0x17); //AUIPC x0,0
			vexriscv_readInstructionResult(target, true, (uint32_t*)reg->value);
		}else{
			*((uint32_t*)reg->value) = 0xDEADBEEF;
		}

		reg->valid = true;
		reg->dirty = false;
	}

	return ERROR_OK;
}


static int vexriscv_set_core_reg(struct reg *reg, uint8_t *buf)
{
	struct vexriscv_core_reg *vexriscv_reg = reg->arch_info;
	struct target *target = vexriscv_reg->target;
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	uint32_t value = buf_get_u32(buf, 0, 32);

	if (vexriscv_reg->inHaltOnly && target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (vexriscv_reg->list_num >= vexriscv->nb_regs) {
		LOG_ERROR("ERROR, try to write unexisting CPU register");
		return ERROR_FAIL;
	}

	reg->dirty = 1;
	reg->valid = 1;
	buf_set_u32(reg->value, 0, 32, value);
	return ERROR_OK;
}

static const struct reg_arch_type vexriscv_reg_type = {
	.get = vexriscv_get_core_reg,
	.set = vexriscv_set_core_reg,
};

static struct reg_cache *vexriscv_build_reg_cache(struct target *target)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	struct reg_cache **cache_p = register_get_last_cache_p(&target->reg_cache);
	struct reg_cache *cache = malloc(sizeof(struct reg_cache));
	struct reg *reg_list = calloc(vexriscv->nb_regs, sizeof(struct reg));
	struct vexriscv_core_reg *arch_info =
		malloc((vexriscv->nb_regs) * sizeof(struct vexriscv_core_reg));



	LOG_DEBUG("-");

	/* Build the process context cache */
	cache->name = "VexRiscv registers";
	cache->next = NULL;
	cache->reg_list = reg_list;
	cache->num_regs = vexriscv->nb_regs;
	(*cache_p) = cache;
	vexriscv->core_cache = cache;
	vexriscv->arch_info = arch_info;
	assert(sizeof(struct reg)*vexriscv->nb_regs >= sizeof(struct vexriscv_reg_mapping));
	vexriscv->regs = (struct vexriscv_reg_mapping*)reg_list;

	for (uint32_t i = 0; i < vexriscv->nb_regs; i++) {
		arch_info[i] = vexriscv_core_reg_list_arch_info[i];
		arch_info[i].target = target;
		arch_info[i].vexriscv_common = vexriscv;
		reg_list[i].name = vexriscv_core_reg_list_arch_info[i].name;
		reg_list[i].feature = NULL;
		reg_list[i].group = NULL;
		reg_list[i].size = 32;
		reg_list[i].value = calloc(1, 4);
		reg_list[i].dirty = 0;
		reg_list[i].valid = 0;
		reg_list[i].type = &vexriscv_reg_type;
		reg_list[i].arch_info = &arch_info[i];
		reg_list[i].number = i;
		reg_list[i].exist = true;
	}

	return cache;
}

static void vexriscv_set_instr(struct jtag_tap *tap, uint32_t new_instr)
{
	struct scan_field field;

	field.num_bits = tap->ir_length;
	uint8_t *t = calloc(DIV_ROUND_UP(field.num_bits, 8), 1);
	field.out_value = t;
	buf_set_u32(t, 0, field.num_bits, new_instr);
	field.in_value = NULL;
	jtag_add_ir_scan(tap, &field, TAP_IDLE);
	free(t);
}

static void vexriscv_yaml_ignore_block(yaml_parser_t *parser){
	yaml_token_t  token;
	int32_t level = 0;
	while(1){
		yaml_parser_scan(parser, &token);
		switch(token.type){
		case YAML_BLOCK_SEQUENCE_START_TOKEN: level++; break;
		case YAML_BLOCK_ENTRY_TOKEN:          level++; break;
		case YAML_BLOCK_END_TOKEN:            level--; break;
		default: break;
		}

		if(level == -1)
			break;
	}
}


static void vexriscv_parse_busInfo(yaml_parser_t *parser, struct BusInfo *busInfo){
	yaml_token_t  token;
	busInfo->flushInstructions = NULL;
	while(1){
		yaml_parser_scan(parser, &token);
		switch(token.type){
			case YAML_SCALAR_TOKEN:
				if(strcmp((char*)token.data.scalar.value,"flushInstructions") == 0){
					busInfo->flushInstructions = malloc(4*4096);
					busInfo->flushInstructionsSize = 0;
					while(1){
						yaml_parser_scan(parser, &token);
						switch(token.type){
							case YAML_SCALAR_TOKEN:
								busInfo->flushInstructions[busInfo->flushInstructionsSize] = atoi((char*)token.data.scalar.value);
								busInfo->flushInstructionsSize++;
								assert(busInfo->flushInstructionsSize <= 4096);
								break;
							default: break;
						}
						if(token.type == YAML_FLOW_SEQUENCE_END_TOKEN)
							break;
					}
				}
			break;
			default: break;
		}
		if(busInfo->flushInstructions != NULL)
			break;
	}
}

static int vexriscv_parse_cpu_file(struct command_context *cmd_ctx, struct target *target){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	yaml_parser_t parser;
	yaml_token_t  token;
	int done = 0;
	yaml_parser_initialize(&parser);

	FILE *input = fopen(vexriscv->cpuConfigFile, "rb");
	if(!input){
		LOG_ERROR("cpuConfigFile %s not found", vexriscv->cpuConfigFile);
		goto error;
	}

	yaml_parser_set_input_file(&parser, input);
	/* Read the event sequence. */
	while (!done) {

		/* Get the next event. */
		if (!yaml_parser_scan(&parser, &token))
			goto error;

		switch(token.type){
			case YAML_SCALAR_TOKEN:
				if(strcmp((char*)token.data.scalar.value,"iBus") == 0){
					vexriscv->iBus = malloc(sizeof(struct BusInfo));
					vexriscv_parse_busInfo(&parser, vexriscv->iBus);
				}
				if(strcmp((char*)token.data.scalar.value,"dBus") == 0){
					vexriscv->dBus = malloc(sizeof(struct BusInfo));
					vexriscv_parse_busInfo(&parser, vexriscv->dBus);
				}
				break;
			case YAML_BLOCK_ENTRY_TOKEN: vexriscv_yaml_ignore_block(&parser); break;
			default: break;
		}


		/* The application is responsible for destroying the event object. */

	    if(token.type != YAML_STREAM_END_TOKEN)
	      yaml_token_delete(&token);
	    else
	    	done = 1;

	}

	/* Destroy the Parser object. */
	yaml_parser_delete(&parser);
	return ERROR_OK;

	/* On error. */
	error:

	/* Destroy the Parser object. */
	yaml_parser_delete(&parser);

	return ERROR_FAIL;
}

static int vexriscv_init_target(struct command_context *cmd_ctx, struct target *target)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	LOG_DEBUG("vexriscv_init_target\n");
	LOG_DEBUG("%s", __func__);

	vexriscv->iBus = NULL;
	vexriscv->dBus = NULL;
	if(vexriscv_parse_cpu_file(cmd_ctx, target))
		return ERROR_FAIL;

	vexriscv_build_reg_cache(target);

	vexriscv->useTCP = 0;
	struct command *command = cmd_ctx->commands;
	while(command != NULL){
		if(strcmp(command->name,"dummy") == 0){
			vexriscv->useTCP = 1;
		}
		command = command->next;
	}
	if(vexriscv->useTCP){
		struct sockaddr_in serverAddr;
		//---- Create the socket. The three arguments are: ----//
		// 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) //
		vexriscv->clientSocket = socket(PF_INET, SOCK_STREAM, 0);
		int flag = 1;
		setsockopt(  vexriscv->clientSocket,            /* socket affected */
					 IPPROTO_TCP,     /* set option at TCP level */
					 TCP_NODELAY,     /* name of option */
					 (char *) &flag,  /* the cast is historical
											 cruft */
					 sizeof(int));    /* length of option value */

		//---- Configure settings of the server address struct ----//
		// Address family = Internet //
		serverAddr.sin_family = AF_INET;
		// Set port number, using htons function to use proper byte order //
		serverAddr.sin_port = htons(7893);
		// Set IP address to localhost //
		serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		// Set all bits of the padding field to 0 //
		memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

		//---- Connect the socket to the server using the address struct ----//
		socklen_t addr_size = sizeof serverAddr;
		if(connect(vexriscv->clientSocket, (struct sockaddr *) &serverAddr, addr_size) != 0){
			LOG_DEBUG("Can't connect to debug server");
			return ERROR_FAIL;
		} else {
			LOG_DEBUG("TCP connection to target etablished");
		}
	}

	return ERROR_OK;
}

static int vexriscv_arch_state(struct target *target)
{
	LOG_DEBUG("vexriscv_arch_state\n");
	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}


static int vexriscv_is_running(struct target * target,uint32_t *running){
	uint32_t flags;
	int error;
	if((error = vexriscv_readStatusRegister(target, true, &flags)) != ERROR_OK){
		LOG_ERROR("Error while calling vexriscv_is_cpu_running");
		return error;
	}
	*running = (flags & vexriscv_FLAGS_PIP_BUSY) || !(flags & vexriscv_FLAGS_HALT);

	return ERROR_OK;
}

static int vexriscv_flush_bus(struct target *target,struct BusInfo * busInfo){
	int error;
	if(!busInfo) return ERROR_OK;
	for(uint32_t idx = 0;idx < busInfo->flushInstructionsSize;idx++){
		vexriscv_pushInstruction(target, false, busInfo->flushInstructions[idx]);
	}
	if((error = jtag_execute_queue()) != ERROR_OK)
		return error;
	while(1){
		uint32_t running;
		if((error = vexriscv_is_running(target,&running)) != ERROR_OK)
			return error;
		if(!running)
			break;
	}
	return ERROR_OK;
}

static int vexriscv_flush_caches(struct target *target)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	int error;
	if((error = vexriscv_flush_bus(target,vexriscv->iBus)) != ERROR_OK)
		return error;
	if((error = vexriscv_flush_bus(target,vexriscv->dBus)) != ERROR_OK)
		return error;
	return ERROR_OK;
}

static int vexriscv_save_context(struct target *target)
{
	int error;
	LOG_DEBUG("-");
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);


	uint32_t flags;
	if((error = vexriscv_readStatusRegister(target, true, &flags)) != ERROR_OK)
		return error;

	//get PC in case of breakpoint before losing the value
	if(flags & vexriscv_FLAGS_HALTED_BY_BREAK){
		struct reg* reg = &vexriscv->regs->pc;
		vexriscv_readInstructionResult(target, false, (uint32_t*)reg->value);
		reg->valid = 1;
		reg->dirty = 1;
	}

	for(uint32_t regId = 0;regId < 32;regId++){
		struct reg* reg = &vexriscv->core_cache->reg_list[regId];
		vexriscv_pushInstruction(target, false, 0x13 | (reg->number << 15)); //ADDI x0, x?, 0
		vexriscv_readInstructionResult(target, false, (uint32_t*)reg->value);
		reg->valid = 1;
		reg->dirty = reg->number == 1 ? 1 : 0; //For safety, invalidate x1 for debugger purposes
	}

	//Flush commands
	if(jtag_execute_queue())
		return ERROR_FAIL;

//	if((error = vexriscv_flush_caches(target)) != ERROR_OK) //Flush instruction cache
//		return error;

	return ERROR_OK;
}



static int vexriscv_restore_context(struct target *target)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	LOG_DEBUG("-");

	//PC
	if(vexriscv->regs->pc.valid && vexriscv->regs->pc.dirty){
		vexriscv_write_regfile(target, false, 1,*((uint32_t*)vexriscv->regs->pc.value));
		vexriscv_pushInstruction(target, false, 0x67 | (1 << 15)); //JALR x1

		vexriscv->regs->pc.valid = false;
		vexriscv->regs->pc.dirty = false;
	}

	for(uint32_t i = 0;i < 32;i++){
		struct reg *reg = vexriscv->core_cache->reg_list + i;
		if(reg->valid && reg->dirty){
			vexriscv_write_regfile(target, false, i,*((uint32_t*)reg->value));
			reg->valid = false;
			reg->dirty = false;
		}
	}

	return jtag_execute_queue();
}


static int vexriscv_debug_entry(struct target *target)
{
	int error;
	LOG_DEBUG("-");


	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_SET)) != ERROR_OK) {
		LOG_ERROR("Impossible to stall the CPU");
		return error;
	}

	if ((error = vexriscv_save_context(target)) != ERROR_OK) {
		LOG_ERROR("Error while calling vexriscv_save_context");
		return error;
	}

	//YY Flush caches
	return ERROR_OK;
}

static int vexriscv_halt(struct target *target)
{
	int error;
	LOG_DEBUG("target->state: %s",target_state_name(target));

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

	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_SET)) != ERROR_OK) {
		LOG_ERROR("Impossible to stall the CPU");
		return error;
	}

	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}


static int vexriscv_poll(struct target *target)
{
	int retval;

	uint32_t running;
	retval = vexriscv_is_running(target,&running);
	if (retval != ERROR_OK) {
		return retval;
	}

	/* check for processor halted */
	if (!running) {
		/* It's actually stalled, so update our software's state */
		if ((target->state == TARGET_RUNNING) ||
		    (target->state == TARGET_RESET)) {

			target->state = TARGET_HALTED;

			retval = vexriscv_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling vexriscv_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,TARGET_EVENT_HALTED);
		} else if (target->state == TARGET_DEBUG_RUNNING) {
			target->state = TARGET_HALTED;

			retval = vexriscv_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling vexriscv_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,TARGET_EVENT_DEBUG_HALTED);
		}
	} else { /* ... target is running */

		/* If target was supposed to be stalled, stall it again */
		/*if  (target->state == TARGET_HALTED) {

			target->state = TARGET_RUNNING;

			retval = vexriscv_halt(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling vexriscv_halt");
				return retval;
			}

			retval = vexriscv_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling vexriscv_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,
						    TARGET_EVENT_DEBUG_HALTED);
		}

		target->state = TARGET_RUNNING;
*/
	}

	return ERROR_OK;
}

static int vexriscv_assert_reset(struct target *target)
{
	int error;
	LOG_DEBUG("vexriscv_assert_reset\n");
	target->state = TARGET_RESET;

	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_SET)) != ERROR_OK) {
		return error;
	}

	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_SET | vexriscv_FLAGS_RESET_SET)) != ERROR_OK) {
		return error;
	}

	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int vexriscv_deassert_reset(struct target *target)
{
	int error;
	LOG_DEBUG("vexriscv_deassert_reset\n");

	if ((error = vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_RESET_CLEAR)) != ERROR_OK) {
		return error;
	}
	uint32_t isRunning;
	if(vexriscv_is_running(target,&isRunning)) return ERROR_FAIL;
	target->state = isRunning ? TARGET_RUNNING : TARGET_HALTED;

	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}



static void vexriscv_memory_cmd(struct target *target, uint32_t address,uint32_t data,int32_t size, int read)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	struct jtag_tap *tap = target->tap;
	struct scan_field field;
	uint8_t cmd[10];

	if(!vexriscv->useTCP) vexriscv_set_instr(tap, 0x2);

	uint8_t inst = 0x00;
	switch(size){
	case 1:
		size = 0;
		data &= 0xFF;
		data = data | (data<<8)  | (data<<16)  | (data<<24);
		break;
	case 2:
		size = 1;
		data &= 0xFFFF;
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
    uint32_t waitCycles = 0;
	field.num_bits = 8+32+32+1+2 + waitCycles;
	field.out_value = cmd;
	bit_copy(cmd,0,&inst,0,8);
	bit_copy(cmd,8 + waitCycles,(uint8_t*)&address,0,32);
	bit_copy(cmd,40 + waitCycles,(uint8_t*)&data,0,32);
	bit_copy(cmd,72 + waitCycles,&write,0,1);
	bit_copy(cmd,73 + waitCycles,(uint8_t*)&size,0,2);
	field.in_value = NULL;
	field.check_value = NULL;
	field.check_mask = NULL;
	if(!vexriscv->useTCP)
		jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
	else {
		uint8_t buffer[10];
		buffer[0] = read ? 0 : 1;
		buffer[1] = size;
		*((uint32_t*) (buffer + 2)) = address;
		*((uint32_t*) (buffer + 6)) = data;
		send(vexriscv->clientSocket,buffer,10,0);
	}
}

static void vexriscv_read_rsp(struct target *target,uint8_t *value, uint32_t size)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	struct jtag_tap *tap = target->tap;
	struct scan_field feilds[3];
	feilds[0].num_bits = 2; //TODO !!!
	feilds[0].out_value = NULL;
	feilds[0].in_value = NULL;
	feilds[0].check_value = NULL;
	feilds[0].check_mask = NULL;

	feilds[1].num_bits = 8*size;
	feilds[1].out_value = NULL;
	feilds[1].in_value = (uint8_t*)value;
	feilds[1].check_value = NULL;
	feilds[1].check_mask = NULL;

	feilds[2].num_bits = 32-8*size;
	feilds[2].out_value = NULL;
	feilds[2].in_value = NULL;
	feilds[2].check_value = NULL;
	feilds[2].check_mask = NULL;

	if(!vexriscv->useTCP) {
		jtag_add_clocks(vexriscv->readWaitCycles);
		vexriscv_set_instr(tap, 0x03);
		jtag_add_dr_scan(tap, size == 4 ? 2 : 3, feilds, TAP_IDLE);
	} else {
		uint32_t buffer;
		if(recv(vexriscv->clientSocket, &buffer, 4, 0) == 4){
			//value[0] = 1;
			//bit_copy(value,2,(uint8_t *) &buffer,0,32);
			bit_copy(value,0,(uint8_t *) &buffer,0,8*size);
		} else{
			LOG_ERROR("???");
			value[0] = 0;
		}
	}
}

static int vexriscv_read_memory(struct target *target, target_addr_t address,
			       uint32_t size, uint32_t count, uint8_t *buffer)
{
	/*LOG_DEBUG("Reading memory at physical address 0x%" PRIx32
		  "; size %" PRId32 "; count %" PRId32, address, size, count);*/

	assert(target->state == TARGET_HALTED);
	if (count == 0 || buffer == NULL)
		return ERROR_COMMAND_SYNTAX_ERROR;

	for(uint32_t idx = 0;idx < count;idx++){
		vexriscv_write_regfile(target, false, 1, address);

		switch(size){
		case 4:
			((uint32_t*)buffer)[0] = 0;
			vexriscv_pushInstruction(target, false, (1 << 15) | (0x2 << 12) | (1 << 7) | 0x3); //LW x1, 0(x1)
			vexriscv_readInstructionResult(target, false, (uint32_t*)buffer);
			break;
		case 2:
			((uint16_t*)buffer)[0] = 0;
			vexriscv_pushInstruction(target, false, (1 << 15) | (0x5 << 12) | (1 << 7) | 0x3); //LHU x1, 0(x1)
			vexriscv_readInstructionResult16(target, false, (uint16_t*)buffer);
			break;
		case 1:
			((uint8_t*)buffer)[0] = 0;
			vexriscv_pushInstruction(target, false, (1 << 15) | (0x4 << 12) | (1 << 7) | 0x3); //LBU x1, 0(x1)
			vexriscv_readInstructionResult8(target, false, (uint8_t*)buffer);
			break;
		}
		buffer += size;
		address += size;
	}

	return jtag_execute_queue();
}


struct vexriscv_mem_access{
	uint32_t address;
	uint32_t data;
};

int vexriscv_mem_access_comp (const void * elem1, const void * elem2)
{
	uint32_t f = ((struct vexriscv_mem_access*)elem1)->data;
	uint32_t s = ((struct vexriscv_mem_access*)elem2)->data;
    return (f > s) - (f < s);
}

static int vexriscv_write_memory(struct target *target, target_addr_t address,
				uint32_t size, uint32_t count,
				const uint8_t *buffer)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	//LOG_DEBUG("Writing memory at physical address 0x%" PRIx32
	//	  "; size %" PRId32 "; count %" PRId32, (uint32_t)address, size, count);

	assert(target->state == TARGET_HALTED);

	if(size == 4 && count > 4){
		//use 4 address registers over a range of 16K in order to reduce JTAG usage
		int maxAddressReg = 4;
		uint32_t numAddressReg = MIN(maxAddressReg, (count * size - 1) / 4096 + 1);
		if(count * size > 4096*numAddressReg){
			if(vexriscv_write_memory(target,address,size,numAddressReg*4096/size,buffer)) return ERROR_FAIL;
			if(vexriscv_write_memory(target,address+4096*numAddressReg,size,count-4096/size*numAddressReg,buffer+4096*numAddressReg))  return ERROR_FAIL;
			return ERROR_OK;
		}

		if (count == 0 || buffer == NULL)
			return ERROR_COMMAND_SYNTAX_ERROR;


		struct vexriscv_mem_access accesses[count];
		for(uint32_t accessId = 0;accessId < count;accessId++){
			accesses[accessId].address = address + accessId*size;
			accesses[accessId].data = ((uint32_t*)buffer)[accessId];
		}
		//Sort access by data value
		qsort (accesses, sizeof(accesses)/sizeof(*accesses), sizeof(*accesses), vexriscv_mem_access_comp);


		vexriscv->regs->x1.dirty = 1;
		vexriscv->regs->x2.dirty = 1;
		for(uint32_t i = 0;i < numAddressReg;i++){
			vexriscv->core_cache->reg_list[i+3].dirty = 1;
			vexriscv_write_regfile(target, false, i + 3, address + 2048 + 4096*i);
		}

		uint32_t x1Value = (accesses[0].data + 2048) & 0xFFFFF000;
		uint32_t x2Value = accesses[0].data;
		vexriscv_write_regfile(target, false, 1, x1Value);
		vexriscv_pushInstruction(target, false , 0x13 | (2 << 7) | (1 << 15) | ((x2Value - x1Value) << 20));//ADDI x2, x1, -2048

		uint32_t saved = 0;
		for(uint32_t accessId = 0;accessId < count;accessId++){
			struct vexriscv_mem_access access = accesses[accessId];
			uint32_t addressReg = ((access.address - address) >> 12) + 3;
			int32_t storeOffset =  ((access.address - address) & 0xFFF) - 2048;

			if(x1Value + 2047 < access.data){
				x1Value = (access.data + 2048) & 0xFFFFF000;
				vexriscv_write_regfile(target, false, 1, x1Value);
			} else
				saved++;

			if(x2Value != access.data){
				vexriscv_pushInstruction(target, false , 0x13 | (2 << 7) | (1 << 15) | ((access.data - x1Value) << 20));//ADDI x2, x1, delta
				x2Value = access.data;
			}else
				saved++;

			vexriscv_pushInstruction(target, false, ((storeOffset & 0xFE0) << 20) | (2 << 20) | (addressReg << 15) | (0x2 << 12) | ((storeOffset & 0x1F) << 7) | 0x23); //SW x2,storeOffset(xAddressReg)
		}
		LOG_DEBUG("SAVED : %x\n",saved);

		//Easy way
		/*for(uint32_t accessId = 0;accessId < count;accessId++){
			uint32_t accessAddress = address + accessId*size;
			uint32_t addressReg = ((accessAddress - address) >> 12) + 3;
			int32_t storeOffset =  ((accessAddress - address) & 0xFFF) - 2048;
			vexriscv_write_regfile(target, false, 1,*((uint32_t*)buffer));
			vexriscv_pushInstruction(target, false, ((storeOffset & 0xFE0) << 20) | (1 << 20) | (addressReg << 15) | (0x2 << 12) | ((storeOffset & 0x1F) << 7) | 0x23); //SW x1,storeOffset(xAddressReg)
			buffer += size;
		}*/
	} else {
		//Generic but slow way
		vexriscv->regs->x1.dirty = 1;
		vexriscv->regs->x2.dirty = 1;
		while (count--) {
			switch(size){
			case 4:
				vexriscv_write_regfile(target, false, 1,*((uint32_t*)buffer));
				vexriscv_write_regfile(target, false, 2,address);
				vexriscv_pushInstruction(target, false, (1 << 20) | (2 << 15) | (0x2 << 12) | 0x23); //SW x1,0(x2)
				break;
			case 2:
				vexriscv_write_regfile(target, false, 1,*((uint16_t*)buffer));
				vexriscv_write_regfile(target, false, 2,address);
				vexriscv_pushInstruction(target, false, (1 << 20) | (2 << 15) | (0x1 << 12) | 0x23); //SH x1,0(x2)
				break;
			case 1:
				vexriscv_write_regfile(target, false, 1,*((uint8_t*)buffer));
				vexriscv_write_regfile(target, false, 2,address);
				vexriscv_pushInstruction(target, false, (1 << 20) | (2 << 15) | (0x0 << 12) | 0x23); //SB x1,0(x2)
				break;
			}

			address += size;
			buffer += size;
		}
	}
	if(jtag_execute_queue())
		return ERROR_FAIL;
	return ERROR_OK;
}


static int vexriscv_pushInstruction(struct target *target, bool execute, uint32_t instruction){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 4,instruction,4, 0);
	return execute ? jtag_execute_queue() : 0;
}


static int vexriscv_writeStatusRegister(struct target *target, bool execute, uint32_t value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase, value, 4, 0);
	return execute ? jtag_execute_queue() : 0;
}

static int vexriscv_readStatusRegister(struct target *target, bool execute, uint32_t *value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase,0, 4, 1);
	vexriscv_read_rsp(target,(uint8_t*)value, 4);
	return execute ? jtag_execute_queue() : 0;
}

static int vexriscv_readInstructionResult(struct target *target, bool execute, uint32_t *value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 4,0, 4, 1);
	vexriscv_read_rsp(target,(uint8_t*)value, 4);
	return execute ? jtag_execute_queue() : 0;
}

static int vexriscv_readInstructionResult16(struct target *target, bool execute, uint16_t *value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 4,0, 4, 1);
	vexriscv_read_rsp(target,(uint8_t*)value, 2);
	return execute ? jtag_execute_queue() : 0;
}

static int vexriscv_readInstructionResult8(struct target *target, bool execute, uint8_t *value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 4,0, 4, 1);
	vexriscv_read_rsp(target,(uint8_t*)value, 1);
	return execute ? jtag_execute_queue() : 0;
}


static int vexriscv_write32(struct target *target, uint32_t address,uint32_t data){
	return vexriscv_write_memory(target,address,4,1,(uint8_t*)&data);
}


static int vexriscv_read32(struct target *target, uint32_t address,uint32_t *data){
	return vexriscv_read_memory(target,address,4,1,(uint8_t*)data);
}



static int vexriscv_get_gdb_reg_list(struct target *target, struct reg **reg_list[],
			  int *reg_list_size, enum target_register_class reg_class)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	LOG_DEBUG("vexriscv_get_gdb_reg_list %d\n",reg_class);
	if (reg_class == REG_CLASS_GENERAL) {
		*reg_list_size = vexriscv->nb_regs;
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));

		for (uint32_t i = 0; i < vexriscv->nb_regs; i++)
			(*reg_list)[i] = &vexriscv->core_cache->reg_list[i];
	} else {
		*reg_list_size = vexriscv->nb_regs;
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));
		
		for (uint32_t i = 0; i < vexriscv->nb_regs; i++)
			(*reg_list)[i] = &vexriscv->core_cache->reg_list[i];
	}

	return ERROR_OK;

}

static int vexriscv_add_breakpoint(struct target *target,
			       struct breakpoint *breakpoint)
{
	uint32_t data;

	LOG_DEBUG("Adding breakpoint: addr 0x%08" PRIx32 ", len %d, type %d, set: %d, id: %" PRId32,
		  (uint32_t)breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

	/* Only support SW breakpoints for now. */
	if (breakpoint->type == BKPT_HARD)
		LOG_ERROR("HW breakpoints not supported for now. Doing SW breakpoint.");

	/* Read and save the instruction */
	int retval = vexriscv_read32(target,
					 breakpoint->address,
					 &data);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while reading the instruction at 0x%08" PRIx32,
				(uint32_t)breakpoint->address);
		return retval;
	}

	if (breakpoint->orig_instr != NULL)
		free(breakpoint->orig_instr);

	breakpoint->orig_instr = malloc(4);
	memcpy(breakpoint->orig_instr, &data, 4);

	/* Sub in the vexriscv trap instruction */
	retval = vexriscv_write32(target,
					  breakpoint->address,
					  vexriscv_BREAK_INST);

	if (retval != ERROR_OK) {
		LOG_ERROR("Error while writing vexriscv_TRAP_INSTR at 0x%08" PRIx32,
				(uint32_t)breakpoint->address);
		return retval;
	}

	/* TODO invalidate instruction cache */

	return ERROR_OK;
}

static int vexriscv_remove_breakpoint(struct target *target,
				  struct breakpoint *breakpoint)
{
	LOG_DEBUG("Removing breakpoint: addr 0x%08" PRIx32 ", len %d, type %d, set: %d, id: %" PRId32,
			(uint32_t)breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

	/* Only support SW breakpoints for now. */
	if (breakpoint->type == BKPT_HARD)
		LOG_ERROR("HW breakpoints not supported for now. Doing SW breakpoint.");

	/* Replace the removed instruction */
	int retval = vexriscv_write32(target,
					  breakpoint->address,
					  *((uint32_t*)breakpoint->orig_instr));

	if (retval != ERROR_OK) {
		LOG_ERROR("Error while writing back the instruction at 0x%08" PRIx32,
				(uint32_t)breakpoint->address);
		return retval;
	}

	/* TODO invalidate instruction cache */

	return ERROR_OK;
}

//TODO look like instruction step when branch is strange
static int vexriscv_resume_or_step(struct target *target, int current,
			       uint32_t address, int handle_breakpoints,
			       int debug_execution, int step)
{

	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	struct breakpoint *breakpoint = NULL;
	int retval;

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
		*((uint32_t*)vexriscv->regs->pc.value) = address;
		vexriscv->regs->pc.valid = true;
		vexriscv->regs->pc.dirty = true;
	}



	/* The front-end may request us not to handle breakpoints */
	if (handle_breakpoints) {
		/* Single step past breakpoint at current address */
		breakpoint = breakpoint_find(target, *((uint32_t*)vexriscv->regs->pc.value));
		if (breakpoint) {
			LOG_DEBUG("Unset breakpoint at 0x%08" PRIx32, (uint32_t) breakpoint->address);
			retval = vexriscv_remove_breakpoint(target, breakpoint);
			if (retval != ERROR_OK)
				return retval;
		}
	}


	vexriscv_flush_caches(target);

	if ((retval = vexriscv_restore_context(target))){
		LOG_ERROR("Error while calling vexriscv_restore_context");
		return retval;
	}

	/* Unstall */
	if ((retval = vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_CLEAR | (step ? vexriscv_FLAGS_STEP : 0))) != ERROR_OK) {
		LOG_ERROR("Error while unstalling the CPU");
		return retval;
	}


	if (step)
		target->debug_reason = DBG_REASON_SINGLESTEP;
	else
		target->debug_reason = DBG_REASON_NOTHALTED;

	/* Registers are now invalid */
	register_cache_invalidate(vexriscv->core_cache);

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		LOG_DEBUG("Target resumed at 0x%08" PRIx32, *((uint32_t*)vexriscv->regs->pc.value));
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		LOG_DEBUG("Target debug resumed at 0x%08" PRIx32, *((uint32_t*)vexriscv->regs->pc.value));
	}

	return ERROR_OK;
}

static int vexriscv_resume(struct target *target, int current,
		target_addr_t address, int handle_breakpoints, int debug_execution)
{
	return vexriscv_resume_or_step(target, current, address,
				   handle_breakpoints,
				   debug_execution,
				   NO_SINGLE_STEP);
}

static int vexriscv_step(struct target *target, int current,
		target_addr_t address, int handle_breakpoints)
{
	return vexriscv_resume_or_step(target, current, address,
				   handle_breakpoints,
				   0,
				   SINGLE_STEP);

}

static int vexriscv_examine(struct target *target)
{
	LOG_DEBUG("vexriscv_examine");
	/*struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	struct reg *reg_list = calloc(vexriscv->nb_regs, sizeof(struct reg));

	for (int i = 0; i < vexriscv->nb_regs; i++) {
		reg_list[i].dirty = 0;
		reg_list[i].valid = 0;
	}*/


	if (!target_was_examined(target)) {

		target_set_examined(target);
		//Soft reset
		vexriscv_assert_reset(target);
		vexriscv_deassert_reset(target);


		uint32_t running;
		int retval = vexriscv_is_running(target,&running);

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

static int vexriscv_soft_reset_halt(struct target *target)
{
	int error;
	LOG_DEBUG("-");


	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_SET)) != ERROR_OK) {
		LOG_ERROR("Error while soft_reset_halt the CPU");
		return error;
	}
	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_RESET_SET)) != ERROR_OK) {
		LOG_ERROR("Error while soft_reset_halt the CPU");
		return error;
	}
	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_RESET_CLEAR)) != ERROR_OK) {
		LOG_ERROR("Error while soft_reset_halt the CPU");
		return error;
	}

	target->state = TARGET_HALTED;
	return ERROR_OK;
}


static int vexriscv_add_watchpoint(struct target *target,
			       struct watchpoint *watchpoint)
{
	LOG_ERROR("%s: implement me", __func__);
	return ERROR_OK;
}

static int vexriscv_remove_watchpoint(struct target *target,
				  struct watchpoint *watchpoint)
{
	LOG_ERROR("%s: implement me", __func__);
	return ERROR_OK;
}


COMMAND_HANDLER(vexriscv_handle_readWaitCycles_command)
{
	if(CMD_ARGC != 1)
		return ERROR_COMMAND_ARGUMENT_INVALID;
	struct target* target = get_current_target(CMD_CTX);
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], vexriscv->readWaitCycles);
	return ERROR_OK;
}

COMMAND_HANDLER(vexriscv_handle_cpuConfigFile_command)
{
	if(CMD_ARGC != 1)
		return ERROR_COMMAND_ARGUMENT_INVALID;
	struct target* target = get_current_target(CMD_CTX);
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv->cpuConfigFile = strdup(CMD_ARGV[0]);
	return ERROR_OK;
}

static const struct command_registration vexriscv_exec_command_handlers[] = {
		{
			.name = "readWaitCycles",
			.handler = vexriscv_handle_readWaitCycles_command,
			.mode = COMMAND_CONFIG,
			.help = "Number of JTAG cycle to wait before getting jtag read responses",
			.usage = "value",
		},{
			.name = "cpuConfigFile",
			.handler = vexriscv_handle_cpuConfigFile_command,
			.mode = COMMAND_CONFIG,
			.help = "Path to the autogenerated configuration file",
			.usage = "filePath",
		},
	COMMAND_REGISTRATION_DONE
};

const struct command_registration vexriscv_command_handlers[] = {
	{
		.name = "vexriscv",
		.mode = COMMAND_ANY,
		.help = "vexriscv command group",
		.usage = "",
		.chain = vexriscv_exec_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};

struct target_type vexriscv_target = {
	.name = "vexriscv",

	.target_create = vexriscv_target_create,
	.init_target = vexriscv_init_target,
	.examine = vexriscv_examine,

	.poll = vexriscv_poll,
	.arch_state = vexriscv_arch_state,
	.get_gdb_reg_list = vexriscv_get_gdb_reg_list,

	.halt = vexriscv_halt,
	.resume = vexriscv_resume,
	.step = vexriscv_step,

	.add_breakpoint = vexriscv_add_breakpoint,
	.remove_breakpoint = vexriscv_remove_breakpoint,
	.add_watchpoint = vexriscv_add_watchpoint,
	.remove_watchpoint = vexriscv_remove_watchpoint,

	.commands = vexriscv_command_handlers,

	.assert_reset = vexriscv_assert_reset,
	.deassert_reset = vexriscv_deassert_reset,
	.soft_reset_halt = vexriscv_soft_reset_halt,

	.read_memory = vexriscv_read_memory,
	.write_memory = vexriscv_write_memory,
};
