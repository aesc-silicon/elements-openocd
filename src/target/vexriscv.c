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
#include "semihosting_common.h"
#include <stdio.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#endif
#include <string.h>
#include <fcntl.h>
#include <yaml.h>
#include <errno.h>
#include "algorithm.h"

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

enum network_protocol{
	NP_IVERILOG,
	NP_ETHERBONE,
};

struct vexriscv_common {
	struct jtag_tap *tap;
	struct reg_cache *core_cache;
	struct vexriscv_reg_mapping *regs;
	uint32_t nb_regs;
	uint32_t largest_csr;
	struct vexriscv_core_reg *arch_info;
	uint32_t dbgBase;
	int clientSocket;
	int useTCP;
	uint32_t readWaitCycles;
	char* cpuConfigFile;
	char *targetAddress;
	enum network_protocol networkProtocol;
	struct BusInfo* iBus, *dBus;
	int hardwareBreakpointsCount;
	bool *hardwareBreakpointUsed;
	uint32_t bridgeInstruction;
    uint32_t jtagRspInstruction;
    uint32_t jtagRspHeader;
    uint32_t jtagRspHeaderSize;
    uint32_t jtagCmdInstruction;
    uint32_t jtagCmdHeader;
    uint32_t jtagCmdHeaderSize;
};

static inline struct vexriscv_common *
target_to_vexriscv(struct target *target)
{
	return (struct vexriscv_common *)target->arch_info;
}

struct vexriscv_core_reg {
	const char *name;
	uint32_t list_num;   /* Index in register cache */
	uint32_t csr_num;    /* Number in architecture's SPR space */
	uint32_t is_csr;     /* False for x0, x1, etc. */
	uint32_t inHaltOnly;
	struct target *target;
	struct vexriscv_common *vexriscv_common;
};


static struct vexriscv_core_reg *vexriscv_core_reg_list_arch_info;

struct vexriscv_reg_mapping {
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

#include "vexriscv-csrs.h"

static int vexriscv_semihosting_setup(struct target *target, int enable);
static int vexriscv_semihosting_post_result(struct target *target);

/**
 * Initialize RISC-V semihosting. Use common ARM code.
 */
void vexriscv_semihosting_init(struct target *target)
{
	semihosting_common_init(target, vexriscv_semihosting_setup,
		vexriscv_semihosting_post_result);
}





static int vexriscv_create_reg_list(struct target *target)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv->largest_csr = 0;

	unsigned int i;

	// GDB CSR numbers are offset by 65.  That is, Risc-V CSR0 is
	// GDB register number 65.
	for (i = 0; i < ARRAY_SIZE(vexriscv_init_reg_list); i++)
		if (vexriscv_init_reg_list[i].is_csr && (vexriscv_init_reg_list[i].csr_num > vexriscv->largest_csr))
			vexriscv->largest_csr = vexriscv_init_reg_list[i].csr_num;
	vexriscv->largest_csr += 65;

	vexriscv_core_reg_list_arch_info = malloc((vexriscv->largest_csr+1) *
				       sizeof(struct vexriscv_core_reg));
	memset(vexriscv_core_reg_list_arch_info, 0, (vexriscv->largest_csr+1) *
				       sizeof(struct vexriscv_core_reg));

	for (i = 0; i < (int)ARRAY_SIZE(vexriscv_init_reg_list); i++) {
		int gdb_reg_num = i;

		// Offset the CSR register numbers by 65 in the array.
		if (vexriscv_init_reg_list[i].is_csr)
			gdb_reg_num = 65 + vexriscv_init_reg_list[i].csr_num;

		vexriscv_core_reg_list_arch_info[gdb_reg_num].name = vexriscv_init_reg_list[i].name;

		// csr_num is the value that's used for instruction encoding.
		vexriscv_core_reg_list_arch_info[gdb_reg_num].csr_num = vexriscv_init_reg_list[i].csr_num;

		vexriscv_core_reg_list_arch_info[gdb_reg_num].is_csr = vexriscv_init_reg_list[i].is_csr;
		vexriscv_core_reg_list_arch_info[gdb_reg_num].inHaltOnly = vexriscv_init_reg_list[i].inHaltOnly;
		vexriscv_core_reg_list_arch_info[gdb_reg_num].list_num = i;
		vexriscv_core_reg_list_arch_info[gdb_reg_num].target = NULL;
		vexriscv_core_reg_list_arch_info[gdb_reg_num].vexriscv_common = NULL;
	}

	vexriscv->nb_regs = vexriscv->largest_csr;


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


    vexriscv->jtagCmdInstruction = 2;
    vexriscv->jtagRspInstruction = 3;
    vexriscv->jtagCmdHeader = 0;
    vexriscv->jtagRspHeader = 0;
    vexriscv->jtagCmdHeaderSize = 0;
    vexriscv->jtagRspHeaderSize = 0;


	vexriscv->targetAddress = "127.0.0.1";
	vexriscv->networkProtocol = NP_IVERILOG;
	vexriscv_create_reg_list(target);
	vexriscv->hardwareBreakpointsCount = 0;
	vexriscv->bridgeInstruction = -1;


	return ERROR_OK;
}

static int vexriscv_execute_jtag_queue(struct target *target) {
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	if (vexriscv->useTCP)
		return 0;
	return jtag_execute_queue();
}

int vexriscv_write_regfile(struct target* target, bool execute,uint32_t regId,uint32_t value){
	assert(regId <= 32);
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

	if (!reg->valid) {
		if(reg->number < 32){
			return ERROR_FAIL;
		}else if(reg->number == 32){
			vexriscv_pushInstruction(target, false, 0x17); //AUIPC x0,0
			vexriscv_readInstructionResult32(target, true, reg->value);
		}else if (vexriscv_reg->is_csr) {
			// Perform a CSRRW which does a Read/Write.  If rs1 is $x0, then the write
			// is ignored and side-effect free.  Set rd to $x1 to make the read 
			// not side-effect free.
			vexriscv_pushInstruction(target, false, 0
				| ((vexriscv_reg->csr_num & 0x1fff) << 20)
				| (0 << 15)	// rs1: x0
				| (2 << 12)	// CSRRW
				| (1 << 7)	// rd: x1
				| (0x73 << 0)	// SYSTEM
			);
			vexriscv_readInstructionResult32(target, false, reg->value);
		}
		else {
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

	buf_set_u32(reg->value, 0, 32, value);

	if (vexriscv_reg->is_csr) {
		// Perform a CSRRW which does a Read/Write.  If rd is $x0, then the read
		// is ignored and side-effect free.  Set rs1 to $x1 to make the write 
		// not side-effect free.
		// 
		// cccc cccc cccc ssss s fff ddddd ooooooo
		// c: CSR number
		// s: rs1 (source register)
		// f: Function
		// d: rd (destination register)
		// o: opcode - 0x73

		vexriscv_write_regfile(target, false, 1, *(uint32_t *)reg->value);
		vexriscv_pushInstruction(target, false, 0
			| ((vexriscv_reg->csr_num & 0x1fff) << 20)
			| (1 << 15)	// rs1: x1
			| (1 << 12)	// CSRRW
			| (0 << 7)	// rd: x0
			| (0x73 << 0)	// SYSTEM
		);
		reg->dirty = 0;
		reg->valid = 1;
	}
	else {
		reg->dirty = 1;
		reg->valid = 1;
	}
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

	static struct reg_feature feature_cpu = {
		.name = "org.gnu.gdb.riscv.cpu"
	};
	static struct reg_feature feature_csr = {
		.name = "org.gnu.gdb.riscv.csr"
	};

	for (uint32_t i = 0; i < vexriscv->nb_regs; i++) {
		arch_info[i] = vexriscv_core_reg_list_arch_info[i];
		arch_info[i].target = target;
		arch_info[i].vexriscv_common = vexriscv;
		reg_list[i].name = vexriscv_core_reg_list_arch_info[i].name;
		reg_list[i].feature = &feature_cpu;
		reg_list[i].group = "general";
		reg_list[i].size = 32;
		reg_list[i].value = calloc(1, 4);
		reg_list[i].dirty = 0;
		reg_list[i].valid = 0;
		reg_list[i].type = &vexriscv_reg_type;
		reg_list[i].arch_info = &arch_info[i];
		reg_list[i].number = i;

		if (vexriscv_core_reg_list_arch_info[i].is_csr) {
			reg_list[i].group = "csr";
			reg_list[i].feature = &feature_csr;
		}

		if ((i <= 32) || (vexriscv_core_reg_list_arch_info[i].is_csr))
			reg_list[i].exist = true;
		else
			reg_list[i].exist = false;
	}

	return cache;
}

static void vexriscv_set_instr(struct target *target, uint32_t new_instr)
{
	struct scan_field field;
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	struct jtag_tap *tap = target->tap;
	if(new_instr == vexriscv->bridgeInstruction && !target->tap->bypass) return;
	vexriscv->bridgeInstruction = new_instr;
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

static void vexriscv_parse_debugReport(yaml_parser_t *parser, struct vexriscv_common *target){
	yaml_token_t  token;
	target->hardwareBreakpointsCount = 0;
	while(1){
		yaml_parser_scan(parser, &token);
		switch(token.type){
			case YAML_SCALAR_TOKEN:
				if(strcmp((char*)token.data.scalar.value,"hardwareBreakpointCount") == 0){
					while(1){
						yaml_parser_scan(parser, &token);
						switch(token.type){
							case YAML_SCALAR_TOKEN:
								target->hardwareBreakpointsCount = atoi((char*)token.data.scalar.value);
								return;
								break;
							default: break;
						}
					}
				}
			break;
			default: break;
		}
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
				if(strcmp((char*)token.data.scalar.value,"debug") == 0){
					vexriscv_parse_debugReport(&parser, vexriscv);
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
	vexriscv->hardwareBreakpointUsed = malloc(sizeof(bool)*vexriscv->hardwareBreakpointsCount);
	for(int i = 0;i < vexriscv->hardwareBreakpointsCount;i++) vexriscv->hardwareBreakpointUsed[i] = 0;

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
		if (vexriscv->networkProtocol == NP_IVERILOG)
			serverAddr.sin_port = htons(7893);
		else if (vexriscv->networkProtocol == NP_ETHERBONE)
			serverAddr.sin_port = htons(1234);
		else
			LOG_ERROR("Unrecognized network protocol defined");
		// Set IP address to localhost //
		serverAddr.sin_addr.s_addr = inet_addr(vexriscv->targetAddress);
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
	vexriscv_semihosting_init(target);
	return ERROR_OK;
}

static int vexriscv_arch_state(struct target *target)
{
	LOG_DEBUG("vexriscv_arch_state\n");
	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}


static int vexriscv_is_halted(struct target * target,uint32_t *halted){
	uint32_t flags;
	int error;
	if((error = vexriscv_readStatusRegister(target, true, &flags)) != ERROR_OK){
		LOG_ERROR("Error while calling vexriscv_is_cpu_running");
		return error;
	}
	*halted = flags & vexriscv_FLAGS_HALT;

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
	if((error = vexriscv_execute_jtag_queue(target)) != ERROR_OK)
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
		vexriscv_readInstructionResult32(target, false, reg->value);
		reg->valid = 1;
		reg->dirty = 1;
	}

	for(uint32_t regId = 0;regId < 32;regId++){
		struct reg* reg = &vexriscv->core_cache->reg_list[regId];
		vexriscv_pushInstruction(target, false, 0x13 | (reg->number << 15)); //ADDI x0, x?, 0
		vexriscv_readInstructionResult32(target, false, reg->value);
		reg->valid = 1;
		reg->dirty = reg->number == 1 ? 1 : 0; //For safety, invalidate x1 for debugger purposes
	}

	// Mark all CSRs as "invalid"
	for (uint32_t regId = 65; regId < vexriscv->nb_regs; regId++) {
		struct reg* reg = &vexriscv->core_cache->reg_list[regId];
		reg->valid = 0;
	}

	//Flush commands
	if(vexriscv_execute_jtag_queue(target))
		return ERROR_FAIL;

//	if((error = vexriscv_flush_caches(target)) != ERROR_OK) //Flush instruction cache
//		return error;

	return ERROR_OK;
}

static void vexriscv_cpu_write_pc(struct target *target, bool execute, uint32_t value){
	vexriscv_write_regfile(target, false, 1,value);
	vexriscv_pushInstruction(target, false, 0x67 | (1 << 15)); //JALR x1
	if(execute) jtag_execute_queue();
}

static int vexriscv_restore_context(struct target *target)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	LOG_DEBUG("-");

	//PC
	if(vexriscv->regs->pc.valid){
		vexriscv_cpu_write_pc(target, false, *((uint32_t*)vexriscv->regs->pc.value));
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

	return vexriscv_execute_jtag_queue(target);
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




/**
 * Check for and process a semihosting request using the ARM protocol). This
 * is meant to be called when the target is stopped due to a debug mode entry.
 * If the value 0 is returned then there was nothing to process. A non-zero
 * return value signifies that a request was processed and the target resumed,
 * or an error was encountered, in which case the caller must return
 * immediately.
 *
 * @param target Pointer to the target to process.
 * @param retval Pointer to a location where the return code will be stored
 * @return non-zero value if a request was processed or an error encountered
 */
int vexriscv_semihosting(struct target *target, int *retval)
{
    struct vexriscv_common *vexriscv = target_to_vexriscv(target);

	struct semihosting *semihosting = target->semihosting;
	if (!semihosting)
		return 0;

	if (!semihosting->is_active)
		return 0;

    uint32_t pc = 0xdeadbeef;
    
    vexriscv_get_core_reg(&vexriscv->core_cache->reg_list[32]);
    pc = *((uint32_t*) vexriscv->core_cache->reg_list[32].value);

    
    LOG_DEBUG("semihosting pc: %08x", pc);
    // todo proper error handling
    if (pc == 0xdeadbeef) {
        return 0;
    }

	uint8_t tmp[12];
	/* Read the current instruction, including the bracketing */
    /*int result =*/ vexriscv_read_memory(target, pc-4, sizeof(uint16_t), 6, tmp);

    // todo error handling

	/*
	 * The instructions that trigger a semihosting call,
	 * always uncompressed, should look like:
	 *
	 * 01f01013              slli    zero,zero,0x1f
	 * 00100073              ebreak
	 * 40705013              srai    zero,zero,0x7
	 */
	uint32_t pre = target_buffer_get_u32(target, tmp);
	uint32_t ebreak = target_buffer_get_u32(target, tmp + 4);
	uint32_t post = target_buffer_get_u32(target, tmp + 8);
	LOG_DEBUG("semihosting check %08x %08x %08x from 0x%" PRIx64 "-4", pre, ebreak, post, (uint64_t) pc);

	if (pre != 0x01f01013 || ebreak != 0x00100073 || post != 0x40705013) {

		/* Not the magic sequence defining semihosting. */
		return 0;
	}

	/*
	 * Perform semihosting call if we are not waiting on a fileio
	 * operation to complete.
	 */
	if (!semihosting->hit_fileio) {

		/* RISC-V uses A0 and A1 to pass function arguments */
        uint32_t r0;
        uint32_t r1;
        
        vexriscv_get_core_reg(&vexriscv->core_cache->reg_list[10]);
        r0 = *((uint32_t*) vexriscv->core_cache->reg_list[10].value);
        
        vexriscv_get_core_reg(&vexriscv->core_cache->reg_list[11]);
        r1 = *((uint32_t*) vexriscv->core_cache->reg_list[11].value);
        
        LOG_DEBUG("semihosting  r0: %08x", r0);
        LOG_DEBUG("semihosting  r1: %08x", r1);
        
		semihosting->op = r0;
		semihosting->param = r1;
		semihosting->word_size_bytes = sizeof(uint32_t);//riscv_xlen(target) / 8;

        /* Check for ARM operation numbers. */
		if (0 <= semihosting->op && semihosting->op <= 0x31) {
			*retval = semihosting_common(target);
			if (*retval != ERROR_OK) {
				LOG_ERROR("Failed semihosting operation");
				return 0;
			}
		} else {
			/* Unknown operation number, not a semihosting call. */
			return 0;
		}
	}

	/*
	 * Resume target if we are not waiting on a fileio
	 * operation to complete.
	 */
	if (semihosting->is_resumable && !semihosting->hit_fileio) {
        // resume only if it was running
        if (target->debug_reason == DBG_REASON_NOTHALTED) {
            /* Resume right after the EBREAK 4 bytes instruction. */
            *retval = target_resume(target, 0, pc+4, 0, 0);
            if (*retval != ERROR_OK) {
                LOG_ERROR("Failed to resume target");
                return 0;
            }
            return 2;
        } else if (target->debug_reason == DBG_REASON_SINGLESTEP) {
            // otherwise
            // set PC to next address instead of resuming
            pc += 4;
            vexriscv_set_core_reg(&vexriscv->core_cache->reg_list[32], (uint8_t*) &pc);
            return 1;
        } else {
            LOG_INFO("unknown debug_reason: %d\n", target->debug_reason);
            return 0;
        }
	}

	return 0;
}






#include <stdlib.h>
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
			if (target->debug_reason == DBG_REASON_SINGLESTEP || target->debug_reason == DBG_REASON_NOTHALTED) {
				if (vexriscv_semihosting(target, &retval) == 2) {
					return ERROR_OK; // don't call event handler if not in single-step
				}
			}

			target_call_event_callbacks(target,TARGET_EVENT_HALTED);
		} else if (target->state == TARGET_DEBUG_RUNNING) {
			// don't know what this is for ...
			target->state = TARGET_HALTED;

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
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	int error;
	LOG_DEBUG("vexriscv_assert_reset\n");
	target->state = TARGET_RESET;

	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_SET)) != ERROR_OK) {
		return error;
	}

	if ((error =  vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_SET | vexriscv_FLAGS_RESET_SET)) != ERROR_OK) {
		return error;
	}


	// Resetting the CPU causes the program counter to jump to the reset vector.
	// Our copy is no longer valid.
	vexriscv->regs->pc.valid = false;

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

	usleep(200000);

	uint32_t isRunning;
	if(vexriscv_is_running(target,&isRunning)) return ERROR_FAIL;
	target->state = isRunning ? TARGET_RUNNING : TARGET_HALTED;

	LOG_DEBUG("%s", __func__);
	return ERROR_OK;
}

static int vexriscv_network_read(struct vexriscv_common *vexriscv, void *buffer, size_t count)
{
	if (vexriscv->networkProtocol == NP_IVERILOG)
		return recv(vexriscv->clientSocket, buffer, 4, 0);
	else if (vexriscv->networkProtocol == NP_ETHERBONE) {
		uint8_t wb_buffer[20];
		uint32_t intermediate;
		int ret = read(vexriscv->clientSocket, wb_buffer, sizeof(wb_buffer));
		if (ret != sizeof(wb_buffer))
			return 0;
		memcpy(&intermediate, &wb_buffer[16], sizeof(intermediate));
		intermediate = ntohl(intermediate);
		memcpy(buffer, &intermediate, sizeof(intermediate));
		return 4;
	}
	else {
		return 0;
	}
}

static int vexriscv_network_write(struct vexriscv_common *vexriscv, int is_read, uint32_t size, uint32_t address, uint32_t data)
{
	if (vexriscv->networkProtocol == NP_IVERILOG)
	{
		uint8_t buffer[10];
		buffer[0] = is_read ? 0 : 1;
		buffer[1] = size;
		buf_set_u32(buffer + 2, 0, 32, address);
		buf_set_u32(buffer + 6, 0, 32, data);
		return send(vexriscv->clientSocket, buffer, 10, 0);
	}
	else if (vexriscv->networkProtocol == NP_ETHERBONE)
	{
		// size==2 is 32-bits
		// size==1 is 16-bits
		// size==0 is 8-bits
		if (size != 2) {
			LOG_ERROR("size is not 2 (32-bits): %d", size);
			exit(0);
		}
		uint8_t wb_buffer[20] = {};
		wb_buffer[0] = 0x4e;	// Magic byte 0
		wb_buffer[1] = 0x6f;	// Magic byte 1
		wb_buffer[2] = 0x10;	// Version 1, all other flags 0
		wb_buffer[3] = 0x44;	// Address is 32-bits, port is 32-bits
		wb_buffer[4] = 0;		// Padding
		wb_buffer[5] = 0;		// Padding
		wb_buffer[6] = 0;		// Padding
		wb_buffer[7] = 0;		// Padding

		// Record
		wb_buffer[8] = 0;		// No Wishbone flags are set (cyc, wca, wff, etc.)
		wb_buffer[9] = 0x0f;	// Byte enable

		if (is_read) {
			wb_buffer[11] = 1;	// Read count
			data = htonl(address);
			memcpy(&wb_buffer[16], &data, sizeof(data));
		}
		else {
			wb_buffer[10] = 1;	// Write count
			address = htonl(address);
			memcpy(&wb_buffer[12], &address, sizeof(address));

			data = htonl(data);
			memcpy(&wb_buffer[16], &data, sizeof(data));
		}
		return write(vexriscv->clientSocket, wb_buffer, sizeof(wb_buffer));
	}
	else {
		LOG_ERROR("Unrecognized network protocol");
		exit(0);
	}
}

static void vexriscv_memory_cmd(struct target *target, uint32_t address,uint32_t data,int32_t size, int read)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	struct jtag_tap *tap = target->tap;
	struct scan_field field;
	uint8_t cmd[10];

	if(!vexriscv->useTCP) vexriscv_set_instr(target, vexriscv->jtagCmdInstruction);

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
	field.num_bits = 8+32+32+1+2+vexriscv->jtagCmdHeaderSize + waitCycles;
	field.out_value = cmd;
	uint32_t offset = 0;

    bit_copy(cmd,offset,(uint8_t*)&vexriscv->jtagCmdHeader,0,vexriscv->jtagCmdHeaderSize); offset += vexriscv->jtagCmdHeaderSize;
	bit_copy(cmd,offset,&inst,0,8); offset += 8 + waitCycles;
	bit_copy(cmd,offset,(uint8_t*)&address,0,32); offset += 32;
	bit_copy(cmd,offset,(uint8_t*)&data,0,32); offset += 32;
	bit_copy(cmd,offset,&write,0,1); offset += 1;
	bit_copy(cmd,offset ,(uint8_t*)&size,0,2); offset += 2;
	field.in_value = NULL;
	field.check_value = NULL;
	field.check_mask = NULL;
	if(!vexriscv->useTCP)
		jtag_add_dr_scan(tap, 1, &field, TAP_IDLE);
	else
	{
		if (vexriscv_network_write(vexriscv, read, size, address, data) <= 0) {
			LOG_ERROR("Network connection closed while writing");
			exit(0);
		}
	}
}

static void vexriscv_read_rsp(struct target *target,uint8_t *value, uint32_t size)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	struct jtag_tap *tap = target->tap;
	struct scan_field feilds[3];
    uint8_t header[10];
    bit_copy(header,0,(uint8_t*)&vexriscv->jtagRspHeader,0,vexriscv->jtagRspHeaderSize);


	feilds[0].num_bits = 2+vexriscv->jtagRspHeaderSize; //TODO !!!
	feilds[0].out_value = header;
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
		vexriscv_set_instr(target, vexriscv->jtagRspInstruction);
		jtag_add_dr_scan(tap, size == 4 ? 2 : 3, feilds, TAP_IDLE);
	} else {
		uint32_t buffer;
		int bytes_read = vexriscv_network_read(vexriscv, &buffer, sizeof(buffer));
		if (bytes_read == 4) {
			//value[0] = 1;
			//bit_copy(value,2,(uint8_t *) &buffer,0,32);
			bit_copy(value,0,(uint8_t *) &buffer,0,8*size);
		} else if (bytes_read == 0) {
			LOG_ERROR("remote bridge closed network connection");
			value[0] = 0;
			exit(0);
		} else if (bytes_read == -1) {
			LOG_ERROR("network connection error: %s\n", strerror(errno));
			value[0] = 0;
			exit(0);
		} else {
			LOG_ERROR("unexpected number of bytes read: %d\n", bytes_read);
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
			buffer[0] = 0; buffer[1] = 0; buffer[2] = 0; buffer[3] = 0;
			vexriscv_pushInstruction(target, false, (1 << 15) | (0x2 << 12) | (1 << 7) | 0x3); //LW x1, 0(x1)
			vexriscv_readInstructionResult32(target, false, buffer);
			break;
		case 2:
			buffer[0] = 0; buffer[1] = 0;
			vexriscv_pushInstruction(target, false, (1 << 15) | (0x5 << 12) | (1 << 7) | 0x3); //LHU x1, 0(x1)
			vexriscv_readInstructionResult16(target, false, buffer);
			break;
		case 1:
			buffer[0] = 0;
			vexriscv_pushInstruction(target, false, (1 << 15) | (0x4 << 12) | (1 << 7) | 0x3); //LBU x1, 0(x1)
			vexriscv_readInstructionResult8(target, false, buffer);
			break;
		}
		buffer += size;
		address += size;
	}

	return vexriscv_execute_jtag_queue(target);
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
	LOG_DEBUG("Writing memory at physical address 0x%" PRIx32
		  "; size %" PRId32 "; count %" PRId32, (uint32_t)address, size, count);

	if (target->state != TARGET_HALTED)
		vexriscv_halt(target);

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
			accesses[accessId].data = buf_get_u32(buffer + 4*accessId, 0 ,32);
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
				vexriscv_write_regfile(target, false, 1,buf_get_u32(buffer, 0, 32));
				vexriscv_write_regfile(target, false, 2,address);
				vexriscv_pushInstruction(target, false, (1 << 20) | (2 << 15) | (0x2 << 12) | 0x23); //SW x1,0(x2)
				break;
			case 2:
				vexriscv_write_regfile(target, false, 1,buf_get_u32(buffer, 0 ,16));
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
	if(vexriscv_execute_jtag_queue(target))
		return ERROR_FAIL;
	return ERROR_OK;
}


static int vexriscv_pushInstruction(struct target *target, bool execute, uint32_t instruction){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 4,instruction,4, 0);
	return execute ? vexriscv_execute_jtag_queue(target) : 0;
}

static int vexriscv_setHardwareBreakpoint(struct target *target, bool execute, uint32_t id, uint32_t enable,uint32_t pc){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 0x40 + id*4, pc | (enable ? 1 : 0),4, 0);
	return execute ? vexriscv_execute_jtag_queue(target) : 0;
}

static int vexriscv_writeStatusRegister(struct target *target, bool execute, uint32_t value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase, value, 4, 0);
	return execute ? vexriscv_execute_jtag_queue(target) : 0;
}

static int vexriscv_readStatusRegister(struct target *target, bool execute, uint32_t *value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase,0, 4, 1);
	vexriscv_read_rsp(target,(uint8_t*)value, 4);
	return execute ? vexriscv_execute_jtag_queue(target) : 0;
}

static int vexriscv_readInstructionResult32(struct target *target, bool execute, uint8_t *value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 4,0, 4, 1);
	vexriscv_read_rsp(target, value, 4);
	return execute ? vexriscv_execute_jtag_queue(target) : 0;
}


static int vexriscv_readInstructionResult16(struct target *target, bool execute, uint8_t *value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 4,0, 4, 1);
	vexriscv_read_rsp(target, value, 2);
	return execute ? vexriscv_execute_jtag_queue(target) : 0;
}


static int vexriscv_readInstructionResult8(struct target *target, bool execute, uint8_t *value){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_memory_cmd(target, vexriscv->dbgBase + 4,0, 4, 1);
	vexriscv_read_rsp(target,(uint8_t*)value, 1);
	return execute ? vexriscv_execute_jtag_queue(target) : 0;
}

static int vexriscv_read16(struct target *target, uint32_t address,uint16_t *data){
	return vexriscv_read_memory(target,address,2,1,(uint8_t*)data);
}
static int vexriscv_write16(struct target *target, uint32_t address,uint16_t data){
	return vexriscv_write_memory(target,address,2,1,(uint8_t*)&data);
}

/**
 * Called via semihosting->setup() later, after the target is known,
 * usually on the first semihosting command.
 */
static int vexriscv_semihosting_setup(struct target *target, int enable)
{
	LOG_DEBUG("enable=%d", enable);

	struct semihosting *semihosting = target->semihosting;
	if (semihosting)
		semihosting->setup_time = clock();

	return ERROR_OK;
}

static int vexriscv_semihosting_post_result(struct target *target)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
    
	struct semihosting *semihosting = target->semihosting;
	if (!semihosting) {
		/* If not enabled, silently ignored. */
		return 0;
	}

	LOG_DEBUG("0x%" PRIx64, semihosting->result);

    vexriscv_set_core_reg(&vexriscv->core_cache->reg_list[10], (uint8_t*) &semihosting->result);
        
	return 0;
}


static int vexriscv_get_gdb_reg_list(struct target *target, struct reg **reg_list[],
			  int *reg_list_size, enum target_register_class reg_class)
{
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	LOG_DEBUG("vexriscv_get_gdb_reg_list %d\n",reg_class);
	if (reg_class == REG_CLASS_GENERAL) {
		*reg_list_size = 32;
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));

		for (int i = 0; i < *reg_list_size; i++)
			(*reg_list)[i] = &vexriscv->core_cache->reg_list[i];
	} else if (reg_class == REG_CLASS_ALL) {
		*reg_list_size = vexriscv->nb_regs;
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));
		for (int i = 0; i < *reg_list_size; i++)
			(*reg_list)[i] = &vexriscv->core_cache->reg_list[i];
	} else {
		LOG_ERROR("Unsupported reg_class: %d", reg_class);
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
	if (breakpoint->type == BKPT_SOFT){
		/* Read and save the instruction */
		int retval = vexriscv_read16(target,
						 breakpoint->address,
						 (uint16_t*)(&data));
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while reading the instruction at 0x%08" PRIx32, (uint32_t)breakpoint->address);
			return retval;
		}
		retval = vexriscv_read16(target,
						 breakpoint->address+2,
						 ((uint16_t*)(&data))+1);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while reading the instruction at 0x%08" PRIx32, (uint32_t)breakpoint->address);
			return retval;
		}

		if (breakpoint->orig_instr != NULL)
			free(breakpoint->orig_instr);

		breakpoint->orig_instr = malloc(4);
		memcpy(breakpoint->orig_instr, &data, 4);

		if((data & 3) == 3){
			retval = vexriscv_write16(target,
							  breakpoint->address,
							  (uint16_t)vexriscv_BREAK_INST);

			if (retval != ERROR_OK) {
				LOG_ERROR("Error while writing vexriscv_TRAP_INSTR at 0x%08" PRIx32,
						(uint32_t)breakpoint->address);
				return retval;
			}
			retval = vexriscv_write16(target,
							  breakpoint->address+2,
							  (uint16_t)(vexriscv_BREAK_INST >> 16));

			if (retval != ERROR_OK) {
				LOG_ERROR("Error while writing vexriscv_TRAP_INSTR at 0x%08" PRIx32,
						(uint32_t)breakpoint->address+2);
				return retval;
			}
		}else{
			retval = vexriscv_write16(target,
							  breakpoint->address,
							  vexriscv_BREAKC_INST);

			if (retval != ERROR_OK) {
				LOG_ERROR("Error while writing vexriscv_TRAP_INSTR at 0x%08" PRIx32,
						(uint32_t)breakpoint->address);
				return retval;
			}
		}
	} else {
		struct vexriscv_common *vexriscv = target_to_vexriscv(target);

		int32_t freeId = - 1;
		for(int i = 0;i < vexriscv->hardwareBreakpointsCount;i++){
			if(!vexriscv->hardwareBreakpointUsed[i]) freeId = i;
		}
		if(freeId == -1){
			LOG_INFO("no watchpoint unit available for hardware breakpoint");
			return ERROR_TARGET_RESOURCE_NOT_AVAILABLE;
		}
		breakpoint->set = freeId+1;
		vexriscv->hardwareBreakpointUsed[freeId] = 1;
		vexriscv_setHardwareBreakpoint(target, true, freeId, 1,breakpoint->address);
	}

	return ERROR_OK;
}

static int vexriscv_remove_breakpoint(struct target *target,
				  struct breakpoint *breakpoint)
{
	LOG_DEBUG("Removing breakpoint: addr 0x%08" PRIx32 ", len %d, type %d, set: %d, id: %" PRId32,
			(uint32_t)breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

	/* Only support SW breakpoints for now. */
	if (breakpoint->type == BKPT_SOFT){

		/* Replace the removed instruction */
		uint32_t data = buf_get_u32(breakpoint->orig_instr,0,32);
		if((data & 3) == 3){
			int retval = vexriscv_write16(target,
							  breakpoint->address,
							  (uint16_t)data);

			if (retval != ERROR_OK) {
				LOG_ERROR("Error while writing back the instruction at 0x%08" PRIx32,
						(uint32_t)breakpoint->address);
				return retval;
			}
			retval = vexriscv_write16(target,
							  breakpoint->address+2,
							  (uint16_t)(data >> 16));

			if (retval != ERROR_OK) {
				LOG_ERROR("Error while writing back the instruction at 0x%08" PRIx32,
						(uint32_t)breakpoint->address+2);
				return retval;
			}
		}else{
			int retval = vexriscv_write16(target,
							  breakpoint->address,
							  (uint16_t)data);

			if (retval != ERROR_OK) {
				LOG_ERROR("Error while writing back the instruction at 0x%08" PRIx32,
						(uint32_t)breakpoint->address);
				return retval;
			}
		}
	} else {
		struct vexriscv_common *vexriscv = target_to_vexriscv(target);
		if (!breakpoint->set) {
			LOG_WARNING("breakpoint not set");
			return ERROR_OK;
		}
		uint32_t freeId = breakpoint->set - 1;
		breakpoint->set = 0;
		vexriscv->hardwareBreakpointUsed[freeId] = 0;
		vexriscv_setHardwareBreakpoint(target, true, freeId, 0,breakpoint->address);
	}


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
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);



	if (!target_was_examined(target)) {

		target_set_examined(target);
		//Soft reset
		vexriscv_assert_reset(target);
		vexriscv_deassert_reset(target);


		uint32_t halted;
		int retval = vexriscv_is_halted(target,&halted);

		if (retval != ERROR_OK) {
			LOG_ERROR("Couldn't read the CPU state");
			return retval;
		} else {
			if (!halted)
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

				for(int i = 0;i < vexriscv->hardwareBreakpointsCount;i++) {
					vexriscv_setHardwareBreakpoint(target, true,i,0,0);
				}
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

	usleep(200000);

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

/* run to exit point. return error if exit point was not reached. */
static int vexriscv_run_and_wait(struct target *target, target_addr_t entry_point, int timeout_ms)
{
	int retval;
	//struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv_cpu_write_pc(target, false, entry_point);

	/* Unstall */
	if ((retval = vexriscv_writeStatusRegister(target, true, vexriscv_FLAGS_HALT_CLEAR)) != ERROR_OK) {
		LOG_ERROR("Error while unstalling the CPU");
		return retval;
	}

	target->state = TARGET_DEBUG_RUNNING;

	retval = target_wait_state(target, TARGET_HALTED, timeout_ms);
	/* If the target fails to halt due to the breakpoint, force a halt */
	if (retval != ERROR_OK || target->state != TARGET_HALTED) {
		retval = target_halt(target);
		if (retval != ERROR_OK)
			return retval;
		retval = target_wait_state(target, TARGET_HALTED, 500);
		if (retval != ERROR_OK)
			return retval;
		return ERROR_TARGET_TIMEOUT;
	}

	/*pc = buf_get_u32(vexriscv->regs.value, 0, 32);
	if (exit_point && (pc != exit_point)) {
		LOG_DEBUG("failed algorithm halted at 0x%" PRIx32 " ", pc);
		return ERROR_TARGET_TIMEOUT;
	}*/

	return ERROR_OK;
}



int vexriscv_run_algorithm(struct target *target, int num_mem_params,
			struct mem_param *mem_params, int num_reg_params,
			struct reg_param *reg_params, target_addr_t entry_point,
			target_addr_t exit_point, int timeout_ms, void *arch_info){
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	int retval;
	LOG_DEBUG("Running algorithm");

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	for (unsigned int i = 0; i < 33; i++) {
		vexriscv_get_core_reg(&vexriscv->core_cache->reg_list[i]);
		vexriscv->core_cache->reg_list[i].dirty = 1;
	}

	for (int i = 0; i < num_mem_params; i++) {
		if (mem_params[i].direction != PARAM_IN) {
			retval = target_write_buffer(target, mem_params[i].address, mem_params[i].size, mem_params[i].value);
			if (retval != ERROR_OK)
				return retval;
		}
	}

	vexriscv_flush_caches(target); //Ensure instruction cache is in sync with recently written program

	for (int i = 0; i < num_reg_params; i++) {
		struct reg *reg = register_get_by_name(vexriscv->core_cache, reg_params[i].reg_name, 0);

		if (!reg) {
			LOG_ERROR("BUG: register '%s' not found", reg_params[i].reg_name);
			return ERROR_COMMAND_SYNTAX_ERROR;
		}

		if (reg->size != reg_params[i].size) {
			LOG_ERROR("BUG: register '%s' size doesn't match reg_params[i].size",
					reg_params[i].reg_name);
			return ERROR_COMMAND_SYNTAX_ERROR;
		}


		vexriscv_write_regfile(target, false, reg->number, buf_get_u32(reg_params[i].value,0,32));
	}

	retval = vexriscv_run_and_wait(target, entry_point, timeout_ms);

	if (retval != ERROR_OK)
		return retval;

	for (int i = 0; i < num_mem_params; i++) {
		if (mem_params[i].direction != PARAM_OUT) {
			retval = target_read_buffer(target, mem_params[i].address, mem_params[i].size,
					mem_params[i].value);
			if (retval != ERROR_OK)
				return retval;
		}
	}

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

COMMAND_HANDLER(vexriscv_handle_jtagMapping_command)
{
    if(CMD_ARGC != 6)
        return ERROR_COMMAND_ARGUMENT_INVALID;
    struct target* target = get_current_target(CMD_CTX);
    struct vexriscv_common *vexriscv = target_to_vexriscv(target);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[0], vexriscv->jtagCmdInstruction);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[1], vexriscv->jtagRspInstruction);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[2], vexriscv->jtagCmdHeader);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[3], vexriscv->jtagRspHeader);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[4], vexriscv->jtagCmdHeaderSize);
    COMMAND_PARSE_NUMBER(u32, CMD_ARGV[5], vexriscv->jtagRspHeaderSize);
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

COMMAND_HANDLER(vexriscv_handle_targetAddress_command)
{
	if(CMD_ARGC != 1)
		return ERROR_COMMAND_ARGUMENT_INVALID;
	struct target* target = get_current_target(CMD_CTX);
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	vexriscv->targetAddress = strdup(CMD_ARGV[0]);
	return ERROR_OK;
}

COMMAND_HANDLER(vexriscv_handle_networkProtocol_command)
{
	if (CMD_ARGC != 1)
		return ERROR_COMMAND_ARGUMENT_INVALID;
	struct target *target = get_current_target(CMD_CTX);
	struct vexriscv_common *vexriscv = target_to_vexriscv(target);
	if (!strcasecmp(CMD_ARGV[0], "iverilog")) {
		vexriscv->networkProtocol = NP_IVERILOG;
	} else if (!strcasecmp(CMD_ARGV[0], "etherbone")) {
		vexriscv->networkProtocol = NP_ETHERBONE;
	} else {
		return ERROR_COMMAND_ARGUMENT_INVALID;
	}
	return ERROR_OK;
}

extern __COMMAND_HANDLER(handle_common_semihosting_command);
extern __COMMAND_HANDLER(handle_common_semihosting_fileio_command);
extern __COMMAND_HANDLER(handle_common_semihosting_resumable_exit_command);
extern __COMMAND_HANDLER(handle_common_semihosting_cmdline);

/*
 * To be noted that RISC-V targets use the same semihosting commands as
 * ARM targets.
 *
 * The main reason is compatibility with existing tools. For example the
 * Eclipse OpenOCD/SEGGER J-Link/QEMU plug-ins have several widgets to
 * configure semihosting, which generate commands like `arm semihosting
 * enable`.
 * A secondary reason is the fact that the protocol used is exactly the
 * one specified by ARM. If RISC-V will ever define its own semihosting
 * protocol, then a command like `riscv semihosting enable` will make
 * sense, but for now all semihosting commands are prefixed with `arm`.
 */
static const struct command_registration arm_exec_command_handlers[] = {
	{
		"semihosting",
		.handler = handle_common_semihosting_command,
		.mode = COMMAND_EXEC,
		.usage = "['enable'|'disable']",
		.help = "activate support for semihosting operations",
	},
	{
		"semihosting_cmdline",
		.handler = handle_common_semihosting_cmdline,
		.mode = COMMAND_EXEC,
		.usage = "arguments",
		.help = "command line arguments to be passed to program",
	},
	{
		"semihosting_fileio",
		.handler = handle_common_semihosting_fileio_command,
		.mode = COMMAND_EXEC,
		.usage = "['enable'|'disable']",
		.help = "activate support for semihosting fileio operations",
	},
	{
		"semihosting_resexit",
		.handler = handle_common_semihosting_resumable_exit_command,
		.mode = COMMAND_EXEC,
		.usage = "['enable'|'disable']",
		.help = "activate support for semihosting resumable exit",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration vexriscv_exec_command_handlers[] = {
        {
            .name = "jtagMapping",
            .handler = vexriscv_handle_jtagMapping_command,
            .mode = COMMAND_CONFIG,
            .help = "Specify the JTAG instructions used for cmd/rsp transactions and their DR_SHIFT header, default 2 3 0 0 0 0",
            .usage = "cmdInstruction rspInstruction cmdHeader rspHeader cmdHeaderSize rspHeaderSize",
        },
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
		},{
			.name = "targetAddress",
			.handler = vexriscv_handle_targetAddress_command,
			.mode = COMMAND_CONFIG,
			.help = "Target address to connect to",
			.usage = "network-address",
		},{
			.name = "networkProtocol",
			.handler = vexriscv_handle_networkProtocol_command,
			.mode = COMMAND_CONFIG,
			.help = "Network protocol to use (iverilog, etherbone)",
			.usage = "iverilog,etherbone",
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
	{
		.name = "arm",
		.mode = COMMAND_ANY,
		.help = "ARM Command Group",
		.usage = "",
		.chain = arm_exec_command_handlers
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
	.run_algorithm = vexriscv_run_algorithm
};
