// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2012 by Matthias Blaicher                               *
 *   Matthias Blaicher - matthias@blaicher.com                             *
 *                                                                         *
 *   Copyright (C) 2011 by Broadcom Corporation                            *
 *   Evan Hunter - ehunter@broadcom.com                                    *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/time_support.h>
#include <jtag/jtag.h>
#include "target/target.h"
#include "target/armv7m.h"
#include "target/cortex_m.h"
#include "rtos.h"
#include "helper/log.h"
#include "helper/types.h"
#include "rtos_chibios_stackings.h"

/**
 * @brief   ChibiOS/RT memory signature record.
 *
 * @details Definition copied from os/kernel/include/chregistry.h of ChibiOS/RT.
 */
struct chibios_chdebug {
	char      ch_identifier[4];       /**< @brief Always set to "main".       */
	uint8_t   ch_zero;                /**< @brief Must be zero.               */
	uint8_t   ch_size;                /**< @brief Size of this structure.     */
	uint8_t   ch_version[2];          /**< @brief Encoded ChibiOS/RT version. */
	uint8_t   ch_ptrsize;             /**< @brief Size of a pointer.          */
	uint8_t   ch_timesize;            /**< @brief Size of a @p systime_t.     */
	uint8_t   ch_threadsize;          /**< @brief Size of a @p Thread struct. */
	uint8_t   cf_off_prio;            /**< @brief Offset of @p p_prio field.  */
	uint8_t   cf_off_ctx;             /**< @brief Offset of @p p_ctx field.   */
	uint8_t   cf_off_newer;           /**< @brief Offset of @p p_newer field. */
	uint8_t   cf_off_older;           /**< @brief Offset of @p p_older field. */
	uint8_t   cf_off_name;            /**< @brief Offset of @p p_name field.  */
	uint8_t   cf_off_stklimit;        /**< @brief Offset of @p p_stklimit
												field.                        */
	uint8_t   cf_off_state;           /**< @brief Offset of @p p_state field. */
	uint8_t   cf_off_flags;           /**< @brief Offset of @p p_flags field. */
	uint8_t   cf_off_refs;            /**< @brief Offset of @p p_refs field.  */
	uint8_t   cf_off_preempt;         /**< @brief Offset of @p p_preempt
												field.                        */
	uint8_t   cf_off_time;            /**< @brief Offset of @p p_time field.  */
};

#define GET_CH_KERNEL_MAJOR(coded_version) ((coded_version >> 11) & 0x1f)
#define GET_CH_KERNEL_MINOR(coded_version) ((coded_version >> 6) & 0x1f)
#define GET_CH_KERNEL_PATCH(coded_version) ((coded_version >> 0) & 0x3f)

/**
 * @brief ChibiOS thread states.
 */
static const char * const chibios_thread_states[] = { "READY", "CURRENT",
"WTSTART", "SUSPENDED", "QUEUED", "WTSEM", "WTMTX", "WTCOND", "SLEEPING",
"WTEXIT", "WTOREVT", "WTANDEVT", "SNDMSGQ", "SNDMSG", "WTMSG", "FINAL"
};

#define CHIBIOS_NUM_STATES ARRAY_SIZE(chibios_thread_states)

/* Maximum ChibiOS thread name. There is no real limit set by ChibiOS but 64
 * chars ought to be enough.
 */
#define CHIBIOS_THREAD_NAME_STR_SIZE (64)

struct chibios_params {
	const char *target_name;

	struct chibios_chdebug *signature;
	const struct rtos_register_stacking *stacking_info;
};

static struct chibios_params chibios_params_list[] = {
	{
	"cortex_m",							/* target_name */
	NULL,
	NULL,									/* stacking_info */
	},
	{
	"hla_target",							/* target_name */
	NULL,
	NULL,									/* stacking_info */
	}
};

static bool chibios_detect_rtos(struct target *target);
static int chibios_create(struct target *target);
static int chibios_update_threads(struct rtos *rtos);
static int chibios_get_thread_reg_list(struct rtos *rtos, int64_t thread_id,
		struct rtos_reg **reg_list, int *num_regs);
static int chibios_get_symbol_list_to_lookup(struct symbol_table_elem *symbol_list[]);

const struct rtos_type chibios_rtos = {
	.name = "chibios",

	.detect_rtos = chibios_detect_rtos,
	.create = chibios_create,
	.update_threads = chibios_update_threads,
	.get_thread_reg_list = chibios_get_thread_reg_list,
	.get_symbol_list_to_lookup = chibios_get_symbol_list_to_lookup,
};


/* In ChibiOS/RT 3.0 the rlist structure has become part of a system
 * data structure ch. We declare both symbols as optional and later
 * use whatever is available.
 */

enum chibios_symbol_values {
	CHIBIOS_VAL_RLIST = 0,
	CHIBIOS_VAL_CH = 1,
	CHIBIOS_VAL_CH_DEBUG = 2
};

static struct symbol_table_elem chibios_symbol_list[] = {
	{ "rlist", 0, true},		/* Thread ready list */
	{ "ch", 0, true},			/* System data structure */
	{ "ch_debug", 0, false},	/* Memory Signature containing offsets of fields in rlist */
	{ NULL, 0, false}
};

/* Offset of the rlist structure within the system data structure (ch) */
#define CH_RLIST_OFFSET 0x00

static int chibios_update_memory_signature(struct rtos *rtos)
{
	int retval;
	struct chibios_params *param;
	struct chibios_chdebug *signature;

	param = (struct chibios_params *) rtos->rtos_specific_params;

	/* Free existing memory description.*/
	free(param->signature);
	param->signature = NULL;

	signature = malloc(sizeof(*signature));
	if (!signature) {
		LOG_ERROR("Could not allocate space for ChibiOS/RT memory signature");
		return -1;
	}

	retval = target_read_buffer(rtos->target,
								rtos->symbols[CHIBIOS_VAL_CH_DEBUG].address,
								sizeof(*signature),
								(uint8_t *) signature);
	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read ChibiOS/RT memory signature from target");
		goto errfree;
	}

	if (strncmp(signature->ch_identifier, "main", 4) != 0) {
		LOG_ERROR("Memory signature identifier does not contain magic bytes.");
		goto errfree;
	}

	if (signature->ch_size < sizeof(*signature)) {
		LOG_ERROR("ChibiOS/RT memory signature claims to be smaller "
				"than expected");
		goto errfree;
	}

	if (signature->ch_size > sizeof(*signature)) {
		LOG_WARNING("ChibiOS/RT memory signature claims to be bigger than"
					" expected. Assuming compatibility...");
	}

	const uint16_t ch_version = target_buffer_get_u16(rtos->target, signature->ch_version);
	LOG_INFO("Successfully loaded memory map of ChibiOS/RT target "
			"running version %i.%i.%i", GET_CH_KERNEL_MAJOR(ch_version),
			GET_CH_KERNEL_MINOR(ch_version), GET_CH_KERNEL_PATCH(ch_version));

	/* Currently, we have the inherent assumption that all address pointers
	 * are 32 bit wide. */
	if (signature->ch_ptrsize != sizeof(uint32_t)) {
		LOG_ERROR("ChibiOS/RT target memory signature claims an address "
				  "width unequal to 32 bits!");
		free(signature);
		return -1;
	}

	param->signature = signature;
	return 0;

errfree:
	/* Error reading the ChibiOS memory structure */
	free(signature);
	param->signature = NULL;
	return -1;
}


static int chibios_update_stacking(struct rtos *rtos)
{
	/* Sometimes the stacking can not be determined only by looking at the
	 * target name but only a runtime.
	 *
	 * For example, this is the case for Cortex-M4 targets and ChibiOS which
	 * only stack the FPU registers if it is enabled during ChibiOS build.
	 *
	 * Terminating which stacking is used is target depending.
	 *
	 * Assumptions:
	 *  - Once ChibiOS is actually initialized, the stacking is fixed.
	 *  - During startup code, the FPU might not be initialized and the
	 *    detection might fail.
	 *  - Since no threads are running during startup, the problem is solved
	 *    by delaying stacking detection until there are more threads
	 *    available than the current execution. In which case
	 *    chibios_get_thread_reg_list is called.
	 */
	int retval;

	if (!rtos->rtos_specific_params)
		return -1;

	struct chibios_params *param;
	param = (struct chibios_params *) rtos->rtos_specific_params;

	/* Check for armv7m with *enabled* FPU, i.e. a Cortex-M4  */
	struct armv7m_common *armv7m_target = target_to_armv7m(rtos->target);
	if (is_armv7m(armv7m_target)) {
		if (armv7m_target->fp_feature != FP_NONE) {
			/* Found ARM v7m target which includes a FPU */
			uint32_t cpacr;

			retval = target_read_u32(rtos->target, FPU_CPACR, &cpacr);
			if (retval != ERROR_OK) {
				LOG_ERROR("Could not read CPACR register to check FPU state");
				return -1;
			}

			/* Check if CP10 and CP11 are set to full access.
			 * In ChibiOS this is done in ResetHandler() in crt0.c */
			if (cpacr & 0x00F00000) {
				LOG_DEBUG("Enabled FPU detected.");
				param->stacking_info = &rtos_chibios_arm_v7m_stacking_w_fpu;
				return 0;
			}
		}

		/* Found ARM v7m target with no or disabled FPU */
		param->stacking_info = &rtos_chibios_arm_v7m_stacking;
		return 0;
	}

	return -1;
}

static int chibios_update_threads(struct rtos *rtos)
{
	int retval;
	const struct chibios_params *param;
	int tasks_found = 0;
	int rtos_valid = -1;

	if (!rtos->rtos_specific_params)
		return -1;

	if (!rtos->symbols) {
		LOG_ERROR("No symbols for ChibiOS");
		return -3;
	}

	param = (const struct chibios_params *) rtos->rtos_specific_params;
	/* Update the memory signature saved in the target memory */
	if (!param->signature) {
		retval = chibios_update_memory_signature(rtos);
		if (retval != ERROR_OK) {
			LOG_ERROR("Reading the memory signature of ChibiOS/RT failed");
			return retval;
		}
	}

	/* wipe out previous thread details if any */
	rtos_free_threadlist(rtos);

	/* ChibiOS does not save the current thread count. We have to first
	 * parse the double linked thread list to check for errors and the number of
	 * threads. */
	const uint32_t rlist = rtos->symbols[CHIBIOS_VAL_RLIST].address ?
		rtos->symbols[CHIBIOS_VAL_RLIST].address :
		rtos->symbols[CHIBIOS_VAL_CH].address + CH_RLIST_OFFSET /* ChibiOS3 */;
	const struct chibios_chdebug *signature = param->signature;
	uint32_t current;
	uint32_t previous;
	uint32_t older;

	current = rlist;
	previous = rlist;
	while (1) {
		retval = target_read_u32(rtos->target,
								 current + signature->cf_off_newer, &current);
		if (retval != ERROR_OK) {
			LOG_ERROR("Could not read next ChibiOS thread");
			return retval;
		}
		/* Could be NULL if the kernel is not initialized yet or if the
		 * registry is corrupted. */
		if (current == 0) {
			LOG_ERROR("ChibiOS registry integrity check failed, NULL pointer");

			rtos_valid = 0;
			break;
		}
		/* Fetch previous thread in the list as a integrity check. */
		retval = target_read_u32(rtos->target,
								 current + signature->cf_off_older, &older);
		if ((retval != ERROR_OK) || (older == 0) || (older != previous)) {
			LOG_ERROR("ChibiOS registry integrity check failed, "
						"double linked list violation");
			rtos_valid = 0;
			break;
		}
		/* Check for full iteration of the linked list. */
		if (current == rlist)
			break;
		tasks_found++;
		previous = current;
	}
	if (!rtos_valid) {
		/* No RTOS, there is always at least the current execution, though */
		LOG_INFO("Only showing current execution because of a broken "
				"ChibiOS thread registry.");

		const char tmp_thread_name[] = "Current Execution";
		const char tmp_thread_extra_info[] = "No RTOS thread";

		rtos->thread_details = malloc(
				sizeof(struct thread_detail));
		rtos->thread_details->threadid = 1;
		rtos->thread_details->exists = true;

		rtos->thread_details->extra_info_str = malloc(
				sizeof(tmp_thread_extra_info));
		strcpy(rtos->thread_details->extra_info_str, tmp_thread_extra_info);

		rtos->thread_details->thread_name_str = malloc(
				sizeof(tmp_thread_name));
		strcpy(rtos->thread_details->thread_name_str, tmp_thread_name);

		rtos->current_thread = 1;
		rtos->thread_count = 1;
		return ERROR_OK;
	}

	/* create space for new thread details */
	rtos->thread_details = malloc(
			sizeof(struct thread_detail) * tasks_found);
	if (!rtos->thread_details) {
		LOG_ERROR("Could not allocate space for thread details");
		return -1;
	}

	rtos->thread_count = tasks_found;
	/* Loop through linked list. */
	struct thread_detail *curr_thrd_details = rtos->thread_details;
	while (curr_thrd_details < rtos->thread_details + tasks_found) {
		uint32_t name_ptr = 0;
		char tmp_str[CHIBIOS_THREAD_NAME_STR_SIZE];

		retval = target_read_u32(rtos->target,
								 current + signature->cf_off_newer, &current);
		if (retval != ERROR_OK) {
			LOG_ERROR("Could not read next ChibiOS thread");
			return -6;
		}

		/* Check for full iteration of the linked list. */
		if (current == rlist)
			break;

		/* Save the thread pointer */
		curr_thrd_details->threadid = current;

		/* read the name pointer */
		retval = target_read_u32(rtos->target,
								 current + signature->cf_off_name, &name_ptr);
		if (retval != ERROR_OK) {
			LOG_ERROR("Could not read ChibiOS thread name pointer from target");
			return retval;
		}

		/* Read the thread name */
		retval = target_read_buffer(rtos->target, name_ptr,
									CHIBIOS_THREAD_NAME_STR_SIZE,
									(uint8_t *)&tmp_str);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error reading thread name from ChibiOS target");
			return retval;
		}
		tmp_str[CHIBIOS_THREAD_NAME_STR_SIZE - 1] = '\x00';

		if (tmp_str[0] == '\x00')
			strcpy(tmp_str, "No Name");

		curr_thrd_details->thread_name_str = malloc(
				strlen(tmp_str) + 1);
		strcpy(curr_thrd_details->thread_name_str, tmp_str);

		/* State info */
		uint8_t thread_state;
		const char *state_desc;

		retval = target_read_u8(rtos->target,
								current + signature->cf_off_state, &thread_state);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error reading thread state from ChibiOS target");
			return retval;
		}


		if (thread_state < CHIBIOS_NUM_STATES)
			state_desc = chibios_thread_states[thread_state];
		else
			state_desc = "Unknown";

		curr_thrd_details->extra_info_str = alloc_printf("State: %s", state_desc);
		if (!curr_thrd_details->extra_info_str) {
			LOG_ERROR("Could not allocate space for thread state description");
			return -1;
		}

		curr_thrd_details->exists = true;

		curr_thrd_details++;
	}

	uint32_t current_thrd;
	/* NOTE: By design, cf_off_name equals readylist_current_offset */
	retval = target_read_u32(rtos->target,
							 rlist + signature->cf_off_name,
							 &current_thrd);
	if (retval != ERROR_OK) {
		LOG_ERROR("Could not read current Thread from ChibiOS target");
		return retval;
	}
	rtos->current_thread = current_thrd;

	return 0;
}

static int chibios_get_thread_reg_list(struct rtos *rtos, int64_t thread_id,
		struct rtos_reg **reg_list, int *num_regs)
{
	int retval;
	const struct chibios_params *param;
	uint32_t stack_ptr = 0;

	if ((!rtos) || (thread_id == 0) ||
			(!rtos->rtos_specific_params))
		return -1;

	param = (const struct chibios_params *) rtos->rtos_specific_params;

	if (!param->signature)
		return -1;

	/* Update stacking if it can only be determined from runtime information */
	if (!param->stacking_info &&
		(chibios_update_stacking(rtos) != ERROR_OK)) {
		LOG_ERROR("Failed to determine exact stacking for the target type %s", target_type_name(rtos->target));
		return -1;
	}

	/* Read the stack pointer */
	retval = target_read_u32(rtos->target,
							 thread_id + param->signature->cf_off_ctx, &stack_ptr);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error reading stack frame from ChibiOS thread");
		return retval;
	}

	return rtos_generic_stack_read(rtos->target, param->stacking_info, stack_ptr, reg_list, num_regs);
}

static int chibios_get_symbol_list_to_lookup(struct symbol_table_elem *symbol_list[])
{
	*symbol_list = malloc(sizeof(chibios_symbol_list));

	if (!*symbol_list)
		return ERROR_FAIL;

	memcpy(*symbol_list, chibios_symbol_list, sizeof(chibios_symbol_list));
	return 0;
}

static bool chibios_detect_rtos(struct target *target)
{
	if ((target->rtos->symbols) &&
			((target->rtos->symbols[CHIBIOS_VAL_RLIST].address != 0) ||
			 (target->rtos->symbols[CHIBIOS_VAL_CH].address != 0))) {

		if (target->rtos->symbols[CHIBIOS_VAL_CH_DEBUG].address == 0) {
			LOG_INFO("It looks like the target may be running ChibiOS "
					"without ch_debug.");
			return false;
		}

		/* looks like ChibiOS with memory map enabled.*/
		return true;
	}

	return false;
}

static int chibios_create(struct target *target)
{
	for (unsigned int i = 0; i < ARRAY_SIZE(chibios_params_list); i++)
		if (strcmp(chibios_params_list[i].target_name, target_type_name(target)) == 0) {
			target->rtos->rtos_specific_params = (void *)&chibios_params_list[i];
			return ERROR_OK;
		}

	LOG_WARNING("Could not find target \"%s\" in ChibiOS compatibility "
				"list", target_type_name(target));
	return ERROR_FAIL;
}
