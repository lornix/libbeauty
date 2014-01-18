/*
 *  Copyright (C) 2004-2009 The libbeauty Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * 11-9-2004 Initial work.
 *   Copyright (C) 2004 James Courtier-Dutton James@superbug.co.uk
 * 10-11-2007 Updates.
 *   Copyright (C) 2007 James Courtier-Dutton James@superbug.co.uk
 * 10-10-2009 Updates.
 *   Copyright (C) 2007 James Courtier-Dutton James@superbug.co.uk
 */

/* Intel ia32 instruction format: -
 Instruction-Prefixes (Up to four prefixes of 1-byte each. [optional] )
 Opcode (1-, 2-, or 3-byte opcode)
 ModR/M (1 byte [if required] )
 SIB (Scale-Index-Base:1 byte [if required] )
 Displacement (Address displacement of 1, 2, or 4 bytes or none)
 Immediate (Immediate data of 1, 2, or 4 bytes or none)

 Naming convention taked from Intel Instruction set manual,
 Appendix A. 25366713.pdf
*/

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <rev.h>


uint64_t read_data(struct self_s *self, uint64_t offset, int size_bits) {
	uint64_t tmp, tmp2, tmp3, limit;
	int n;
	/* Convert bits to bytes. Round up. Make sure 1 bit turns into 1 byte */
	int size = (size_bits + 7) >> 3;

	tmp = 0;
	debug_print(DEBUG_EXE, 1, "read_data:offset = 0x%"PRIx64", size = %d\n", offset, size);
	limit = offset + size - 1;
	if (limit <= self->data_size) {
		for (n = (size - 1); n >= 0; n--) {
			tmp2 = (tmp << 8);
			tmp3 = self->data[n + offset];
			debug_print(DEBUG_EXE, 1, "read_data:data = 0x%"PRIx64"\n", tmp3);
			tmp = tmp2 | tmp3;
		}
	} else {
		debug_print(DEBUG_EXE, 1, "read_data: offset out of range\n");
		tmp = 0;
	}
	debug_print(DEBUG_EXE, 1, "read_data:return = 0x%"PRIx64"\n", tmp);
	
	return tmp;
}

	
	
struct memory_s *search_store(
	struct memory_s *memory, uint64_t index, int size_bits)
{
	int n = 0;
	uint64_t start = index;
	//uint64_t end = index + size;
	uint64_t memory_start;
	//uint64_t memory_end;
	struct memory_s *result = NULL;
	/* Convert bits to bytes. Round up. Make sure 1 bit turns into 1 byte */
	int size = (size_bits + 7) >> 3;

	debug_print(DEBUG_EXE, 1, "memory=%p, index=%"PRIx64", size=%d\n", memory, index, size);
	while (memory[n].valid == 1) {
		memory_start = memory[n].start_address;
		debug_print(DEBUG_EXE, 1, "looping 0x%x:start_address = 0x%"PRIx64"\n", n, memory_start);
		//memory_end = memory[n].start_address + memory[n].length;
		/* FIXME: for now ignore size */
/*		if ((start >= memory_start) &&
			(end <= memory_end)) {
*/
		if (start == memory_start) {
			result = &memory[n];
			debug_print(DEBUG_EXE, 1, "Found entry %d in table %p, %p\n", n, memory, result);
			break;
		}
		n++;
	}
	return result;
}

struct memory_s *add_new_store(
	struct memory_s *memory, uint64_t index, int size_bits)
{
	int n = 0;
	uint64_t start = index;
	//uint64_t end = index + size;
	uint64_t memory_start;
	//uint64_t memory_end;
	struct memory_s *result = NULL;
	/* Convert bits to bytes. Round up. Make sure 1 bit turns into 1 byte */
	int size = (size_bits + 7) >> 3;

	debug_print(DEBUG_EXE, 1, "add_new_store: memory=%p, index=0x%"PRIx64", size=%d\n", memory, index, size);
	while (memory[n].valid == 1) {
		memory_start = memory[n].start_address;
		debug_print(DEBUG_EXE, 1, "looping 0x%x:start_address = 0x%"PRIx64"\n", n, memory_start);
		//memory_end = memory[n].start_address + memory[n].length;
		/* FIXME: for now ignore size */
/*		if ((start >= memory_start) &&
			(end <= memory_end)) {
*/
		if (start == memory_start) {
			result = NULL;
			/* Store already existed, so exit */
			goto exit_add_new_store;
		}
		n++;
	}
	result = &memory[n];
	debug_print(DEBUG_EXE, 1, "Found empty entry %d in table %p, %p\n", n, memory, result);
	result->start_address = index;
	result->length = size;
	/* unknown */
	result->init_value_type = 0;
	result->init_value = 0;
	result->offset_value = 0;
	/* unknown */
	result->value_type = 0;
	/* not set yet. */
	result->ref_memory = 0;
	/* not set yet. */
	result->ref_log = 0;
	/* unknown */
	result->value_scope = 0;
	/* Each time a new value is assigned, this value_id increases */
	result->value_id = 1;
	/* 1 - Entry Used */
	result->valid = 1;
exit_add_new_store:
	return result;
}

int print_store(struct memory_s *memory) {
	int n = 0;
	uint64_t memory_start;
	while (memory[n].valid == 1) {
		memory_start = memory[n].start_address;
		debug_print(DEBUG_EXE, 1, "looping print 0x%x: start_address = 0x%"PRIx64"\n", n, memory_start);
		n++;
	}
	debug_print(DEBUG_EXE, 1, "looping print 0x%x: finished\n", n);
	return 0;
}

static int source_equals_dest(struct operand_s *srcA, struct operand_s *dstA)
{
	int ret;
	/* Exclude value in comparison for XOR */
	if ((srcA->store == dstA->store) &&
		(srcA->indirect == dstA->indirect) &&
		(srcA->indirect_size == dstA->indirect_size) &&
		(srcA->index == dstA->index) &&
		(srcA->value_size == dstA->value_size)) {
		ret = 1;
	} else {
		ret = 0;
	}
	return ret;
}

static int get_value_RTL_instruction(
	struct self_s *self,
	struct process_state_s *process_state,
	struct operand_s *source,
	struct memory_s *destination,
	int info_id )
{
	struct memory_s *value = NULL;
	struct memory_s *value_data = NULL;
	struct memory_s *value_stack = NULL;
	uint64_t data_index;
	char *info = NULL;
	//struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	//int *memory_used;

	//memory_text = process_state->memory_text;
	memory_stack = process_state->memory_stack;
	memory_reg = process_state->memory_reg;
	memory_data = process_state->memory_data;
	//memory_used = process_state->memory_used;

	if (info_id == 0) info = "srcA";
	if (info_id == 1) info = "srcB";
	debug_print(DEBUG_EXE, 1, "get_value_RTL_instruction:%p, %p, %i\n", source, destination, info_id);
	switch (source->indirect) {
	case IND_DIRECT:
		/* Not indirect */
		debug_print(DEBUG_EXE, 1, "%s-direct\n", info);
		switch (source->store) {
		case STORE_DIRECT:
			/* i - immediate */
			debug_print(DEBUG_EXE, 1, "%s-immediate\n", info);
			debug_print(DEBUG_EXE, 1, "%s-relocated=0x%x\n", info, source->relocated);
			debug_print(DEBUG_EXE, 1, "index=%"PRIx64", size=%d\n",
					source->index,
					source->value_size);
			destination->start_address = 0;
			destination->length = source->value_size;
			/* known */
			destination->init_value_type = 1;
			destination->init_value = source->index;
			destination->offset_value = 0;
			/* unknown */
			destination->value_type = 0;
			/* not set yet. */
			destination->ref_memory = 0;
			/* not set yet. */
			destination->ref_log = 0;
			/* unknown */
			/* FIXME: Do we need a special value for this. E.g. for CONSTANT */
			destination->value_scope = 0;
			/* 1 - Entry Used */
			destination->value_id = 0;
			destination->valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				destination->init_value,
				destination->offset_value,
				destination->init_value +
					 destination->offset_value);
			break;
		case STORE_REG:
			/* r - register */
			debug_print(DEBUG_EXE, 1, "%s-register\n", info);
			debug_print(DEBUG_EXE, 1, "index=%"PRIx64", size=%d\n",
					source->index,
					source->value_size);
			value = search_store(memory_reg,
					source->index,
					source->value_size);
			debug_print(DEBUG_EXE, 1, "GET:EXE value=%p\n", value);
			if (value) {
				debug_print(DEBUG_EXE, 1, "value_id = 0x%"PRIx64"\n", value->value_id);
				debug_print(DEBUG_EXE, 1, "init_value = 0x%"PRIx64", offset_value = 0x%"PRIx64", start_address = 0x%"PRIx64", length = 0x%x\n",
					value->init_value, value->offset_value,
					value->start_address, value->length);
			}
			/* FIXME what to do in NULL */
			if (!value) {
				value = add_new_store(memory_reg,
						source->index,
						source->value_size);
				value->value_id = 0;
				value->value_scope = 1;
				if (1 == info_id) {
					value->value_scope = 2;
				}
			}
			if (!value) {
				debug_print(DEBUG_EXE, 1, "GET CASE0:STORE_REG ERROR!\n");
				return 1;
				break;
			}
			destination->start_address = value->start_address;
			destination->length = value->length;
			destination->init_value_type = value->init_value_type;
			destination->init_value = value->init_value;
			destination->offset_value = value->offset_value;
			destination->value_type = value->value_type;
			destination->ref_memory =
				value->ref_memory;
			destination->ref_log =
				value->ref_log;
			destination->value_scope = value->value_scope;
			/* local counter */
			destination->value_id = value->value_id;
			/* 1 - Entry Used */
			destination->valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				destination->init_value,
				destination->offset_value,
				destination->init_value +
					destination->offset_value);
			break;
		default:
			/* Should not get here */
			debug_print(DEBUG_EXE, 1, "FAILED\n");
			return 1;
		}
		break;
	case IND_MEM:
		/* m - memory */
		debug_print(DEBUG_EXE, 1, "%s-indirect\n", info);
		debug_print(DEBUG_EXE, 1, "%s-memory\n", info);
		debug_print(DEBUG_EXE, 1, "index=%"PRIx64", indirect_size=%d, value_size=%d\n",
				source->index,
				source->indirect_size,
				source->value_size);
		switch (source->store) {
		case STORE_DIRECT:
			data_index = source->index;
			break;
		case STORE_REG:
			value = search_store(memory_reg,
					source->index,
					source->indirect_size);
			debug_print(DEBUG_EXE, 1, "EXE value=%p\n", value);
			/* FIXME what to do in NULL */
			if (!value) {
				value = add_new_store(memory_reg,
						source->index,
						source->indirect_size);
				value->value_id = 0;
			}
			if (!value) {
				debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG ERROR!\n");
				return 1;
				break;
			}
			data_index = value->init_value + value->offset_value;
			destination->indirect_value_id = value->value_id;
			break;
		default:
			/* Should not get here */
			debug_print(DEBUG_EXE, 1, "FAILED\n");
			return 1;
			break;
		}
		value_data = search_store(memory_data,
				data_index,
				source->value_size);
		debug_print(DEBUG_EXE, 1, "EXE2 value_data=%p, %p\n", value_data, &value_data);
		if (!value_data) {
			value_data = add_new_store(memory_data,
				data_index,
				source->value_size);
			value_data->init_value = read_data(self, data_index, 32); 
			debug_print(DEBUG_EXE, 1, "EXE3 value_data=%p, %p\n", value_data, &value_data);
			debug_print(DEBUG_EXE, 1, "EXE3 value_data->init_value=%"PRIx64"\n", value_data->init_value);
			/* Data */
			value_data->value_scope = 3;
			/* Param number */
			value_data->value_id = 0;
		}
		debug_print(DEBUG_EXE, 1, "variable on data:0x%"PRIx64"\n",
			data_index);
		if (!value_data) {
			debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG2 ERROR!\n");
			return 1;
			break;
		}
		destination->start_address = value_data->start_address;
		destination->length = value_data->length;
		destination->init_value_type = value_data->init_value_type;
		destination->init_value = value_data->init_value;
		destination->offset_value = value_data->offset_value;
		destination->indirect_init_value = value->init_value;
		destination->indirect_offset_value = value->offset_value;
		destination->value_type = value_data->value_type;
		destination->ref_memory =
			value_data->ref_memory;
		destination->ref_log =
			value_data->ref_log;
		destination->value_scope = value_data->value_scope;
		/* counter */
		destination->value_id = value_data->value_id;
		debug_print(DEBUG_EXE, 1, "%s: scope=%d, id=%"PRIu64"\n",
			info,
			destination->value_scope,
			destination->value_id);
		/* 1 - Entry Used */
		destination->valid = 1;
		debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
			destination->init_value,
			destination->offset_value,
			destination->init_value +
				destination->offset_value);
		break;
	case IND_STACK:
		/* s - stack */
		debug_print(DEBUG_EXE, 1, "%s-indirect\n", info);
		debug_print(DEBUG_EXE, 1, "%s-stack\n", info);
		debug_print(DEBUG_EXE, 1, "index=%"PRIx64", indirect_size=%d, value_size=%d\n",
				source->index,
				source->indirect_size,
				source->value_size);
		value = search_store(memory_reg,
				source->index,
				source->indirect_size);
		debug_print(DEBUG_EXE, 1, "EXE value=%p\n", value);
		/* FIXME what to do in NULL */
		if (!value) {
			value = add_new_store(memory_reg,
					source->index,
					source->indirect_size);
			value->value_id = 0;
		}
		if (!value) {
			debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG ERROR!\n");
			return 1;
			break;
		}
		value_stack = search_store(memory_stack,
				value->init_value +
					value->offset_value,
					source->value_size);
		debug_print(DEBUG_EXE, 1, "EXE2 value_stack=%p, %p\n", value_stack, &value_stack);
		if (!value_stack) {
			value_stack = add_new_store(memory_stack,
				value->init_value +
					value->offset_value,
					source->value_size);
			debug_print(DEBUG_EXE, 1, "EXE3 value_stack=%p, %p\n", value_stack, &value_stack);
			/* Only do this init on new stores */
			/* FIXME: 0x10000 should be a global variable */
			/* because it should match the ESP entry value */
			if ((value->init_value +
				value->offset_value) > 0x10000) {
				debug_print(DEBUG_EXE, 1, "PARAM\n");
				/* Param */
				value_stack->value_scope = 1;
				/* Param number */
				value_stack->value_id = 0;
			} else {
				debug_print(DEBUG_EXE, 1, "LOCAL\n");
				/* Local */
				value_stack->value_scope = 2;
				/* Local number */
				value_stack->value_id = 0;
			}
/* Section ends */
		}
		debug_print(DEBUG_EXE, 1, "variable on stack:0x%"PRIx64"\n",
			value->init_value + value->offset_value);
		if (!value_stack) {
			debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG2 ERROR!\n");
			return 1;
			break;
		}
		destination->start_address = 0;
		destination->length = value_stack->length;
		destination->init_value_type = value_stack->init_value_type;
		destination->init_value = value_stack->init_value;
		destination->offset_value = value_stack->offset_value;
		destination->indirect_init_value = value->init_value;
		destination->indirect_offset_value = value->offset_value;
		destination->value_type = value_stack->value_type;
		destination->ref_memory =
			value_stack->ref_memory;
		destination->ref_log =
			value_stack->ref_log;
		destination->value_scope = value_stack->value_scope;
		/* counter */
		destination->value_id = value_stack->value_id;
		debug_print(DEBUG_EXE, 1, "%s: scope=%d, id=%"PRIu64"\n",
			info,
			destination->value_scope,
			destination->value_id);
		/* 1 - Entry Used */
		destination->valid = 1;
		debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
			destination->init_value,
			destination->offset_value,
			destination->init_value +
				destination->offset_value);
		break;
	default:
		/* Should not get here */
		debug_print(DEBUG_EXE, 1, "FAILED\n");
		return 1;
	}
	print_store(memory_reg);
	print_store(memory_stack);
	return 0;
}

static int put_value_RTL_instruction( 
	struct self_s *self,
	struct process_state_s *process_state,
	struct inst_log_entry_s *inst)
{
	struct instruction_s *instruction;
	struct memory_s *value;
//	struct memory_s *value_mem;
	struct memory_s *value_data;
	struct memory_s *value_stack;
	uint64_t data_index;
	//struct memory_s *memory_text;
	struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	struct memory_s *memory_data;
	//int *memory_used;
	int result = 1;

	//memory_text = process_state->memory_text;
	memory_stack = process_state->memory_stack;
	memory_reg = process_state->memory_reg;
	memory_data = process_state->memory_data;
	//memory_used = process_state->memory_used;

	/* Put result in dstA */
	instruction = &inst->instruction;
	switch (instruction->dstA.indirect) {
	case IND_DIRECT:
		/* Not indirect */
		debug_print(DEBUG_EXE, 1, "dstA-direct\n");
		switch (instruction->dstA.store) {
		case STORE_DIRECT:
			/* i - immediate */
			debug_print(DEBUG_EXE, 1, "dstA-immediate-THIS SHOULD NEVER HAPPEN!\n");
			result = 1;
			goto exit_put_value;
			break;
		case STORE_REG:
			/* r - register */
			debug_print(DEBUG_EXE, 1, "dstA-register saving result\n");
			value = search_store(memory_reg,
					instruction->dstA.index,
					instruction->dstA.value_size);
			debug_print(DEBUG_EXE, 1, "EXE value=%p\n", value);
			if (value) {
				debug_print(DEBUG_EXE, 1, "init_value = 0x%"PRIx64", offset_value = 0x%"PRIx64", start_address = 0x%"PRIx64", length = 0x%x\n",
					value->init_value, value->offset_value,
					value->start_address, value->length);
			}
			/* FIXME what to do in NULL */
			if (!value) {
				debug_print(DEBUG_EXE, 1, "WHY!!!!!\n");
				value = add_new_store(memory_reg,
						instruction->dstA.index,
						instruction->dstA.value_size);
			}
			if (!value) {
				debug_print(DEBUG_EXE, 1, "PUT CASE0:STORE_REG ERROR!\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			/* eip changing */
			/* Make the constant 0x24 configurable
			 * depending on CPU type.
			 */
			debug_print(DEBUG_EXE, 1, "STORE_REG: index=0x%"PRIx64", start_address=0x%"PRIx64"\n",
				instruction->dstA.index, value->start_address);
			if (value->start_address != instruction->dstA.index) {
				debug_print(DEBUG_EXE, 1, "STORE failure\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			if (value->start_address == 0x24) {
				debug_print(DEBUG_EXE, 1, "A JUMP or RET has occured\n");
			}

			/* FIXME: these should always be the same */
			/* value->length = inst->value3.length; */
			debug_print(DEBUG_EXE, 1, "STORING: value3.start_address 0x%"PRIx64" into value->start_address 0x%"PRIx64"\n",
				inst->value3.start_address, value->start_address);
			if (value->start_address != inst->value3.start_address) {
				debug_print(DEBUG_EXE, 1, "STORE failure2\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			
			value->start_address = inst->value3.start_address;
			value->init_value_type = inst->value3.init_value_type;
			value->init_value = inst->value3.init_value;
			value->offset_value = inst->value3.offset_value;
			value->value_type = inst->value3.value_type;
			value->ref_memory =
				inst->value3.ref_memory;
			value->ref_log =
				inst->value3.ref_log;
			value->value_scope = inst->value3.value_scope;
			/* 1 - Ids */
			value->value_id = inst->value3.value_id;
			debug_print(DEBUG_EXE, 1, "Saving to reg value_id of 0x%"PRIx64"\n", value->value_id);
			/* 1 - Entry Used */
			value->valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				value->init_value,
				value->offset_value,
				value->init_value + value->offset_value);
			result = 0;
			break;
		default:
			/* Should not get here */
			debug_print(DEBUG_EXE, 1, "FAILED\n");
			result = 1;
			goto exit_put_value;
		}
		break;
	case IND_MEM:
		/* m - memory */
		/* FIXME TODO */
		debug_print(DEBUG_EXE, 1, "dstA-indirect-NOT\n");
		debug_print(DEBUG_EXE, 1, "dstA-memory-NOT\n");
		debug_print(DEBUG_EXE, 1, "index=%"PRIx64", value_size=%d\n",
				instruction->dstA.index,
				instruction->dstA.value_size);
		switch (instruction->dstA.store) {
		case STORE_DIRECT:
			data_index = instruction->dstA.index;
			result = 0;
			break;
		case STORE_REG:
			value = search_store(memory_reg,
					instruction->dstA.index,
					instruction->dstA.indirect_size);
			debug_print(DEBUG_EXE, 1, "EXE value=%p\n", value);
			/* FIXME what to do in NULL */
			if (!value) {
				value = add_new_store(memory_reg,
						instruction->dstA.index,
						instruction->dstA.indirect_size);
				value->value_id = 0;
			}
			if (!value) {
				debug_print(DEBUG_EXE, 1, "GET CASE2:STORE_REG ERROR!\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			if (value->start_address != instruction->dstA.index) {
				debug_print(DEBUG_EXE, 1, "STORE failure\n");
				result = 1;
				goto exit_put_value;
				break;
			}
			data_index = value->init_value + value->offset_value;
			result = 0;
			break;
		default:
			/* Should not get here */
			debug_print(DEBUG_EXE, 1, "FAILED\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		value_data = search_store(memory_data,
				data_index,
				instruction->dstA.value_size);
		debug_print(DEBUG_EXE, 1, "EXE2 value_data=%p\n", value_data);
		if (!value_data) {
			value_data = add_new_store(memory_data,
				data_index,
				instruction->dstA.value_size);
		}
		if (!value_data) {
			debug_print(DEBUG_EXE, 1, "PUT CASE2:STORE_REG2 ERROR!\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		if (value_data->start_address != data_index) {
			debug_print(DEBUG_EXE, 1, "STORE DATA failure\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		/* FIXME: these should always be the same */
		/* value_data->length = inst->value3.length; */
		value_data->init_value_type = inst->value3.init_value_type;
		value_data->init_value = inst->value3.init_value;
		value_data->offset_value = inst->value3.offset_value;
		value_data->value_type = inst->value3.value_type;
		value_data->ref_memory =
			inst->value3.ref_memory;
		value_data->ref_log =
			inst->value3.ref_log;
		value_data->value_scope = inst->value3.value_scope;
		/* 1 - Ids */
		value_data->value_id = inst->value3.value_id;
		debug_print(DEBUG_EXE, 1, "PUT: scope=%d, id=%"PRIu64"\n",
			value_data->value_scope,
			value_data->value_id);
		/* 1 - Entry Used */
		value_data->valid = 1;
		debug_print(DEBUG_EXE, 1, "value_data=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
			value_data->init_value,
			value_data->offset_value,
			value_data->init_value + value_data->offset_value);
		result = 0;
		break;
	case IND_STACK:
		/* s - stack */
		debug_print(DEBUG_EXE, 1, "dstA-indirect\n");
		debug_print(DEBUG_EXE, 1, "dstA-stack saving result\n");
		debug_print(DEBUG_EXE, 1, "index=%"PRIx64", indirect_size=%d\n",
				instruction->dstA.index,
				instruction->dstA.indirect_size);
		value = search_store(memory_reg,
				instruction->dstA.index,
				instruction->dstA.indirect_size);
		debug_print(DEBUG_EXE, 1, "dstA reg 0x%"PRIx64" value = 0x%"PRIx64" + 0x%"PRIx64"\n", instruction->dstA.index, value->init_value, value->offset_value);
		/* FIXME what to do in NULL */
		if (!value) {
			value = add_new_store(memory_reg,
					instruction->dstA.index,
					instruction->dstA.indirect_size);
		}
		if (!value) {
			debug_print(DEBUG_EXE, 1, "PUT CASE2:STORE_REG ERROR!\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		if (value->start_address != instruction->dstA.index) {
			debug_print(DEBUG_EXE, 1, "STORE failure\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		value_stack = search_store(memory_stack,
				value->init_value +
					value->offset_value,
					instruction->dstA.value_size);
		debug_print(DEBUG_EXE, 1, "EXE2 value_stack=%p\n", value_stack);
		if (!value_stack) {
			value_stack = add_new_store(memory_stack,
				value->init_value +
					value->offset_value,
					instruction->dstA.value_size);
		}
		if (!value_stack) {
			debug_print(DEBUG_EXE, 1, "PUT CASE2:STORE_REG2 ERROR!\n");
			result = 1;
			goto exit_put_value;
			break;
		}
		/* FIXME: these should always be the same */
		/* value_stack->length = inst->value3.length; */
		value_stack->init_value_type = inst->value3.init_value_type;
		value_stack->init_value = inst->value3.init_value;
		value_stack->offset_value = inst->value3.offset_value;
		value_stack->value_type = inst->value3.value_type;
		value_stack->ref_memory =
			inst->value3.ref_memory;
		value_stack->ref_log =
			inst->value3.ref_log;
		value_stack->value_scope = inst->value3.value_scope;
		/* 1 - Ids */
		value_stack->value_id = inst->value3.value_id;
		debug_print(DEBUG_EXE, 1, "PUT: scope=%d, id=%"PRIu64"\n",
			value_stack->value_scope,
			value_stack->value_id);
		/* 1 - Entry Used */
		value_stack->valid = 1;
		debug_print(DEBUG_EXE, 1, "value_stack=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
			value_stack->init_value,
			value_stack->offset_value,
			value_stack->init_value + value_stack->offset_value);
		result = 0;
		break;
	default:
		/* Should not get here */
		debug_print(DEBUG_EXE, 1, "FAILED\n");
		result = 1;
		goto exit_put_value;
	}

exit_put_value:
	print_store(memory_reg);
	print_store(memory_stack);
	return result;
}







int execute_instruction(struct self_s *self, struct process_state_s *process_state, struct inst_log_entry_s *inst)
{
	struct instruction_s *instruction;
	struct memory_s *value;
	//struct memory_s *memory_text;
	//struct memory_s *memory_stack;
	struct memory_s *memory_reg;
	//struct memory_s *memory_data;
	//int *memory_used;
	struct operand_s operand;
	int16_t tmp16s;
	int32_t tmp32s;
	int64_t tmp64s;
	uint64_t tmp64u;
	int tmp;

	//memory_text = process_state->memory_text;
	//memory_stack = process_state->memory_stack;
	memory_reg = process_state->memory_reg;
	//memory_data = process_state->memory_data;
	//memory_used = process_state->memory_used;
	int ret = 0;

	instruction = &inst->instruction;

	print_inst_short(self, instruction);

	switch (instruction->opcode) {
	case NOP:
		/* Get value of srcA */
		//ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of dstA */
		//ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "NOP\n");
		//put_value_RTL_instruction(self, process_state, inst);
		break;
	case CMP:
		/* Currently, do the same as NOP */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "CMP\n");
		//debug_print(DEBUG_EXE, 1, "value1 = 0x%x, value2 = 0x%x\n", inst->value1, inst->value2);
		debug_print(DEBUG_EXE, 1, "value_scope1=0x%"PRIx32", value_scope2=0x%"PRIx32"\n",
			inst->value1.value_scope,
			inst->value2.value_scope);
		debug_print(DEBUG_EXE, 1, "value_type1=0x%"PRIx32", value_type2=0x%"PRIx32"\n",
			inst->value1.value_type,
			inst->value2.value_type);
		debug_print(DEBUG_EXE, 1, "value_id1=0x%"PRIx64", value_id2=0x%"PRIx64"\n",
			inst->value1.value_id,
			inst->value2.value_id);
		/* A CMP does not save any values */
		//put_value_RTL_instruction(self, inst);
		break;
	case MOV:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "MOV\n");
		debug_print(DEBUG_EXE, 1, "MOV dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			debug_print(DEBUG_EXE, 1, "ERROR: MOV set to dstA.indirect\n");
			exit(1);
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* MOV imm to local */
		if ((inst->value3.value_scope == 0) &&
			(STORE_DIRECT == instruction->srcA.store) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case LOAD:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "LOAD\n");
		debug_print(DEBUG_EXE, 1, "LOAD dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			debug_print(DEBUG_EXE, 1, "ERROR: LOAD set to dstA.indirect\n");
			exit(1);
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		inst->value3.value_scope = 2;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		//if ((inst->value3.value_scope == 1) &&
		//	(STORE_REG == instruction->dstA.store) &&
		//	(1 == inst->value1.value_scope) &&
		//	(0 == instruction->dstA.indirect)) {
		//	inst->value3.value_scope = 2;
		//}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case STORE:
		/* STORE is a special case where the indirect REG of IMM in the dstA is a direct REG or IMM in srcB */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "STORE\n");
		debug_print(DEBUG_EXE, 1, "STORE dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.start_address = inst->value2.start_address;
		inst->value3.length = inst->value2.length;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value2.init_value;
			inst->value3.indirect_offset_value =
				inst->value2.offset_value;
			inst->value3.indirect_value_id =
				inst->value2.value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		if (instruction->dstA.indirect == IND_STACK) {
			inst->value3.value_scope = 2;
		} else if (instruction->dstA.indirect == IND_MEM) {
			inst->value3.value_scope = 3;
		}

		
		//inst->value3.value_scope = 3;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		//if ((inst->value3.value_scope == 1) &&
		//	(STORE_REG == instruction->dstA.store) &&
		//	(1 == inst->value1.value_scope) &&
		//	(0 == instruction->dstA.indirect)) {
		//	inst->value3.value_scope = 2;
		//}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SEX:
		debug_print(DEBUG_EXE, 1, "SEX dest length = %d %d\n", inst->value1.length, inst->value3.length);
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SEX\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		/* Special case for SEX instruction. */
		/* FIXME: Stored value in reg store should be size modified */
		value = search_store(process_state->memory_reg,
				instruction->dstA.index,
				instruction->dstA.value_size);
		if (value) {
			/* Only update it if is is found */
			value->length = instruction->dstA.value_size;
		}
		debug_print(DEBUG_EXE, 1, "SEX dest length = %d %d\n", inst->value1.length, inst->value3.length);
		inst->value3.init_value_type = inst->value1.init_value_type;
		if (64 == inst->value3.length) {
			tmp32s = inst->value1.init_value;
			tmp64s = tmp32s;
			tmp64u = tmp64s;
		} else if (32 == inst->value3.length) {
			tmp16s = inst->value1.init_value;
			tmp32s = tmp16s;
			tmp64u = tmp32s;
		} else {
			debug_print(DEBUG_EXE, 1, "SEX length failure\n");
			return 1;
		}
		inst->value3.init_value = tmp64u;
		if (64 == inst->value3.length) {
			tmp32s = inst->value1.offset_value;
			tmp64s = tmp32s;
			tmp64u = tmp64s;
		} else if (32 == inst->value3.length) {
			tmp16s = inst->value1.offset_value;
			tmp32s = tmp16s;
			tmp64u = tmp32s;
		} else {
			debug_print(DEBUG_EXE, 1, "SEX length failure\n");
			return 1;
		}
		inst->value3.offset_value = tmp64u;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value2 values */
		//inst->value3.value_id = inst->value2.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case ADD:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "ADD\n");
		debug_print(DEBUG_EXE, 1, "ADD dest length = %d %d %d\n", inst->value1.length, inst->value2.length, inst->value3.length);
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value =
			inst->value1.offset_value + inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case ADC:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "ADC\n");
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case MUL:  /* Unsigned mul */
	case IMUL: /* FIXME: Handled signed case */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of dstA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "MUL\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value =
			((inst->value1.offset_value + inst->value1.init_value) 
			* (inst->value2.offset_value + inst->value2.init_value))
			 - inst->value1.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SUB:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SUB\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value -
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SBB:
		/* FIXME: Add support for the Carry bit */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SUB\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value -
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case TEST:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "TEST \n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value2.init_value) &
			inst->value1.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		/* Fixme handle saving flags */
		//put_value_RTL_instruction(self, process_state, inst);
		break;
	case rAND:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "AND \n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) &
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case OR:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "OR \n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) |
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case XOR:
		/* If XOR against itself, this is a special case of making a dst value out of a src value,
		    but not really using the src value. 
		    So, the source value cannot be considered a PARAM
		    If tmp == 0, set scope to PARAM in get_value_RTL_intruction.
		    If tmp == 1, set scope to LOCAL in get_value_RTL_intruction.
		    TODO: Change output .c code from "local1 ^= local1;" to "local1 = 0;"
		 */
		tmp = source_equals_dest(&(instruction->srcA), &(instruction->srcB));
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), tmp); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "XOR\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) ^
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case NEG:
		/* Get value of srcA */
		/* Could be replaced with a SUB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "NOT\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = 0 - (inst->value1.offset_value +
			inst->value1.init_value);
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case NOT:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "NOT\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = !(inst->value1.offset_value +
			inst->value1.init_value);
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SHL:
		/* This is an UNSIGNED operation */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SHL\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) <<
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SHR:
		/* This is an UNSIGNED operation */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SHR\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) >>
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SAL:
		/* This is an UNSIGNED operation */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SAL\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		/* FIXME: This is currently doing unsigned SHL instead of SAL */
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) <<
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case SAR:
		/* This is an UNSIGNED operation */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcB), &(inst->value2), 0); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "SAR\n");
		inst->value3.start_address = instruction->dstA.index;
		inst->value3.length = instruction->dstA.value_size;
		//inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = 0;
		/* FIXME: This is currently doing unsigned SHR instead of SAR */
		inst->value3.offset_value = (inst->value1.offset_value +
			inst->value1.init_value) >>
			inst->value2.init_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = inst->value1.value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case IF:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->dstA), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "IF\n");
		/* Create absolute JMP value in value3 */
		value = search_store(memory_reg,
				REG_IP,
				4);
		inst->value3.start_address = value->start_address;
		inst->value3.length = value->length;
		inst->value3.init_value_type = value->init_value_type;
		inst->value3.init_value = value->init_value;
		inst->value3.offset_value = value->offset_value +
			inst->value2.init_value;
		inst->value3.value_type = value->value_type;
		inst->value3.ref_memory =
			value->ref_memory;
		inst->value3.ref_log =
			value->ref_log;
		inst->value3.value_scope = value->value_scope;
		/* Counter */
		inst->value3.value_id = value->value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
		/* No put_RTL_value is done for an IF */
		break;
	case JMPT:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of srcB */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->dstA), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "JMPT\n");
		debug_print(DEBUG_EXE, 1, "JMPT dest length = %d %d %d\n", inst->value1.length, inst->value2.length, inst->value3.length);
		inst->value3.start_address = inst->value1.start_address;
		inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		inst->value3.value_type = inst->value1.value_type;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		/* Note: value_scope stays from the dst, not the src. */
		/* FIXME Maybe Exception is the MOV instruction */
		inst->value3.value_scope = inst->value1.value_scope;
		/* MOV param to local */
		/* When the destination is a param_reg,
		 * Change it to a local_reg */
		if ((inst->value3.value_scope == 1) &&
			(STORE_REG == instruction->dstA.store) &&
			(1 == inst->value1.value_scope) &&
			(0 == instruction->dstA.indirect)) {
			inst->value3.value_scope = 2;
		}
		/* Counter */
		//if (inst->value3.value_scope == 2) {
			/* Only value_id preserves the value1 values */
		//inst->value3.value_id = inst->value1.value_id;
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		//}
		/* 1 - Entry Used */
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		break;
	case JMP:
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0); 
		/* Get value of dstA */
		//ret = get_value_RTL_instruction(self,  &(instruction->dstA), &(inst->value2), 1); 
		/* Create result */
		debug_print(DEBUG_EXE, 1, "JMP\n");
		/* Create absolute JMP value in value3 */
		value = search_store(memory_reg,
				REG_IP,
				4);
		debug_print(DEBUG_EXE, 1, "JMP 0x%"PRIx64"+%"PRId64"\n",
			value->offset_value, inst->value1.init_value);
		inst->value3.start_address = value->start_address;
		inst->value3.length = value->length;
		inst->value3.init_value_type = value->init_value_type;
		inst->value3.init_value = value->init_value;
		inst->value3.offset_value = value->offset_value +
			inst->value1.init_value;
		inst->value3.value_type = value->value_type;
		inst->value3.ref_memory =
			value->ref_memory;
		inst->value3.ref_log =
			value->ref_log;
		inst->value3.value_scope = value->value_scope;
		/* Counter */
		inst->value3.value_id = value->value_id;
		/* 1 - Entry Used */
		inst->value3.valid = 1;
		/* update EIP */
		value->offset_value = inst->value3.offset_value;
		break;
	case CALL:
		/* FIXME */
		/* On entry:
		 * srcA = relative offset which is value 1.
		 * dstA is destination EAX register which is value 2.
		 * with associated value1 and value2 
		 * On exit we have need:
		 * relative value coverted to ABS value.
		 * value1 = value1.  // Value 1 is useful for function pointer calls. 
		 * value3 = value2
		 * value2 = ESP
		 */
		/* Get value of srcA */
		ret = get_value_RTL_instruction(self, process_state, &(instruction->srcA), &(inst->value1), 0);
		value = search_store(memory_reg,
				REG_IP,
				4);
		debug_print(DEBUG_EXE, 1, "EXE CALL 0x%"PRIx64"+%"PRIx64"\n",
			value->offset_value, inst->value1.init_value);
		/* Make init_value +  offset_value = abs value */
		inst->value1.offset_value = inst->value1.init_value;
		inst->value1.init_value = value->offset_value;
 
		/* FIXME: Currently this is a NOP. */
		/* Get value of dstA */
		inst->value3.start_address = inst->value1.start_address;
		inst->value3.length = inst->value1.length;
		inst->value3.init_value_type = inst->value1.init_value_type;
		inst->value3.init_value = inst->value1.init_value;
		inst->value3.offset_value = inst->value1.offset_value;
		//inst->value3.value_type = inst->value1.value_type;
		inst->value3.value_type = 0;
		inst->value3.indirect_init_value =
			inst->value1.indirect_init_value;
		inst->value3.indirect_offset_value =
			inst->value1.indirect_offset_value;
		if (inst->instruction.dstA.indirect) {
			inst->value3.indirect_init_value =
				inst->value1.indirect_init_value;
			inst->value3.indirect_offset_value =
				inst->value1.indirect_offset_value;
			inst->value3.indirect_value_id =
				inst->value1.indirect_value_id;
		}
		inst->value3.ref_memory =
			inst->value1.ref_memory;
		inst->value3.ref_log =
			inst->value1.ref_log;
		inst->value3.value_scope = inst->value1.value_scope;
		/* Counter */
		inst->value3.value_id = 0;
		inst->value1.value_id = 0;
		/* 1 - Entry Used */
		inst->value1.valid = 1;
		inst->value3.valid = 1;
			debug_print(DEBUG_EXE, 1, "value=0x%"PRIx64"+0x%"PRIx64"=0x%"PRIx64"\n",
				inst->value3.init_value,
				inst->value3.offset_value,
				inst->value3.init_value +
					inst->value3.offset_value);
		put_value_RTL_instruction(self, process_state, inst);
		/* Once value3 is written, over write value1 with ESP */
		/* Get the current ESP value so one can convert function params to locals */
		operand.indirect = IND_DIRECT;
		operand.store = STORE_REG;
		operand.index = REG_SP;
		/* Need to find out if the reg is 32bit or 64bit. Use the REG_AX return value size */
		operand.value_size = instruction->dstA.value_size;

		ret = get_value_RTL_instruction(self, process_state, &(operand), &(inst->value1), 1); 
		break;

	default:
		debug_print(DEBUG_EXE, 1, "Unhandled EXE intruction 0x%x\n", instruction->opcode);
		ret = 1;
		break;
	}
	return ret;
}

