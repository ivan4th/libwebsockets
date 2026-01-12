/*
 * lws-mqtt-parser-fuzzer
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * libFuzzer harness for all MQTT parser primitives.
 * Tests VBI, 2-byte, 4-byte, and string parsing with fragmentation.
 *
 * Build:
 *   cmake .. -DLWS_ROLE_MQTT=1 -DLWS_WITH_FUZZER=1 -DCMAKE_C_COMPILER=clang
 *
 * Run:
 *   ./lws-mqtt-parser-fuzzer -max_len=1024 -runs=1000000
 */

#include <libwebsockets.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

/*
 * Internal MQTT parser types - matching lib/roles/mqtt/private-lib-roles-mqtt.h
 */
typedef enum {
	LMSPR_COMPLETED			=  0,
	LMSPR_NEED_MORE			=  1,
	LMSPR_FAILED_OOM		= -1,
	LMSPR_FAILED_OVERSIZE		= -2,
	LMSPR_FAILED_FORMAT		= -3,
	LMSPR_FAILED_ALREADY_COMPLETED	= -4,
} lws_mqtt_stateful_primitive_return_t;

typedef struct {
	uint32_t value;
	char budget;
	char consumed;
} lws_mqtt_vbi;

typedef struct {
	char *buf;
	uint16_t pos;
	uint16_t len;
	uint16_t len_valid;
	uint16_t limit;
} lws_mqtt_str_st;

extern void
lws_mqtt_vbi_init(lws_mqtt_vbi *vbi);

extern void
lws_mqtt_2byte_init(lws_mqtt_vbi *vbi);

extern void
lws_mqtt_4byte_init(lws_mqtt_vbi *vbi);

extern lws_mqtt_stateful_primitive_return_t
lws_mqtt_vbi_r(lws_mqtt_vbi *vbi, const uint8_t **in, size_t *len);

extern lws_mqtt_stateful_primitive_return_t
lws_mqtt_mb_parse(lws_mqtt_vbi *vbi, const uint8_t **in, size_t *len);

extern lws_mqtt_stateful_primitive_return_t
lws_mqtt_str_parse(lws_mqtt_str_st *s, const uint8_t **in, size_t *len);

/*
 * Parser type selection
 */
enum parser_type {
	PARSER_VBI = 0,
	PARSER_2BYTE = 1,
	PARSER_4BYTE = 2,
	PARSER_STRING = 3,
	PARSER_TYPE_COUNT
};

/*
 * Fragmentation strategies
 */
enum frag_strategy {
	FRAG_ALL_AT_ONCE = 0,
	FRAG_SINGLE_BYTE = 1,
	FRAG_RANDOM_CHUNKS = 2,
	FRAG_STRATEGY_COUNT
};

/*
 * Test VBI parser with fragmentation
 */
static lws_mqtt_stateful_primitive_return_t
fuzz_vbi(const uint8_t *data, size_t size, uint8_t strategy, uint8_t chunk_hint)
{
	lws_mqtt_vbi vbi;
	lws_mqtt_stateful_primitive_return_t r;
	const uint8_t *p = data;
	size_t remaining = size;

	lws_mqtt_vbi_init(&vbi);
	r = LMSPR_NEED_MORE;

	while (remaining > 0 && r == LMSPR_NEED_MORE) {
		size_t chunk;

		switch (strategy % FRAG_STRATEGY_COUNT) {
		case FRAG_ALL_AT_ONCE:
			chunk = remaining;
			break;
		case FRAG_SINGLE_BYTE:
			chunk = 1;
			break;
		case FRAG_RANDOM_CHUNKS:
			chunk = (chunk_hint % remaining) + 1;
			break;
		default:
			chunk = remaining;
			break;
		}

		size_t len = chunk;
		r = lws_mqtt_vbi_r(&vbi, &p, &len);
		remaining -= (chunk - len);
	}

	return r;
}

/*
 * Test 2-byte parser with fragmentation
 */
static lws_mqtt_stateful_primitive_return_t
fuzz_2byte(const uint8_t *data, size_t size, uint8_t strategy, uint8_t chunk_hint)
{
	lws_mqtt_vbi vbi;
	lws_mqtt_stateful_primitive_return_t r;
	const uint8_t *p = data;
	size_t remaining = size;

	lws_mqtt_2byte_init(&vbi);
	r = LMSPR_NEED_MORE;

	while (remaining > 0 && r == LMSPR_NEED_MORE) {
		size_t chunk;

		switch (strategy % FRAG_STRATEGY_COUNT) {
		case FRAG_ALL_AT_ONCE:
			chunk = remaining;
			break;
		case FRAG_SINGLE_BYTE:
			chunk = 1;
			break;
		case FRAG_RANDOM_CHUNKS:
			chunk = (chunk_hint % remaining) + 1;
			break;
		default:
			chunk = remaining;
			break;
		}

		size_t len = chunk;
		r = lws_mqtt_mb_parse(&vbi, &p, &len);
		remaining -= (chunk - len);
	}

	return r;
}

/*
 * Test 4-byte parser with fragmentation
 */
static lws_mqtt_stateful_primitive_return_t
fuzz_4byte(const uint8_t *data, size_t size, uint8_t strategy, uint8_t chunk_hint)
{
	lws_mqtt_vbi vbi;
	lws_mqtt_stateful_primitive_return_t r;
	const uint8_t *p = data;
	size_t remaining = size;

	lws_mqtt_4byte_init(&vbi);
	r = LMSPR_NEED_MORE;

	while (remaining > 0 && r == LMSPR_NEED_MORE) {
		size_t chunk;

		switch (strategy % FRAG_STRATEGY_COUNT) {
		case FRAG_ALL_AT_ONCE:
			chunk = remaining;
			break;
		case FRAG_SINGLE_BYTE:
			chunk = 1;
			break;
		case FRAG_RANDOM_CHUNKS:
			chunk = (chunk_hint % remaining) + 1;
			break;
		default:
			chunk = remaining;
			break;
		}

		size_t len = chunk;
		r = lws_mqtt_mb_parse(&vbi, &p, &len);
		remaining -= (chunk - len);
	}

	return r;
}

/*
 * Test string parser with fragmentation
 */
static lws_mqtt_stateful_primitive_return_t
fuzz_string(const uint8_t *data, size_t size, uint8_t strategy, uint8_t chunk_hint)
{
	lws_mqtt_str_st s;
	lws_mqtt_stateful_primitive_return_t r;
	const uint8_t *p = data;
	size_t remaining = size;
	char buf[512];  /* Max string buffer for fuzzing */

	memset(&s, 0, sizeof(s));
	s.buf = buf;
	s.limit = sizeof(buf) - 1;
	r = LMSPR_NEED_MORE;

	while (remaining > 0 && r == LMSPR_NEED_MORE) {
		size_t chunk;

		switch (strategy % FRAG_STRATEGY_COUNT) {
		case FRAG_ALL_AT_ONCE:
			chunk = remaining;
			break;
		case FRAG_SINGLE_BYTE:
			chunk = 1;
			break;
		case FRAG_RANDOM_CHUNKS:
			chunk = (chunk_hint % remaining) + 1;
			break;
		default:
			chunk = remaining;
			break;
		}

		size_t len = chunk;
		r = lws_mqtt_str_parse(&s, &p, &len);
		remaining -= (chunk - len);
	}

	return r;
}

/*
 * libFuzzer entry point
 *
 * Input format:
 *   Byte 0: Parser type (VBI, 2-byte, 4-byte, string)
 *   Byte 1: Fragmentation strategy
 *   Byte 2: Chunk size hint
 *   Bytes 3+: Data to parse
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t parser_type, strategy, chunk_hint;

	/* Need control bytes + at least 1 data byte */
	if (size < 4)
		return 0;

	parser_type = data[0];
	strategy = data[1];
	chunk_hint = data[2];
	data += 3;
	size -= 3;

	/* Limit data size to prevent excessive memory use */
	if (size > 512)
		size = 512;

	switch (parser_type % PARSER_TYPE_COUNT) {
	case PARSER_VBI:
		/* VBI max is 4 bytes */
		if (size > 8)
			size = 8;
		fuzz_vbi(data, size, strategy, chunk_hint);
		break;

	case PARSER_2BYTE:
		/* 2-byte parser needs 2 bytes */
		if (size > 4)
			size = 4;
		fuzz_2byte(data, size, strategy, chunk_hint);
		break;

	case PARSER_4BYTE:
		/* 4-byte parser needs 4 bytes */
		if (size > 8)
			size = 8;
		fuzz_4byte(data, size, strategy, chunk_hint);
		break;

	case PARSER_STRING:
		/* String parser: 2-byte length + data */
		fuzz_string(data, size, strategy, chunk_hint);
		break;
	}

	return 0;
}
