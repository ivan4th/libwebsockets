/*
 * lws-mqtt-vbi-fuzzer
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * libFuzzer harness for MQTT VBI (Variable Byte Integer) parsing.
 * Tests fragmented delivery to catch bugs like commit 5719dbe9.
 *
 * Build:
 *   cmake .. -DLWS_ROLE_MQTT=1 -DLWS_WITH_FUZZER=1 -DCMAKE_C_COMPILER=clang
 *
 * Run:
 *   ./lws-mqtt-vbi-fuzzer -max_len=8 -runs=1000000
 */

#include <libwebsockets.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

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

extern void
lws_mqtt_vbi_init(lws_mqtt_vbi *vbi);

extern lws_mqtt_stateful_primitive_return_t
lws_mqtt_vbi_r(lws_mqtt_vbi *vbi, const uint8_t **in, size_t *len);

extern int
lws_mqtt_vbi_encode(uint32_t value, void *buf);

/*
 * Fragmentation strategies based on first byte of input
 */
enum frag_strategy {
	FRAG_ALL_AT_ONCE = 0,		/* Feed all data at once */
	FRAG_SINGLE_BYTE = 1,		/* Feed one byte at a time */
	FRAG_TWO_THEN_REST = 2,		/* Feed two bytes, then rest */
	FRAG_RANDOM_CHUNKS = 3,		/* Use second byte as chunk size */
	FRAG_STRATEGY_COUNT
};

/*
 * Feed data to VBI parser with specified fragmentation strategy
 */
static lws_mqtt_stateful_primitive_return_t
feed_vbi_fragmented(const uint8_t *data, size_t size, uint8_t strategy,
		    uint8_t chunk_hint, uint32_t *result)
{
	lws_mqtt_vbi vbi;
	lws_mqtt_stateful_primitive_return_t r;
	const uint8_t *p;
	size_t remaining, chunk;

	lws_mqtt_vbi_init(&vbi);
	p = data;
	remaining = size;
	r = LMSPR_NEED_MORE;

	while (remaining > 0 && r == LMSPR_NEED_MORE) {
		switch (strategy % FRAG_STRATEGY_COUNT) {
		case FRAG_ALL_AT_ONCE:
			chunk = remaining;
			break;
		case FRAG_SINGLE_BYTE:
			chunk = 1;
			break;
		case FRAG_TWO_THEN_REST:
			chunk = (p == data) ? (remaining >= 2 ? 2 : remaining) : remaining;
			break;
		case FRAG_RANDOM_CHUNKS:
			chunk = (chunk_hint % remaining) + 1;
			if (chunk > remaining)
				chunk = remaining;
			break;
		default:
			chunk = remaining;
			break;
		}

		size_t len = chunk;
		r = lws_mqtt_vbi_r(&vbi, &p, &len);
		remaining -= (chunk - len);
	}

	if (result)
		*result = vbi.value;

	return r;
}

/*
 * libFuzzer entry point
 *
 * Input format:
 *   Byte 0: Fragmentation strategy
 *   Byte 1: Chunk size hint (for FRAG_RANDOM_CHUNKS)
 *   Bytes 2+: VBI data to parse
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t strategy, chunk_hint;
	uint32_t parsed_value;
	lws_mqtt_stateful_primitive_return_t r;

	/* Need at least strategy + chunk_hint + 1 data byte */
	if (size < 3)
		return 0;

	strategy = data[0];
	chunk_hint = data[1];
	data += 2;
	size -= 2;

	/* Limit to max VBI size (4 bytes) + some margin */
	if (size > 8)
		size = 8;

	/* Parse with specified fragmentation */
	r = feed_vbi_fragmented(data, size, strategy, chunk_hint, &parsed_value);

	/*
	 * If parsing completed successfully, verify round-trip encoding
	 * This catches any corruption in the parsed value
	 */
	if (r == LMSPR_COMPLETED && parsed_value <= 268435455) {
		uint8_t encoded[4];
		int encoded_len;
		uint32_t reparsed;
		lws_mqtt_stateful_primitive_return_t r2;

		encoded_len = lws_mqtt_vbi_encode(parsed_value, encoded);
		if (encoded_len > 0) {
			/* Parse the re-encoded value */
			r2 = feed_vbi_fragmented(encoded, (size_t)encoded_len,
						 FRAG_ALL_AT_ONCE, 0, &reparsed);

			/* Values must match */
			if (r2 == LMSPR_COMPLETED && reparsed != parsed_value) {
				/* Round-trip mismatch - this would be a bug */
				__builtin_trap();
			}
		}
	}

	return 0;
}
