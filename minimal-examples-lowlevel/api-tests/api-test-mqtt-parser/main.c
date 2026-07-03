/*
 * lws-api-test-mqtt-parser
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Unit tests for MQTT parser primitives with fragmentation scenarios.
 * These tests are designed to catch bugs like commit 5719dbe9 where
 * the VBI parser failed when data arrived in multiple fragments.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>

/*
 * Internal MQTT parser types and functions - declarations for testing
 * These match the definitions in lib/roles/mqtt/private-lib-roles-mqtt.h
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

/* Function declarations - these are defined in lib/roles/mqtt/primitives.c */
extern int
lws_mqtt_vbi_encode(uint32_t value, void *buf);

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

/*
 * Topic matching return type
 */
typedef enum {
	LMMTR_TOPIC_NOMATCH		= 0,
	LMMTR_TOPIC_MATCH		= 1,
	LMMTR_TOPIC_MATCH_ERROR		= -1
} lws_mqtt_match_topic_return_t;

extern lws_mqtt_match_topic_return_t
lws_mqtt_is_topic_matched(const char *sub, const char *pub);

/*
 * VBI (Variable Byte Integer) test vectors
 * Values at encoding boundaries: 0, 127, 128, 16383, 16384, 2097151, 2097152, max
 */
struct vbi_test {
	const char *name;
	uint8_t data[4];
	size_t len;
	uint32_t expected_value;
	lws_mqtt_stateful_primitive_return_t expected_result;
};

static struct vbi_test vbi_tests[] = {
	/* Valid single-byte encodings */
	{ "vbi_0", { 0x00 }, 1, 0, LMSPR_COMPLETED },
	{ "vbi_1", { 0x01 }, 1, 1, LMSPR_COMPLETED },
	{ "vbi_127", { 0x7f }, 1, 127, LMSPR_COMPLETED },

	/* Valid two-byte encodings */
	{ "vbi_128", { 0x80, 0x01 }, 2, 128, LMSPR_COMPLETED },
	{ "vbi_255", { 0xff, 0x01 }, 2, 255, LMSPR_COMPLETED },
	{ "vbi_16383", { 0xff, 0x7f }, 2, 16383, LMSPR_COMPLETED },

	/* Valid three-byte encodings */
	{ "vbi_16384", { 0x80, 0x80, 0x01 }, 3, 16384, LMSPR_COMPLETED },
	{ "vbi_2097151", { 0xff, 0xff, 0x7f }, 3, 2097151, LMSPR_COMPLETED },

	/* Valid four-byte encodings */
	{ "vbi_2097152", { 0x80, 0x80, 0x80, 0x01 }, 4, 2097152, LMSPR_COMPLETED },
	{ "vbi_max", { 0xff, 0xff, 0xff, 0x7f }, 4, 268435455, LMSPR_COMPLETED },

	/* Invalid: continuation bit set on 4th byte (overflow) */
	{ "vbi_overflow", { 0x80, 0x80, 0x80, 0x80 }, 4, 0, LMSPR_FAILED_FORMAT },
};

/*
 * Multi-byte (2-byte and 4-byte big-endian) test vectors
 */
struct mb_test {
	const char *name;
	uint8_t data[4];
	size_t len;
	uint32_t expected_value;
};

static struct mb_test mb_2byte_tests[] = {
	{ "2byte_0", { 0x00, 0x00 }, 2, 0 },
	{ "2byte_1", { 0x00, 0x01 }, 2, 1 },
	{ "2byte_256", { 0x01, 0x00 }, 2, 256 },
	{ "2byte_0x1234", { 0x12, 0x34 }, 2, 0x1234 },
	{ "2byte_max", { 0xff, 0xff }, 2, 65535 },
};

static struct mb_test mb_4byte_tests[] = {
	{ "4byte_0", { 0x00, 0x00, 0x00, 0x00 }, 4, 0 },
	{ "4byte_1", { 0x00, 0x00, 0x00, 0x01 }, 4, 1 },
	{ "4byte_256", { 0x00, 0x00, 0x01, 0x00 }, 4, 256 },
	{ "4byte_0x12345678", { 0x12, 0x34, 0x56, 0x78 }, 4, 0x12345678 },
	{ "4byte_max", { 0xff, 0xff, 0xff, 0xff }, 4, 0xffffffff },
};

/*
 * Topic matching test vectors
 */
struct topic_test {
	const char *name;
	const char *sub;
	const char *pub;
	int expected_match; /* 1 = match, 0 = no match */
};

static struct topic_test topic_tests[] = {
	/* Exact matches */
	{ "exact_match", "foo/bar", "foo/bar", 1 },
	{ "exact_nomatch", "foo/bar", "foo/baz", 0 },
	{ "exact_prefix_nomatch", "foo/bar", "foo/bar/baz", 0 },
	{ "exact_suffix_nomatch", "foo/bar/baz", "foo/bar", 0 },

	/* Single-level wildcard + */
	{ "plus_middle", "foo/+/bar", "foo/xyz/bar", 1 },
	{ "plus_empty", "foo/+/bar", "foo//bar", 1 },
	{ "plus_start", "+/bar", "foo/bar", 1 },
	{ "plus_end", "foo/+", "foo/bar", 1 },
	{ "plus_nomatch_multi", "foo/+/bar", "foo/x/y/bar", 0 },

	/* Multi-level wildcard # */
	{ "hash_end", "foo/#", "foo/bar", 1 },
	{ "hash_multi", "foo/#", "foo/bar/baz", 1 },
	{ "hash_deep", "foo/#", "foo/a/b/c/d", 1 },
	{ "hash_all", "#", "foo/bar/baz", 1 },
	{ "hash_single", "#", "foo", 1 },
	{ "hash_empty_after_slash", "foo/bar/#", "foo/bar", 1 },

	/* Combined wildcards */
	{ "plus_hash", "foo/+/#", "foo/bar/baz/qux", 1 },
	{ "plus_hash_min", "foo/+/#", "foo/bar", 1 },

	/* Edge cases */
	{ "empty_topic", "", "", 1 },
	{ "single_level", "foo", "foo", 1 },
	{ "single_level_nomatch", "foo", "bar", 0 },
};

/*
 * Test VBI parsing with all-at-once delivery (baseline)
 */
static int
test_vbi_basic(void)
{
	int fail = 0;
	size_t i;

	lwsl_user("  VBI basic parsing tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(vbi_tests); i++) {
		struct vbi_test *t = &vbi_tests[i];
		lws_mqtt_vbi vbi;
		const uint8_t *p = t->data;
		size_t len = t->len;
		lws_mqtt_stateful_primitive_return_t r;

		lws_mqtt_vbi_init(&vbi);
		r = lws_mqtt_vbi_r(&vbi, &p, &len);

		if (r != t->expected_result) {
			lwsl_err("    FAIL %s: expected result %d, got %d\n",
				 t->name, t->expected_result, r);
			fail++;
			continue;
		}

		if (r == LMSPR_COMPLETED && vbi.value != t->expected_value) {
			lwsl_err("    FAIL %s: expected value %u, got %u\n",
				 t->name, t->expected_value, vbi.value);
			fail++;
			continue;
		}

		lwsl_user("    PASS %s\n", t->name);
	}

	return fail;
}

/*
 * Test VBI parsing with single-byte fragmentation (maximum fragmentation)
 * This is the scenario that caught the bug in commit 5719dbe9
 */
static int
test_vbi_fragmented_single_byte(void)
{
	int fail = 0;
	size_t i;

	lwsl_user("  VBI single-byte fragmentation tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(vbi_tests); i++) {
		struct vbi_test *t = &vbi_tests[i];
		lws_mqtt_vbi vbi;
		const uint8_t *p;
		size_t len;
		lws_mqtt_stateful_primitive_return_t r = LMSPR_NEED_MORE;
		size_t byte_idx;

		if (t->len < 2)
			continue; /* Skip single-byte tests */

		lws_mqtt_vbi_init(&vbi);
		p = t->data;

		/* Feed one byte at a time */
		for (byte_idx = 0; byte_idx < t->len && r == LMSPR_NEED_MORE; byte_idx++) {
			len = 1;
			r = lws_mqtt_vbi_r(&vbi, &p, &len);
		}

		if (r != t->expected_result) {
			lwsl_err("    FAIL %s (fragmented): expected result %d, got %d\n",
				 t->name, t->expected_result, r);
			fail++;
			continue;
		}

		if (r == LMSPR_COMPLETED && vbi.value != t->expected_value) {
			lwsl_err("    FAIL %s (fragmented): expected value %u, got %u\n",
				 t->name, t->expected_value, vbi.value);
			fail++;
			continue;
		}

		lwsl_user("    PASS %s (fragmented)\n", t->name);
	}

	return fail;
}

/*
 * Test VBI parsing with split-at-middle fragmentation
 */
static int
test_vbi_fragmented_split(void)
{
	int fail = 0;
	size_t i;

	lwsl_user("  VBI split fragmentation tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(vbi_tests); i++) {
		struct vbi_test *t = &vbi_tests[i];
		lws_mqtt_vbi vbi;
		const uint8_t *p;
		size_t len;
		lws_mqtt_stateful_primitive_return_t r;
		size_t split;

		if (t->len < 2)
			continue;

		/* Try splitting at each possible point */
		for (split = 1; split < t->len; split++) {
			lws_mqtt_vbi_init(&vbi);
			p = t->data;

			/* First chunk */
			len = split;
			r = lws_mqtt_vbi_r(&vbi, &p, &len);

			if (r == LMSPR_COMPLETED || r < 0) {
				/* Completed or error in first chunk - check result */
				if (r != t->expected_result && t->expected_result >= 0) {
					lwsl_err("    FAIL %s (split@%zu): early completion\n",
						 t->name, split);
					fail++;
				}
				continue;
			}

			/* Second chunk */
			len = t->len - split;
			r = lws_mqtt_vbi_r(&vbi, &p, &len);

			if (r != t->expected_result) {
				lwsl_err("    FAIL %s (split@%zu): expected %d, got %d\n",
					 t->name, split, t->expected_result, r);
				fail++;
				continue;
			}

			if (r == LMSPR_COMPLETED && vbi.value != t->expected_value) {
				lwsl_err("    FAIL %s (split@%zu): expected %u, got %u\n",
					 t->name, split, t->expected_value, vbi.value);
				fail++;
				continue;
			}
		}
		lwsl_user("    PASS %s (all splits)\n", t->name);
	}

	return fail;
}

/*
 * Test VBI encode/decode round-trip
 */
static int
test_vbi_encode_decode(void)
{
	int fail = 0;
	uint32_t test_values[] = { 0, 1, 127, 128, 255, 16383, 16384,
				   2097151, 2097152, 268435455 };
	size_t i;

	lwsl_user("  VBI encode/decode round-trip tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(test_values); i++) {
		uint32_t value = test_values[i];
		uint8_t buf[4];
		int encoded_len;
		lws_mqtt_vbi vbi;
		const uint8_t *p;
		size_t len;
		lws_mqtt_stateful_primitive_return_t r;

		/* Encode */
		encoded_len = lws_mqtt_vbi_encode(value, buf);
		if (encoded_len < 0) {
			lwsl_err("    FAIL encode %u: returned %d\n",
				 value, encoded_len);
			fail++;
			continue;
		}

		/* Decode */
		lws_mqtt_vbi_init(&vbi);
		p = buf;
		len = (size_t)encoded_len;
		r = lws_mqtt_vbi_r(&vbi, &p, &len);

		if (r != LMSPR_COMPLETED) {
			lwsl_err("    FAIL decode %u: result %d\n", value, r);
			fail++;
			continue;
		}

		if (vbi.value != value) {
			lwsl_err("    FAIL round-trip %u: got %u\n",
				 value, vbi.value);
			fail++;
			continue;
		}

		lwsl_user("    PASS round-trip %u (len=%d)\n", value, encoded_len);
	}

	return fail;
}

/*
 * Test multi-byte (2-byte) parsing
 */
static int
test_mb_2byte(void)
{
	int fail = 0;
	size_t i;

	lwsl_user("  2-byte parsing tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(mb_2byte_tests); i++) {
		struct mb_test *t = &mb_2byte_tests[i];
		lws_mqtt_vbi vbi;
		const uint8_t *p = t->data;
		size_t len = t->len;
		lws_mqtt_stateful_primitive_return_t r;

		lws_mqtt_2byte_init(&vbi);
		r = lws_mqtt_mb_parse(&vbi, &p, &len);

		if (r != LMSPR_COMPLETED) {
			lwsl_err("    FAIL %s: result %d\n", t->name, r);
			fail++;
			continue;
		}

		if (vbi.value != t->expected_value) {
			lwsl_err("    FAIL %s: expected %u, got %u\n",
				 t->name, t->expected_value, vbi.value);
			fail++;
			continue;
		}

		lwsl_user("    PASS %s\n", t->name);
	}

	return fail;
}

/*
 * Test multi-byte (2-byte) parsing with fragmentation
 */
static int
test_mb_2byte_fragmented(void)
{
	int fail = 0;
	size_t i;

	lwsl_user("  2-byte fragmented parsing tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(mb_2byte_tests); i++) {
		struct mb_test *t = &mb_2byte_tests[i];
		lws_mqtt_vbi vbi;
		const uint8_t *p;
		size_t len;
		lws_mqtt_stateful_primitive_return_t r;

		/* Feed one byte at a time */
		lws_mqtt_2byte_init(&vbi);
		p = t->data;

		len = 1;
		r = lws_mqtt_mb_parse(&vbi, &p, &len);
		if (r != LMSPR_NEED_MORE) {
			lwsl_err("    FAIL %s: first byte should need more\n", t->name);
			fail++;
			continue;
		}

		len = 1;
		r = lws_mqtt_mb_parse(&vbi, &p, &len);
		if (r != LMSPR_COMPLETED) {
			lwsl_err("    FAIL %s: result %d\n", t->name, r);
			fail++;
			continue;
		}

		if (vbi.value != t->expected_value) {
			lwsl_err("    FAIL %s: expected %u, got %u\n",
				 t->name, t->expected_value, vbi.value);
			fail++;
			continue;
		}

		lwsl_user("    PASS %s (fragmented)\n", t->name);
	}

	return fail;
}

/*
 * Test multi-byte (4-byte) parsing
 */
static int
test_mb_4byte(void)
{
	int fail = 0;
	size_t i;

	lwsl_user("  4-byte parsing tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(mb_4byte_tests); i++) {
		struct mb_test *t = &mb_4byte_tests[i];
		lws_mqtt_vbi vbi;
		const uint8_t *p = t->data;
		size_t len = t->len;
		lws_mqtt_stateful_primitive_return_t r;

		lws_mqtt_4byte_init(&vbi);
		r = lws_mqtt_mb_parse(&vbi, &p, &len);

		if (r != LMSPR_COMPLETED) {
			lwsl_err("    FAIL %s: result %d\n", t->name, r);
			fail++;
			continue;
		}

		if (vbi.value != t->expected_value) {
			lwsl_err("    FAIL %s: expected %u, got %u\n",
				 t->name, t->expected_value, vbi.value);
			fail++;
			continue;
		}

		lwsl_user("    PASS %s\n", t->name);
	}

	return fail;
}

/*
 * Test multi-byte (4-byte) parsing with fragmentation
 */
static int
test_mb_4byte_fragmented(void)
{
	int fail = 0;
	size_t i;

	lwsl_user("  4-byte fragmented parsing tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(mb_4byte_tests); i++) {
		struct mb_test *t = &mb_4byte_tests[i];
		lws_mqtt_vbi vbi;
		const uint8_t *p;
		size_t len;
		lws_mqtt_stateful_primitive_return_t r;
		int byte_idx;

		/* Feed one byte at a time */
		lws_mqtt_4byte_init(&vbi);
		p = t->data;

		for (byte_idx = 0; byte_idx < 4; byte_idx++) {
			len = 1;
			r = lws_mqtt_mb_parse(&vbi, &p, &len);

			if (byte_idx < 3 && r != LMSPR_NEED_MORE) {
				lwsl_err("    FAIL %s: byte %d should need more\n",
					 t->name, byte_idx);
				fail++;
				break;
			}
		}

		if (byte_idx < 4)
			continue;

		if (r != LMSPR_COMPLETED) {
			lwsl_err("    FAIL %s: final result %d\n", t->name, r);
			fail++;
			continue;
		}

		if (vbi.value != t->expected_value) {
			lwsl_err("    FAIL %s: expected %u, got %u\n",
				 t->name, t->expected_value, vbi.value);
			fail++;
			continue;
		}

		lwsl_user("    PASS %s (fragmented)\n", t->name);
	}

	return fail;
}

/*
 * Test topic matching
 */
static int
test_topic_matching(void)
{
	int fail = 0;
	size_t i;

	lwsl_user("  Topic matching tests\n");

	for (i = 0; i < LWS_ARRAY_SIZE(topic_tests); i++) {
		struct topic_test *t = &topic_tests[i];
		lws_mqtt_match_topic_return_t r;

		r = lws_mqtt_is_topic_matched(t->sub, t->pub);

		int matched = (r == LMMTR_TOPIC_MATCH);
		if (matched != t->expected_match) {
			lwsl_err("    FAIL %s: '%s' vs '%s' expected %s, got %s\n",
				 t->name, t->sub, t->pub,
				 t->expected_match ? "match" : "nomatch",
				 matched ? "match" : "nomatch");
			fail++;
			continue;
		}

		lwsl_user("    PASS %s\n", t->name);
	}

	return fail;
}

int main(int argc, const char **argv)
{
	int fail = 0;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: MQTT parser primitives\n\n");

	/* VBI tests */
	lwsl_user("VBI parsing tests:\n");
	fail += test_vbi_basic();
	fail += test_vbi_fragmented_single_byte();
	fail += test_vbi_fragmented_split();
	fail += test_vbi_encode_decode();

	/* Multi-byte tests */
	lwsl_user("\nMulti-byte parsing tests:\n");
	fail += test_mb_2byte();
	fail += test_mb_2byte_fragmented();
	fail += test_mb_4byte();
	fail += test_mb_4byte_fragmented();

	/* Topic matching tests */
	lwsl_user("\nTopic matching tests:\n");
	fail += test_topic_matching();

	lwsl_user("\n============================================\n");
	lwsl_user("Completed: %s (%d failures)\n",
		  fail ? "FAIL" : "PASS", fail);
	lwsl_user("============================================\n");

	return fail ? 1 : 0;
}
