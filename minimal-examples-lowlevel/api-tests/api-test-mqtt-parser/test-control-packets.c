/*
 * test-unhandled-packets.c - Unit tests for PINGREQ, DISCONNECT, AUTH parsing
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * These tests verify that the MQTT parser correctly handles PINGREQ,
 * DISCONNECT, and AUTH packets. Currently these packet types are NOT
 * implemented - the parser falls through to a default case and returns
 * a protocol error.
 *
 * MQTT 5.0 Spec:
 *   - PINGREQ (0xC0): Fixed header only, remaining length = 0
 *   - DISCONNECT (0xE0): Optional reason code + properties
 *   - AUTH (0xF0): Reason code + properties (MQTT 5.0 only)
 *
 * Test expectation:
 *   - Initially: FAIL (parser rejects these packets)
 *   - After fix: PASS (parser accepts these packets)
 */

#include "private-lib-core.h"
#include "private-lib-roles-mqtt.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Global context and vhost */
static struct lws_context *g_ctx;
static struct lws_vhost *g_vhost;

/*
 * PINGREQ packet - simplest MQTT packet
 * Fixed header: 0xC0 (type=12, flags=0)
 * Remaining length: 0
 */
static const uint8_t pingreq_valid[] = {
	0xc0,  /* PINGREQ packet type */
	0x00   /* Remaining length: 0 */
};

/*
 * PINGREQ with invalid remaining length (should be rejected)
 */
static const uint8_t pingreq_invalid_remlen[] = {
	0xc0,  /* PINGREQ packet type */
	0x01,  /* Remaining length: 1 (invalid - must be 0) */
	0x00   /* Spurious byte */
};

/*
 * DISCONNECT packet - MQTT 3.1.1 style (no reason code)
 * Fixed header: 0xE0 (type=14, flags=0)
 * Remaining length: 0
 */
static const uint8_t disconnect_simple[] = {
	0xe0,  /* DISCONNECT packet type */
	0x00   /* Remaining length: 0 */
};

/*
 * DISCONNECT packet - MQTT 5.0 with reason code
 * Fixed header: 0xE0
 * Remaining length: 1
 * Reason code: 0x00 (Normal disconnection)
 */
static const uint8_t disconnect_with_reason[] = {
	0xe0,  /* DISCONNECT packet type */
	0x01,  /* Remaining length: 1 */
	0x00   /* Reason code: Normal disconnection */
};

/*
 * DISCONNECT packet - MQTT 5.0 with reason code and empty properties
 * Fixed header: 0xE0
 * Remaining length: 2
 * Reason code: 0x04 (Disconnect with Will Message)
 * Properties length: 0
 */
static const uint8_t disconnect_with_props[] = {
	0xe0,  /* DISCONNECT packet type */
	0x02,  /* Remaining length: 2 */
	0x04,  /* Reason code: Disconnect with Will Message */
	0x00   /* Properties length: 0 */
};

/*
 * AUTH packet - MQTT 5.0 authentication
 * Fixed header: 0xF0 (type=15, flags=0)
 * Remaining length: 2
 * Reason code: 0x00 (Success)
 * Properties length: 0
 */
static const uint8_t auth_simple[] = {
	0xf0,  /* AUTH packet type */
	0x02,  /* Remaining length: 2 */
	0x00,  /* Reason code: Success */
	0x00   /* Properties length: 0 */
};

/*
 * AUTH packet - MQTT 5.0 with Continue Authentication reason
 * Reason code: 0x18 (Continue authentication)
 */
static const uint8_t auth_continue[] = {
	0xf0,  /* AUTH packet type */
	0x02,  /* Remaining length: 2 */
	0x18,  /* Reason code: Continue authentication */
	0x00   /* Properties length: 0 */
};

/* Test case definition */
struct packet_test {
	const char *name;
	const uint8_t *data;
	size_t len;
	int should_accept;  /* 1 = valid packet, parser should accept */
	const char *description;
};

static const struct packet_test test_cases[] = {
	/* PINGREQ tests */
	{
		"PINGREQ valid",
		pingreq_valid,
		sizeof(pingreq_valid),
		1,
		"Valid PINGREQ with remaining length 0"
	},
	{
		"PINGREQ invalid remlen",
		pingreq_invalid_remlen,
		sizeof(pingreq_invalid_remlen),
		0,
		"Invalid PINGREQ with non-zero remaining length"
	},

	/* DISCONNECT tests */
	{
		"DISCONNECT simple",
		disconnect_simple,
		sizeof(disconnect_simple),
		1,
		"MQTT 3.1.1 DISCONNECT (no reason code)"
	},
	{
		"DISCONNECT with reason",
		disconnect_with_reason,
		sizeof(disconnect_with_reason),
		1,
		"MQTT 5.0 DISCONNECT with reason code"
	},
	{
		"DISCONNECT with props",
		disconnect_with_props,
		sizeof(disconnect_with_props),
		1,
		"MQTT 5.0 DISCONNECT with empty properties"
	},

	/* AUTH tests */
	{
		"AUTH simple",
		auth_simple,
		sizeof(auth_simple),
		1,
		"MQTT 5.0 AUTH with Success reason"
	},
	{
		"AUTH continue",
		auth_continue,
		sizeof(auth_continue),
		1,
		"MQTT 5.0 AUTH with Continue Authentication"
	},
};

#define NUM_TEST_CASES (sizeof(test_cases) / sizeof(test_cases[0]))

/* Minimal callback - does nothing */
static int
callback_mqtt_test(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	(void)wsi; (void)reason; (void)user; (void)in; (void)len;
	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "mqtt", callback_mqtt_test, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Create a minimal wsi structure for testing the parser directly.
 * Set up as a client in ESTABLISHED state (ready to receive these packets).
 */
static struct lws *
create_test_wsi(void)
{
	struct lws *wsi;

	wsi = lws_zalloc(sizeof(*wsi) + sizeof(struct _lws_mqtt_related),
			 "test-wsi");
	if (!wsi)
		return NULL;

	wsi->mqtt = (struct _lws_mqtt_related *)(wsi + 1);
	wsi->mqtt->wsi = wsi;
	wsi->a.context = g_ctx;
	wsi->a.vhost = g_vhost;
	wsi->a.protocol = &protocols[0];
	wsi->role_ops = &role_ops_mqtt;

	/* Set client role flag */
	wsi->wsistate |= LWSIFR_CLIENT;

	/* Initialize parser state - client in ESTABLISHED state */
	wsi->mqtt->client.par.state = LMQCPP_IDLE;
	wsi->mqtt->client.estate = LGSMQTT_ESTABLISHED;

	return wsi;
}

static void
destroy_test_wsi(struct lws *wsi)
{
	if (wsi) {
		if (wsi->mqtt && wsi->mqtt->rx_cpkt_param) {
			lws_mqtt_publish_param_t *pub =
				(lws_mqtt_publish_param_t *)wsi->mqtt->rx_cpkt_param;
			if (pub->topic)
				lws_free(pub->topic);
			lws_free(wsi->mqtt->rx_cpkt_param);
		}
		lws_free(wsi);
	}
}

/*
 * Test a single packet.
 * Returns:
 *   1 = parser accepted the packet
 *   0 = parser rejected the packet
 *  -1 = test setup error
 */
static int
test_packet(const struct packet_test *tc)
{
	struct lws *wsi = NULL;
	lws_mqtt_parser_t *par;
	int result = -1;
	int ret;

	/* Create test wsi */
	wsi = create_test_wsi();
	if (!wsi) {
		fprintf(stderr, "Failed to create test wsi\n");
		return -1;
	}

	par = &wsi->mqtt->client.par;

	/*
	 * Feed the packet to the parser.
	 *
	 * Returns:
	 *   0 = success (more data may be needed or packet complete)
	 *  -1 = error (including protocol errors)
	 */
	ret = _lws_mqtt_rx_parser(wsi, par, tc->data, tc->len);

	if (ret >= 0) {
		result = 1;  /* Accepted */
	} else {
		result = 0;  /* Rejected */
	}

	destroy_test_wsi(wsi);

	return result;
}

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	int not_implemented = 0;
	int tests_passed = 0;
	int tests_run = 0;
	int errors = 0;
	size_t i;

	(void)argc;
	(void)argv;

	lws_set_log_level(0, NULL);  /* Quiet for testing */

	printf("MQTT Parser PINGREQ/DISCONNECT/AUTH Tests\n");
	printf("==========================================\n\n");
	printf("Testing parser support for PINGREQ, DISCONNECT, and AUTH packets.\n");
	printf("These packet types require implementation in mqtt.c.\n\n");

	/* Create context for tests */
	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	g_ctx = lws_create_context(&info);
	if (!g_ctx) {
		fprintf(stderr, "Failed to create context\n");
		return 1;
	}

	/* Get vhost - required for parser to not crash */
	g_vhost = lws_get_vhost_by_name(g_ctx, "default");
	if (!g_vhost)
		g_vhost = lws_get_vhost_by_name(g_ctx, NULL);

	printf("%-25s %-10s %-10s %s\n", "Test Case", "Expected", "Actual", "Result");
	printf("%-25s %-10s %-10s %s\n", "---------", "--------", "------", "------");

	for (i = 0; i < NUM_TEST_CASES; i++) {
		const struct packet_test *tc = &test_cases[i];
		int result;
		int accepted;

		tests_run++;
		result = test_packet(tc);

		if (result < 0) {
			printf("%-25s %-10s %-10s ERROR\n",
			       tc->name,
			       tc->should_accept ? "ACCEPT" : "REJECT",
			       "ERROR");
			errors++;
			continue;
		}

		accepted = (result == 1);

		printf("%-25s %-10s %-10s ",
		       tc->name,
		       tc->should_accept ? "ACCEPT" : "REJECT",
		       accepted ? "ACCEPT" : "REJECT");

		if (accepted == tc->should_accept) {
			printf("PASS\n");
			tests_passed++;
		} else if (tc->should_accept && !accepted) {
			printf("FAIL (not implemented)\n");
			not_implemented++;
		} else {
			printf("FAIL\n");
			not_implemented++;
		}
	}

	printf("\n");
	printf("Results: %d/%d tests passed", tests_passed, tests_run);
	if (errors > 0)
		printf(", %d test errors", errors);
	if (not_implemented > 0)
		printf(", %d not implemented", not_implemented);
	printf("\n");

	lws_context_destroy(g_ctx);

	if (errors > 0) {
		printf("\nTEST ERROR: %d test(s) could not run.\n", errors);
		return 1;
	}

	if (not_implemented > 0) {
		printf("\n");
		printf("NOT IMPLEMENTED: Parser does not support these packet types.\n\n");
		printf("To fix, add handlers in lib/roles/mqtt/mqtt.c for:\n");
		printf("  - PINGREQ (0xC0): Validate remaining length = 0\n");
		printf("  - DISCONNECT (0xE0): Parse optional reason code + properties\n");
		printf("  - AUTH (0xF0): Parse reason code + properties\n\n");
		printf("TEST FAILED: %d packet type(s) not implemented.\n", not_implemented);
		return 1;
	}

	printf("\nTEST PASSED: All packet types handled correctly.\n");
	return 0;
}
