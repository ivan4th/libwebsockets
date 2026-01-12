/*
 * test-connack-props.c - Unit test for CONNACK remaining length bug
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests that verify the MQTT parser correctly handles MQTT 5.0 CONNACK
 * packets with properties. Currently there is a bug at mqtt.c:1012:
 *
 *     if (par->cpkt_remlen != 2)
 *         goto send_protocol_error_and_close;
 *
 * This incorrectly requires CONNACK to have exactly 2 bytes remaining
 * length, but MQTT 5.0 CONNACK structure is:
 *   - 1 byte: Connect Acknowledge Flags (Session Present)
 *   - 1 byte: Connect Reason Code
 *   - Variable: Properties Length VBI + Properties (0 or more bytes)
 *
 * Valid MQTT 5.0 CONNACK packets with properties (remaining length > 2)
 * are incorrectly rejected as protocol errors.
 *
 * This test is expected to FAIL until the bug is fixed:
 *   - CONNACK remlen=2 (no props): PASS
 *   - CONNACK remlen=3 (empty props): FAIL (bug)
 *   - CONNACK remlen=8 (with props): FAIL (bug)
 */

#include "private-lib-core.h"
#include "private-lib-roles-mqtt.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Global context and vhost */
static struct lws_context *g_ctx;
static struct lws_vhost *g_vhost;

/* Test packet definitions - all valid MQTT 5.0 CONNACK packets */

/* Valid MQTT 5.0 CONNACK - no properties (remlen=2) */
static const uint8_t connack_no_props[] = {
	0x20,  /* CONNACK packet type */
	0x02,  /* Remaining length: 2 */
	0x00,  /* Session Present: 0 */
	0x00   /* Reason Code: Success */
};

/* Valid MQTT 5.0 CONNACK - empty properties (remlen=3) */
static const uint8_t connack_empty_props[] = {
	0x20,  /* CONNACK packet type */
	0x03,  /* Remaining length: 3 */
	0x00,  /* Session Present: 0 */
	0x00,  /* Reason Code: Success */
	0x00   /* Properties Length: 0 (VBI encoding of 0) */
};

/* Valid MQTT 5.0 CONNACK - with Session Expiry Interval property (remlen=8) */
static const uint8_t connack_with_props[] = {
	0x20,  /* CONNACK packet type */
	0x08,  /* Remaining length: 8 */
	0x00,  /* Session Present: 0 */
	0x00,  /* Reason Code: Success */
	0x05,  /* Properties Length: 5 */
	0x11,  /* Property ID: Session Expiry Interval (0x11) */
	0x00, 0x00, 0x0e, 0x10  /* Value: 3600 seconds (big-endian) */
};

/* Test case definition */
struct connack_test {
	const char *name;
	const uint8_t *data;
	size_t len;
	int remlen;
	int should_accept;  /* 1 = valid per MQTT 5.0 spec, should be accepted */
};

static const struct connack_test test_cases[] = {
	{
		"CONNACK remlen=2 (no props)",
		connack_no_props,
		sizeof(connack_no_props),
		2,
		1  /* Valid - no properties field */
	},
	{
		"CONNACK remlen=3 (empty props)",
		connack_empty_props,
		sizeof(connack_empty_props),
		3,
		1  /* Valid - properties length = 0 */
	},
	{
		"CONNACK remlen=8 (with props)",
		connack_with_props,
		sizeof(connack_with_props),
		8,
		1  /* Valid - has Session Expiry property */
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
 * Set up as a client that just sent CONNECT and is waiting for CONNACK.
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

	/* Set client role flag - required for CONNACK processing */
	wsi->wsistate |= LWSIFR_CLIENT;

	/* Initialize parser state - client waiting for CONNACK */
	wsi->mqtt->client.par.state = LMQCPP_IDLE;
	wsi->mqtt->client.estate = LGSMQTT_SENT_CONNECT;  /* Waiting for CONNACK */

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
 * Test a single CONNACK packet.
 * Returns:
 *   1 = parser accepted the packet (no error)
 *   0 = parser rejected the packet (protocol error or similar)
 *  -1 = test setup error
 */
static int
test_connack_packet(const struct connack_test *tc)
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
	 * The parser returns:
	 *   0 = success (more data may be needed or packet complete)
	 *  -1 = error (including protocol errors)
	 *
	 * For CONNACK, the bug at mqtt.c:1012 causes:
	 *   if (par->cpkt_remlen != 2)
	 *       goto send_protocol_error_and_close;
	 *
	 * This will reject any CONNACK with remaining length != 2,
	 * even though MQTT 5.0 allows properties (remlen >= 3).
	 */
	ret = _lws_mqtt_rx_parser(wsi, par, tc->data, tc->len);

	/*
	 * Check result:
	 *   ret >= 0 means parser accepted (at least partially)
	 *   ret < 0 means parser rejected with error
	 */
	if (ret >= 0) {
		/*
		 * Also check if we moved past the CONNACK state or got stuck.
		 * For a complete CONNACK, estate should advance to ESTABLISHED
		 * or at least the parser should be waiting for more data.
		 */
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
	int bugs_found = 0;
	int tests_passed = 0;
	int tests_run = 0;
	int errors = 0;
	size_t i;

	(void)argc;
	(void)argv;

	lws_set_log_level(0, NULL);  /* Quiet for testing */

	printf("MQTT Parser CONNACK Remaining Length Bug Test\n");
	printf("==============================================\n\n");
	printf("Testing for bug at mqtt.c:1012 that rejects valid MQTT 5.0\n");
	printf("CONNACK packets with properties (remaining length > 2).\n\n");
	printf("Bug: if (par->cpkt_remlen != 2) goto send_protocol_error_and_close;\n");
	printf("Fix: Should be (par->cpkt_remlen < 2) for minimum validation.\n\n");

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

	printf("%-35s %-8s %-10s %s\n", "Test Case", "RemLen", "Expected", "Actual");
	printf("%-35s %-8s %-10s %s\n", "---------", "------", "--------", "------");

	for (i = 0; i < NUM_TEST_CASES; i++) {
		const struct connack_test *tc = &test_cases[i];
		int result;
		int accepted;

		tests_run++;
		result = test_connack_packet(tc);

		if (result < 0) {
			printf("%-35s %-8d %-10s ERROR\n",
			       tc->name, tc->remlen,
			       tc->should_accept ? "ACCEPT" : "REJECT");
			errors++;
			continue;
		}

		accepted = (result == 1);

		printf("%-35s %-8d %-10s %-10s ",
		       tc->name, tc->remlen,
		       tc->should_accept ? "ACCEPT" : "REJECT",
		       accepted ? "ACCEPT" : "REJECT");

		if (accepted == tc->should_accept) {
			printf("PASS\n");
			tests_passed++;
		} else {
			printf("FAIL (BUG)\n");
			bugs_found++;
		}
	}

	printf("\n");
	printf("Results: %d/%d tests passed", tests_passed, tests_run);
	if (errors > 0)
		printf(", %d test errors", errors);
	if (bugs_found > 0)
		printf(", %d FAILED due to bug", bugs_found);
	printf("\n");

	lws_context_destroy(g_ctx);

	if (errors > 0) {
		printf("\nTEST ERROR: %d test(s) could not run.\n", errors);
		return 1;
	}

	if (bugs_found > 0) {
		printf("\n");
		printf("BUG CONFIRMED: Parser incorrectly rejects valid MQTT 5.0\n");
		printf("CONNACK packets that include properties.\n\n");
		printf("Location: lib/roles/mqtt/mqtt.c:1012\n");
		printf("Current:  if (par->cpkt_remlen != 2)\n");
		printf("Fix:      if (par->cpkt_remlen < 2)\n\n");
		printf("MQTT 5.0 CONNACK structure:\n");
		printf("  - 1 byte: Session Present flag\n");
		printf("  - 1 byte: Reason Code\n");
		printf("  - Variable: Properties Length (VBI) + Properties\n\n");
		printf("Minimum remaining length is 2 (no properties), but can be\n");
		printf("larger when properties are present.\n\n");
		printf("TEST FAILED: %d bug(s) found!\n", bugs_found);
		return 1;
	}

	printf("\nTEST PASSED: All CONNACK packets handled correctly.\n");
	return 0;
}
