/*
 * test-infinite-loops.c - Unit tests for MQTT parser infinite loop bugs
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests that verify infinite loop bugs in _lws_mqtt_rx_parser() for
 * unhandled packet types. The parser lacks handler cases for:
 *   - 0x80: SUBSCRIBE (packet type 8)
 *   - 0xa0: UNSUBSCRIBE (packet type 10)
 *   - 0xc0: PINGREQ (packet type 12)
 *   - 0xe0: DISCONNECT (packet type 14)
 *   - 0xf0: AUTH (packet type 15)
 *
 * At mqtt.c:584, par->state = par->packet_type_flags & 0xf0 sets a state
 * with no corresponding case in the switch, causing infinite loop since
 * no bytes are consumed.
 */

#include "private-lib-core.h"
#include "private-lib-roles-mqtt.h"

#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Test timeout in seconds */
#define TEST_TIMEOUT_SECS 1

/* Jump buffer for timeout recovery */
static sigjmp_buf timeout_jmp;
static volatile sig_atomic_t timeout_fired;

/* Global context */
static struct lws_context *g_ctx;

/* Test case definition */
struct infinite_loop_test {
	const char *name;
	uint8_t packet_type_byte;
	const char *description;
};

/* All packet types that cause infinite loops */
static const struct infinite_loop_test test_cases[] = {
	{ "SUBSCRIBE",   0x82, "Packet type 8 (SUBSCRIBE) with flags 0x2" },
	{ "UNSUBSCRIBE", 0xa2, "Packet type 10 (UNSUBSCRIBE) with flags 0x2" },
	{ "PINGREQ",     0xc0, "Packet type 12 (PINGREQ) with flags 0x0" },
	{ "DISCONNECT",  0xe0, "Packet type 14 (DISCONNECT) with flags 0x0" },
	{ "AUTH",        0xf0, "Packet type 15 (AUTH) with flags 0x0" },
};

#define NUM_TEST_CASES (sizeof(test_cases) / sizeof(test_cases[0]))

/* Signal handler for timeout */
static void
timeout_handler(int sig)
{
	(void)sig;
	timeout_fired = 1;
	siglongjmp(timeout_jmp, 1);
}

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
 * This mirrors the approach used in mqtt-direct-fuzz.c.
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
	wsi->a.protocol = &protocols[0];
	wsi->role_ops = &role_ops_mqtt;

	/* Initialize parser state */
	wsi->mqtt->client.par.state = LMQCPP_IDLE;
	wsi->mqtt->client.estate = LGSMQTT_IDLE;

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
 * Test a single packet type for infinite loop.
 * Returns:
 *   1 = infinite loop detected (bug confirmed)
 *   0 = parser returned normally (bug fixed or not present)
 *  -1 = test setup error
 */
static int
test_packet_type(const struct infinite_loop_test *tc)
{
	struct sigaction sa, old_sa;
	struct lws *wsi = NULL;
	lws_mqtt_parser_t *par;
	int result = -1;
	int ret;
	uint8_t packet[4];

	/*
	 * Build a minimal packet:
	 * [0] = packet type + flags
	 * [1] = remaining length (0x01 = 1 byte follows)
	 * [2] = dummy payload byte
	 */
	packet[0] = tc->packet_type_byte;
	packet[1] = 0x01;  /* remaining length = 1 */
	packet[2] = 0x00;  /* dummy byte */

	/* Set up timeout signal handler */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = timeout_handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGALRM, &sa, &old_sa) < 0) {
		fprintf(stderr, "sigaction failed\n");
		return -1;
	}

	/* Create test wsi */
	wsi = create_test_wsi();
	if (!wsi) {
		fprintf(stderr, "Failed to create test wsi\n");
		goto cleanup_signal;
	}

	par = &wsi->mqtt->client.par;

	/* Set up timeout jump point */
	timeout_fired = 0;
	if (sigsetjmp(timeout_jmp, 1) != 0) {
		/* We jumped here from the signal handler - timeout occurred */
		result = 1;  /* Infinite loop detected */
		goto cleanup;
	}

	/* Start the timer */
	alarm(TEST_TIMEOUT_SECS);

	/* Call the parser - this may infinite loop */
	ret = _lws_mqtt_rx_parser(wsi, par, packet, sizeof(packet));

	/* Cancel the timer - parser returned */
	alarm(0);

	/* Parser returned normally */
	result = 0;
	(void)ret;  /* We don't care about return value, just that it returned */

cleanup:
	alarm(0);  /* Cancel any pending alarm */
	destroy_test_wsi(wsi);

cleanup_signal:
	sigaction(SIGALRM, &old_sa, NULL);  /* Restore old handler */

	return result;
}

int main(int argc, char **argv)
{
	struct lws_context_creation_info info;
	int bugs_found = 0;
	int tests_run = 0;
	int errors = 0;
	size_t i;

	(void)argc;
	(void)argv;

	lws_set_log_level(0, NULL);  /* Quiet for testing */

	printf("MQTT Parser Infinite Loop Bug Tests\n");
	printf("====================================\n\n");
	printf("Testing for infinite loops in _lws_mqtt_rx_parser()\n");
	printf("caused by unhandled packet type states.\n\n");
	printf("Each test has a %d second timeout.\n\n", TEST_TIMEOUT_SECS);

	/* Create context for tests */
	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	g_ctx = lws_create_context(&info);
	if (!g_ctx) {
		fprintf(stderr, "Failed to create context\n");
		return 1;
	}

	printf("%-15s %-50s %s\n", "Packet Type", "Description", "Result");
	printf("%-15s %-50s %s\n", "-----------", "-----------", "------");

	for (i = 0; i < NUM_TEST_CASES; i++) {
		const struct infinite_loop_test *tc = &test_cases[i];
		int result;

		tests_run++;
		result = test_packet_type(tc);

		printf("0x%02x %-10s %-50s ",
		       tc->packet_type_byte, tc->name, tc->description);

		if (result == 1) {
			printf("BUG (infinite loop)\n");
			bugs_found++;
		} else if (result == 0) {
			printf("OK (parser returned)\n");
		} else {
			printf("ERROR (test failed)\n");
			errors++;
		}
	}

	printf("\n");
	printf("Summary: %d/%d packet types cause infinite loops",
	       bugs_found, tests_run);
	if (errors > 0)
		printf(", %d test errors", errors);
	printf("\n");

	if (bugs_found > 0) {
		printf("\nRoot cause: mqtt.c:584 sets par->state = packet_type & 0xf0\n");
		printf("but the switch statement has no case for these states,\n");
		printf("causing the while(len) loop to spin forever.\n");
		printf("\nFix: Add a default case to return an error for unknown states.\n");
	}

	lws_context_destroy(g_ctx);

	/*
	 * Return 0 if all tests passed (no infinite loops - bugs fixed).
	 * Return 1 if there were test errors or bugs found.
	 */
	if (errors > 0)
		return 1;
	if (bugs_found > 0) {
		printf("\nTEST FAILED: %d infinite loop bug(s) found!\n", bugs_found);
		return 1;
	}

	printf("\nTEST PASSED: All packet types handled correctly.\n");
	return 0;
}
