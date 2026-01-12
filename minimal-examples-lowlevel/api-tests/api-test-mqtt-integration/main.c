/*
 * lws-api-test-mqtt-integration
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Integration tests for MQTT client with mosquitto broker.
 * Tests connection, pub/sub, QoS levels, and large messages.
 *
 * Prerequisites:
 *   mosquitto -c mosquitto-test.conf -p 31883
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

/* Test scenarios */
enum test_scenario {
	TEST_CONNECT_DISCONNECT,
	TEST_PUBSUB_QOS0,
	TEST_PUBSUB_QOS1,
	TEST_LARGE_MESSAGE,
	TEST_RECONNECT,

	TEST_COUNT
};

static const char *test_names[] = {
	"Connect/Disconnect",
	"Pub/Sub QoS0",
	"Pub/Sub QoS1",
	"Large Message (1KB)",
	"Reconnect",
};

/* Test states */
enum test_state {
	STATE_CONNECTING,
	STATE_SUBSCRIBE,
	STATE_PUBLISH,
	STATE_WAIT_RX,
	STATE_WAIT_ACK,
	STATE_DISCONNECT,
	STATE_RECONNECTING,
	STATE_DONE
};

/* Per-session data */
struct pss {
	enum test_state state;
	size_t pos;
	size_t rx_pos;
	int retries;
	int rx_complete;
};

/* Global test context */
static struct {
	struct lws_context *context;
	struct lws *wsi;
	enum test_scenario current_test;
	int test_result;
	int interrupted;
	int broker_port;
	int tests_passed;
	int tests_failed;
	int tests_skipped;
	int reconnect_count;
	uint8_t *large_buf;
	size_t large_buf_size;
} G;

/* Retry/keepalive policy */
static const lws_retry_bo_t retry = {
	.secs_since_valid_ping		= 10,
	.secs_since_valid_hangup	= 15,
};

/* MQTT client connection parameters */
static lws_mqtt_client_connect_param_t client_connect_param = {
	.client_id			= "lwsIntegrationTest",
	.keep_alive			= 30,
	.clean_start			= 1,
	.client_id_nofree		= 1,
};

/* Topics for testing */
static lws_mqtt_topic_elem_t topics_qos0[] = {
	{ .name = "lws/test/qos0", .qos = QOS0 },
};

static lws_mqtt_topic_elem_t topics_qos1[] = {
	{ .name = "lws/test/qos1", .qos = QOS1 },
};

static lws_mqtt_subscribe_param_t sub_param;
static lws_mqtt_publish_param_t pub_param;

/* Test message */
static const char *test_message = "Hello from libwebsockets MQTT test!";

static void
sigint_handler(int sig)
{
	G.interrupted = 1;
}

/*
 * Initialize large buffer with pattern for large message test
 */
static int
init_large_buffer(void)
{
	size_t i;

	G.large_buf_size = 1024;  /* 1KB - single chunk, fits within service buffer */
	G.large_buf = malloc(G.large_buf_size);
	if (!G.large_buf)
		return -1;

	/* Fill with recognizable pattern */
	for (i = 0; i < G.large_buf_size; i++)
		G.large_buf[i] = (uint8_t)(i & 0xff);

	return 0;
}

/*
 * Connect to broker
 */
static int
connect_client(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));

	i.mqtt_cp = &client_connect_param;
	i.address = "localhost";
	i.host = "localhost";
	i.protocol = "mqtt";
	i.context = G.context;
	i.method = "MQTT";
	i.alpn = "mqtt";
	i.port = G.broker_port;

	G.wsi = lws_client_connect_via_info(&i);
	if (!G.wsi) {
		lwsl_err("%s: Client connect failed\n", __func__);
		return -1;
	}

	return 0;
}

/*
 * Setup for current test
 */
static void
setup_current_test(struct pss *pss)
{
	pss->state = STATE_CONNECTING;
	pss->pos = 0;
	pss->rx_pos = 0;
	pss->retries = 0;
	pss->rx_complete = 0;

	memset(&sub_param, 0, sizeof(sub_param));
	memset(&pub_param, 0, sizeof(pub_param));

	switch (G.current_test) {
	case TEST_CONNECT_DISCONNECT:
		/* No subscription needed, just connect and disconnect */
		break;

	case TEST_PUBSUB_QOS0:
		sub_param.topic = topics_qos0;
		sub_param.num_topics = LWS_ARRAY_SIZE(topics_qos0);
		pub_param.topic = "lws/test/qos0";
		pub_param.qos = QOS0;
		break;

	case TEST_PUBSUB_QOS1:
		sub_param.topic = topics_qos1;
		sub_param.num_topics = LWS_ARRAY_SIZE(topics_qos1);
		pub_param.topic = "lws/test/qos1";
		pub_param.qos = QOS1;
		break;

	case TEST_LARGE_MESSAGE:
		sub_param.topic = topics_qos1;
		sub_param.num_topics = LWS_ARRAY_SIZE(topics_qos1);
		pub_param.topic = "lws/test/qos1";
		pub_param.qos = QOS1;
		break;

	case TEST_RECONNECT:
		sub_param.topic = topics_qos0;
		sub_param.num_topics = LWS_ARRAY_SIZE(topics_qos0);
		pub_param.topic = "lws/test/qos0";
		pub_param.qos = QOS0;
		break;

	default:
		break;
	}

	if (pub_param.topic)
		pub_param.topic_len = (uint16_t)strlen(pub_param.topic);
}

/*
 * Check if received data matches expected
 */
static int
verify_rx_data(const uint8_t *data, size_t len, size_t offset)
{
	size_t i;

	switch (G.current_test) {
	case TEST_PUBSUB_QOS0:
	case TEST_PUBSUB_QOS1:
		if (len != strlen(test_message))
			return -1;
		if (memcmp(data, test_message, len) != 0)
			return -1;
		break;

	case TEST_LARGE_MESSAGE:
		for (i = 0; i < len; i++) {
			if (data[i] != (uint8_t)((offset + i) & 0xff))
				return -1;
		}
		break;

	default:
		break;
	}

	return 0;
}

/*
 * MQTT callback
 */
static int
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	lws_mqtt_publish_param_t *pub;
	const uint8_t *payload;
	size_t payload_len;
	size_t chunk;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: CONNECTION_ERROR: %s\n", __func__,
			 in ? (char *)in : "(null)");
		G.test_result = -1;
		G.interrupted = 1;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		lwsl_notice("%s: CLIENT_CLOSED\n", __func__);
		if (pss->state == STATE_DISCONNECT ||
		    pss->state == STATE_RECONNECTING) {
			/* Expected close */
			if (G.current_test == TEST_RECONNECT &&
			    pss->state == STATE_RECONNECTING) {
				/* Reconnect after close */
				G.reconnect_count++;
				if (connect_client() == 0) {
					pss->state = STATE_DONE;
				} else {
					G.test_result = -1;
					G.interrupted = 1;
				}
			} else {
				G.test_result = 0;
				G.interrupted = 1;
			}
		} else {
			G.test_result = -1;
			G.interrupted = 1;
		}
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_notice("%s: MQTT_ESTABLISHED\n", __func__);
		setup_current_test(pss);

		if (G.current_test == TEST_CONNECT_DISCONNECT) {
			/* Connection established successfully, now disconnect */
			pss->state = STATE_DISCONNECT;
			G.test_result = 0;
			G.interrupted = 1;
			break;
		}

		if (G.current_test == TEST_RECONNECT && G.reconnect_count > 0) {
			/* Reconnection successful */
			G.test_result = 0;
			G.interrupted = 1;
			break;
		}

		pss->state = STATE_SUBSCRIBE;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		lwsl_notice("%s: MQTT_SUBSCRIBED\n", __func__);
		pss->state = STATE_PUBLISH;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		switch (pss->state) {
		case STATE_SUBSCRIBE:
			lwsl_notice("%s: Subscribing\n", __func__);
			if (lws_mqtt_client_send_subcribe(wsi, &sub_param)) {
				lwsl_err("%s: Subscribe failed\n", __func__);
				return -1;
			}
			break;

		case STATE_PUBLISH:
			lwsl_notice("%s: Publishing\n", __func__);

			if (G.current_test == TEST_LARGE_MESSAGE) {
				pub_param.payload_len = (uint32_t)G.large_buf_size;
				chunk = 2048;  /* Send in 2KB chunks */
				if (chunk > G.large_buf_size - pss->pos)
					chunk = G.large_buf_size - pss->pos;

				if (lws_mqtt_client_send_publish(wsi, &pub_param,
						(const char *)(G.large_buf + pss->pos),
						(uint32_t)chunk,
						(pss->pos + chunk == G.large_buf_size))) {
					lwsl_err("%s: Publish failed\n", __func__);
					return -1;
				}
				pss->pos += chunk;

				if (pss->pos < G.large_buf_size) {
					lws_callback_on_writable(wsi);
					break;
				}
			} else {
				pub_param.payload_len = (uint32_t)strlen(test_message);
				if (lws_mqtt_client_send_publish(wsi, &pub_param,
						test_message,
						(uint32_t)strlen(test_message), 1)) {
					lwsl_err("%s: Publish failed\n", __func__);
					return -1;
				}
			}

			pss->pos = 0;
			if (pub_param.qos == QOS0) {
				/* QoS0: wait for RX */
				pss->state = STATE_WAIT_RX;
			} else {
				/* QoS1: wait for ACK first */
				pss->state = STATE_WAIT_ACK;
			}
			break;

		default:
			break;
		}
		break;

	case LWS_CALLBACK_MQTT_ACK:
		lwsl_notice("%s: MQTT_ACK\n", __func__);
		if (pss->state == STATE_WAIT_ACK) {
			pss->state = STATE_WAIT_RX;
		}
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
		pub = (lws_mqtt_publish_param_t *)in;
		if (!pub) {
			lwsl_err("%s: RX with null pub\n", __func__);
			return -1;
		}

		payload = (const uint8_t *)pub->payload;
		payload_len = pub->payload_len;

		lwsl_notice("%s: RX %zu bytes (total %u)\n", __func__,
			    payload_len, (unsigned)pub->payload_len);

		if (verify_rx_data(payload, payload_len, pss->rx_pos) < 0) {
			lwsl_err("%s: RX data mismatch at offset %zu\n",
				 __func__, pss->rx_pos);
			G.test_result = -1;
			return -1;
		}

		pss->rx_pos += payload_len;

		/* Check if we've received all expected data */
		if (G.current_test == TEST_LARGE_MESSAGE) {
			if (pss->rx_pos >= G.large_buf_size)
				pss->rx_complete = 1;
		} else {
			if (pss->rx_pos >= strlen(test_message))
				pss->rx_complete = 1;
		}

		if (pss->rx_complete) {
			lwsl_notice("%s: RX complete\n", __func__);

			/* Test passed, disconnect */
			pss->state = STATE_DISCONNECT;
			G.test_result = 0;
			G.interrupted = 1;
			break;
		}
		break;

	case LWS_CALLBACK_MQTT_RESEND:
		lwsl_notice("%s: MQTT_RESEND\n", __func__);
		if (++pss->retries > 3) {
			lwsl_err("%s: Too many retries\n", __func__);
			G.test_result = -1;
			G.interrupted = 1;
			break;
		}
		pss->state = STATE_PUBLISH;
		pss->pos = 0;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{
		.name			= "mqtt",
		.callback		= callback_mqtt,
		.per_session_data_size	= sizeof(struct pss)
	},
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Run a single test
 */
static int
run_test(enum test_scenario test)
{
	struct lws_context_creation_info info;
	int n = 0;

	G.current_test = test;
	G.test_result = -1;
	G.interrupted = 0;
	G.reconnect_count = 0;
	G.wsi = NULL;

	lwsl_user("Running: %s\n", test_names[test]);

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.fd_limit_per_thread = 3;
	info.retry_and_idle_policy = &retry;

	G.context = lws_create_context(&info);
	if (!G.context) {
		lwsl_err("Context creation failed\n");
		return -1;
	}

	if (connect_client() < 0) {
		lws_context_destroy(G.context);
		return -1;
	}

	while (n >= 0 && !G.interrupted)
		n = lws_service(G.context, 100);

	lws_context_destroy(G.context);
	G.context = NULL;

	return G.test_result;
}

/*
 * Check if broker is available
 */
static int
check_broker(void)
{
	struct lws_context_creation_info info;
	struct lws_client_connect_info ci;
	struct lws_context *ctx;
	struct lws *wsi;
	int n, tries = 0;
	int result;

	/* Reset global state for broker check */
	G.current_test = TEST_CONNECT_DISCONNECT;
	G.test_result = -1;
	G.interrupted = 0;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.fd_limit_per_thread = 3;

	ctx = lws_create_context(&info);
	if (!ctx)
		return -1;

	memset(&ci, 0, sizeof(ci));
	ci.mqtt_cp = &client_connect_param;
	ci.address = "localhost";
	ci.host = "localhost";
	ci.protocol = "mqtt";
	ci.context = ctx;
	ci.method = "MQTT";
	ci.alpn = "mqtt";
	ci.port = G.broker_port;

	wsi = lws_client_connect_via_info(&ci);
	if (!wsi) {
		lws_context_destroy(ctx);
		return -1;
	}

	/* Give it a few service cycles to connect */
	while (tries++ < 40 && !G.interrupted) {
		n = lws_service(ctx, 50);
		if (n < 0)
			break;
	}

	result = G.test_result;
	lws_context_destroy(ctx);

	return result;
}

int main(int argc, const char **argv)
{
	const char *p;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	int i;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);

	/* Default port */
	G.broker_port = 31883;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		G.broker_port = atoi(p);

	lwsl_user("LWS MQTT Integration Tests\n");
	lwsl_user("Broker: localhost:%d\n\n", G.broker_port);

	/* Check if broker is available */
	lwsl_user("Checking broker availability...\n");
	if (check_broker() < 0) {
		lwsl_user("SKIP: Broker not available at localhost:%d\n",
			  G.broker_port);
		lwsl_user("Start mosquitto with:\n");
		lwsl_user("  mosquitto -c mosquitto-test.conf -p %d\n",
			  G.broker_port);
		return 77;  /* Skip return code for CTest */
	}
	lwsl_user("Broker available\n\n");

	/* Initialize large buffer for large message test */
	if (init_large_buffer() < 0) {
		lwsl_err("Failed to allocate large buffer\n");
		return 1;
	}

	/* Run tests */
	for (i = 0; i < TEST_COUNT; i++) {
		int result = run_test((enum test_scenario)i);

		if (result == 0) {
			lwsl_user("  PASS: %s\n", test_names[i]);
			G.tests_passed++;
		} else {
			lwsl_user("  FAIL: %s\n", test_names[i]);
			G.tests_failed++;
		}
		lwsl_user("\n");
	}

	free(G.large_buf);

	lwsl_user("============================================\n");
	lwsl_user("Results: %d passed, %d failed, %d skipped\n",
		  G.tests_passed, G.tests_failed, G.tests_skipped);
	lwsl_user("============================================\n");

	return G.tests_failed ? 1 : 0;
}
