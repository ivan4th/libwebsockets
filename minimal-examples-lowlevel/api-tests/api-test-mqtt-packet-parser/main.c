/*
 * lws-api-test-mqtt-packet-parser
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests full MQTT packet parsing with fragmentation scenarios.
 * Uses a local loopback server to send canned packets with controlled
 * fragmentation to exercise the parser's stateful, fragmentation-immune
 * design.
 *
 * Tests include:
 *   - Complete packet parsing (all packet types)
 *   - Single-byte fragmentation (maximum fragmentation stress)
 *   - Mid-packet splits (at VBI boundaries, topic boundaries, etc.)
 *   - Multiple packets in single read (boundary crossing)
 *   - Invalid packet rejection
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#include "mqtt-packets.h"

/* Test server port - 0 for dynamic allocation */
static int test_port;

/* Test modes - all fragmentation scenarios including single-byte */
enum frag_mode {
	FRAG_NONE,		/* Send complete packet at once */
	FRAG_SINGLE_BYTE,	/* Send one byte at a time */
	FRAG_SPLIT_HALF,	/* Split at middle */
	FRAG_SPLIT_AFTER_FIXED,	/* Split after fixed header (2 bytes) */
	FRAG_SPLIT_IN_VBI,	/* Split in middle of VBI (if multi-byte) */
	FRAG_CUSTOM_SPLIT,	/* Split at frag_split_at offset */

	FRAG_MODE_COUNT
};

static const char *frag_mode_names[] = {
	"complete",
	"single-byte",
	"split-half",
	"split-after-fixed",
	"split-in-vbi",
	"custom-split"
};

/* Test phases for multi-packet handshake flows */
enum test_phase {
	PHASE_WAITING_CONNECT,		/* Wait for client CONNECT */
	PHASE_SEND_CONNACK,		/* Send CONNACK */
	PHASE_WAITING_SUBSCRIBE,	/* Wait for client SUBSCRIBE */
	PHASE_SEND_SUBACK,		/* Send SUBACK */
	PHASE_WAITING_PUBLISH,		/* Wait for client PUBLISH (for PUBACK tests) */
	PHASE_SEND_PUBACK,		/* Send PUBACK (for PUBACK tests) */
	PHASE_SEND_TEST_PACKET,		/* Send the test packet (PUBLISH/etc) */
	PHASE_COMPLETE
};

/* Test context */
static struct {
	struct lws_context *context;
	struct lws *client_wsi;
	struct lws *server_wsi;
	struct lws *accepted_wsi;

	/* Test data to send */
	const uint8_t *send_data;
	size_t send_len;
	size_t send_pos;

	/* Optional prefix (e.g., CONNACK before PUBLISH) */
	const uint8_t *prefix_data;
	size_t prefix_len;
	size_t prefix_pos;
	int prefix_sent;

	/* Synchronization: wait for client to process CONNACK before sending test data */
	int connection_established;

	/* For handshake flows (PUBLISH, PUBACK tests) */
	enum test_phase phase;
	int need_subscribe;		/* Test requires client subscription */
	int need_client_publish;	/* Test requires client to publish (for PUBACK) */
	int test_server_qos1_pub;	/* Test QoS1 PUBLISH from server (expect client PUBACK) */
	int subscription_done;		/* Client finished subscribing */
	int client_publish_done;	/* Client finished publishing */
	int client_puback_received;	/* Server received PUBACK from client */
	uint16_t subscribe_packet_id;	/* Packet ID from SUBSCRIBE for SUBACK */
	uint16_t client_publish_packet_id; /* Packet ID from client PUBLISH for PUBACK */
	uint16_t server_publish_packet_id; /* Packet ID for server's QoS1 PUBLISH */

	/* Fragmentation control */
	enum frag_mode frag_mode;
	size_t frag_chunk_size;
	size_t frag_split_at;

	/* Results */
	int packets_received;
	int expected_packets;
	int parse_errors;
	int test_complete;
	int interrupted;
	int in_cleanup;		/* Set when actively closing connections */

	/* Current test info */
	const char *test_name;
	uint8_t expected_packet_type;
} G;

/* MQTT client retry policy - short timeouts for fast tests */
static const lws_retry_bo_t retry = {
	.secs_since_valid_ping = 300,   /* Don't ping during tests */
	.secs_since_valid_hangup = 600,
};

/* MQTT connection params - minimal for testing */
static lws_mqtt_client_connect_param_t mqtt_connect_param = {
	.client_id = "pktParserTest",
	.keep_alive = 60,
	.clean_start = 1,
	.client_id_nofree = 1,
};

/* Subscription topic for PUBLISH tests */
static lws_mqtt_topic_elem_t test_topics[] = {
	{ .name = "test", .qos = QOS0 },
};

static lws_mqtt_subscribe_param_t test_sub_param = {
	.topic = test_topics,
	.num_topics = 1,
};

/* Publish params for PUBACK tests */
static lws_mqtt_publish_param_t test_pub_param;

/*
 * Calculate next chunk size based on fragmentation mode
 */
static size_t
get_next_chunk_size(size_t remaining, size_t total_sent)
{
	switch (G.frag_mode) {
	case FRAG_SINGLE_BYTE:
		return 1;

	case FRAG_SPLIT_HALF:
		if (total_sent < G.send_len / 2)
			return G.send_len / 2 - total_sent;
		return remaining;

	case FRAG_SPLIT_AFTER_FIXED:
		if (total_sent < 2)
			return 2 - total_sent;
		return remaining;

	case FRAG_SPLIT_IN_VBI:
		/* If packet has 2-byte VBI, split after first VBI byte */
		if (G.send_len > 3 && (G.send_data[1] & 0x80)) {
			if (total_sent < 2)
				return 2 - total_sent;
		}
		return remaining;

	case FRAG_CUSTOM_SPLIT:
		/* Split at custom offset (for boundary crossing tests) */
		if (total_sent < G.frag_split_at)
			return G.frag_split_at - total_sent;
		return remaining;

	case FRAG_NONE:
	default:
		return remaining;
	}
}

/*
 * Parse packet ID from SUBSCRIBE packet
 * SUBSCRIBE: type(1) + remaining_len(1-4) + packet_id(2) + topics...
 */
static uint16_t
parse_subscribe_packet_id(const uint8_t *data, size_t len)
{
	size_t offset = 1; /* Skip packet type byte */
	uint32_t rem_len = 0;
	int shift = 0;

	/* Parse variable byte integer (remaining length) - just skip it */
	while (offset < len && shift < 28) {
		uint8_t b = data[offset++];
		rem_len |= (uint32_t)(b & 0x7f) << shift;
		if (!(b & 0x80))
			break;
		shift += 7;
	}
	(void)rem_len; /* Not used, just need to skip VBI bytes */

	/* Now at packet ID position */
	if (offset + 2 > len)
		return 0;

	return (uint16_t)((data[offset] << 8) | data[offset + 1]);
}

/*
 * Build SUBACK packet dynamically based on SUBSCRIBE packet ID
 */
static uint8_t suback_response[5];
static size_t suback_response_len;
static size_t suback_response_pos;

static void
build_suback_response(uint16_t packet_id)
{
	suback_response[0] = 0x90;	/* SUBACK */
	suback_response[1] = 0x03;	/* Remaining length: 2 (pkt_id) + 1 (return code) */
	suback_response[2] = (uint8_t)(packet_id >> 8);
	suback_response[3] = (uint8_t)(packet_id & 0xff);
	suback_response[4] = 0x00;	/* QoS0 granted */
	suback_response_len = 5;
	suback_response_pos = 0;
}

/*
 * Build PUBACK packet dynamically based on publish packet ID
 */
static uint8_t puback_response[4];
static size_t puback_response_len;
static size_t puback_response_pos;

static void
build_puback_response(uint16_t packet_id)
{
	puback_response[0] = 0x40;	/* PUBACK */
	puback_response[1] = 0x02;	/* Remaining length: 2 (pkt_id) */
	puback_response[2] = (uint8_t)(packet_id >> 8);
	puback_response[3] = (uint8_t)(packet_id & 0xff);
	puback_response_len = 4;
	puback_response_pos = 0;
}

/*
 * Calculate fragmented chunk size for dynamic packets
 */
static size_t
get_dynamic_chunk_size(size_t remaining, size_t total_sent, size_t total_len)
{
	switch (G.frag_mode) {
	case FRAG_SINGLE_BYTE:
		return 1;

	case FRAG_SPLIT_HALF:
		if (total_sent < total_len / 2)
			return total_len / 2 - total_sent;
		return remaining;

	case FRAG_SPLIT_AFTER_FIXED:
		if (total_sent < 2)
			return 2 - total_sent;
		return remaining;

	case FRAG_SPLIT_IN_VBI:
		/* For dynamic packets, just send complete (VBI is always 1 byte) */
		return remaining;

	case FRAG_NONE:
	default:
		return remaining;
	}
}

/*
 * Raw protocol callback - simulates MQTT broker responses
 */
static int
callback_raw_server(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	size_t chunk, remaining;
	const uint8_t *rxdata;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		lwsl_info("%s: RAW_ADOPT\n", __func__);
		G.accepted_wsi = wsi;
		G.phase = PHASE_SEND_CONNACK;
		/* Request writable callback to start sending CONNACK */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		/*
		 * Phase-based handshake for tests requiring subscription
		 */
		if (G.need_subscribe) {
			switch (G.phase) {
			case PHASE_SEND_CONNACK:
				/* Send CONNACK */
				lwsl_notice("%s: [phase] sending CONNACK\n", __func__);
				if (lws_write(wsi, (uint8_t *)pkt_connack_ok,
					      sizeof(pkt_connack_ok), LWS_WRITE_RAW) < (int)sizeof(pkt_connack_ok)) {
					lwsl_err("%s: CONNACK write failed\n", __func__);
					return -1;
				}
				G.phase = PHASE_WAITING_SUBSCRIBE;
				break;

			case PHASE_SEND_SUBACK: {
				/* Send SUBACK with matching packet ID (fragmented) */
				size_t chunk, remaining;

				if (suback_response_pos == 0) {
					/* First call - build the response */
					build_suback_response(G.subscribe_packet_id);
				}

				remaining = suback_response_len - suback_response_pos;
				chunk = get_dynamic_chunk_size(remaining, suback_response_pos,
							       suback_response_len);
				if (chunk > remaining)
					chunk = remaining;

				lwsl_notice("%s: [phase] sending SUBACK %zu bytes (pos %zu/%zu, mode %s)\n",
					    __func__, chunk, suback_response_pos, suback_response_len,
					    frag_mode_names[G.frag_mode]);

				if (lws_write(wsi, suback_response + suback_response_pos, chunk,
					      LWS_WRITE_RAW) < (int)chunk) {
					lwsl_err("%s: SUBACK write failed\n", __func__);
					return -1;
				}
				suback_response_pos += chunk;

				if (suback_response_pos < suback_response_len) {
					/* More to send */
					lws_callback_on_writable(wsi);
					break;
				}

				/* SUBACK complete */
				if (G.need_client_publish)
					G.phase = PHASE_WAITING_PUBLISH;
				else
					G.phase = PHASE_SEND_TEST_PACKET;
				break;
			}

			case PHASE_SEND_PUBACK: {
				/* Send PUBACK with matching packet ID (fragmented) */
				size_t chunk, remaining;

				if (puback_response_pos == 0) {
					/* First call - build the response */
					build_puback_response(G.client_publish_packet_id);
				}

				remaining = puback_response_len - puback_response_pos;
				chunk = get_dynamic_chunk_size(remaining, puback_response_pos,
							       puback_response_len);
				if (chunk > remaining)
					chunk = remaining;

				lwsl_notice("%s: [phase] sending PUBACK %zu bytes (pos %zu/%zu, mode %s)\n",
					    __func__, chunk, puback_response_pos, puback_response_len,
					    frag_mode_names[G.frag_mode]);

				if (lws_write(wsi, puback_response + puback_response_pos, chunk,
					      LWS_WRITE_RAW) < (int)chunk) {
					lwsl_err("%s: PUBACK write failed\n", __func__);
					return -1;
				}
				puback_response_pos += chunk;

				if (puback_response_pos < puback_response_len) {
					/* More to send */
					lws_callback_on_writable(wsi);
					break;
				}

				/* PUBACK complete - test done */
				G.phase = PHASE_COMPLETE;
				break;
			}

			case PHASE_SEND_TEST_PACKET:
				/* Wait for subscription_done before sending test packet */
				if (!G.subscription_done) {
					return 0;
				}
				goto send_test_packet;

			default:
				break;
			}
			return 0;
		}

		/* Simple flow for CONNACK-only tests */
		/* First send prefix (CONNACK) if specified and not yet sent */
		if (G.prefix_data && !G.prefix_sent) {
			remaining = G.prefix_len - G.prefix_pos;
			lwsl_notice("%s: sending CONNACK prefix (%zu bytes)\n", __func__, remaining);
			if (lws_write(wsi, (uint8_t *)G.prefix_data + G.prefix_pos,
				      remaining, LWS_WRITE_RAW) < (int)remaining) {
				lwsl_err("%s: prefix write failed\n", __func__);
				return -1;
			}
			G.prefix_pos = G.prefix_len;
			G.prefix_sent = 1;
			/* Schedule next write - will wait for connection_established */
			lws_callback_on_writable(wsi);
			break;
		}

		/* Wait for client to process CONNACK before sending test data */
		if (G.prefix_data && !G.connection_established) {
			/* Re-schedule check */
			return 0;
		}

send_test_packet:
		if (!G.send_data || G.send_pos >= G.send_len) {
			/* Nothing more to send */
			return 0;
		}

		remaining = G.send_len - G.send_pos;
		chunk = get_next_chunk_size(remaining, G.send_pos);
		if (chunk > remaining)
			chunk = remaining;

		lwsl_notice("%s: sending test data %zu bytes (pos %zu/%zu, mode %s)\n",
			   __func__, chunk, G.send_pos, G.send_len,
			   frag_mode_names[G.frag_mode]);

		if (lws_write(wsi, (uint8_t *)G.send_data + G.send_pos,
			      chunk, LWS_WRITE_RAW) < (int)chunk) {
			lwsl_err("%s: write failed\n", __func__);
			return -1;
		}

		G.send_pos += chunk;

		/* Schedule more writes if fragmented */
		if (G.send_pos < G.send_len)
			lws_callback_on_writable(wsi);

		break;

	case LWS_CALLBACK_RAW_RX:
		rxdata = (const uint8_t *)in;
		if (len < 2)
			break;

		/* Check packet type */
		switch (rxdata[0] & 0xf0) {
		case 0x10: /* CONNECT */
			lwsl_debug("%s: received CONNECT (%zu bytes)\n", __func__, len);
			break;

		case 0x80: /* SUBSCRIBE */
			lwsl_notice("%s: received SUBSCRIBE (%zu bytes)\n", __func__, len);
			G.subscribe_packet_id = parse_subscribe_packet_id(rxdata, len);
			lwsl_notice("%s: SUBSCRIBE packet_id = %u\n", __func__, G.subscribe_packet_id);
			if (G.phase == PHASE_WAITING_SUBSCRIBE) {
				G.phase = PHASE_SEND_SUBACK;
				lws_callback_on_writable(wsi);
			}
			break;

		case 0x30: /* PUBLISH */
			lwsl_notice("%s: received PUBLISH (%zu bytes)\n", __func__, len);
			/* For PUBACK tests, extract packet ID and send PUBACK */
			if (G.need_client_publish && G.phase == PHASE_WAITING_PUBLISH) {
				/* Parse packet ID from QoS1 PUBLISH */
				/* Skip: type(1) + rem_len(VBI) + topic_len(2) + topic(n) */
				size_t offset = 1;
				uint32_t rem_len = 0;
				int shift = 0;
				while (offset < len && shift < 28) {
					uint8_t b = rxdata[offset++];
					rem_len |= (uint32_t)(b & 0x7f) << shift;
					if (!(b & 0x80)) break;
					shift += 7;
				}
				(void)rem_len; /* Not used, just skip VBI */
				if (offset + 2 <= len) {
					uint16_t topic_len = (uint16_t)((rxdata[offset] << 8) | rxdata[offset + 1]);
					offset += 2 + topic_len; /* Skip topic length + topic */
					if (offset + 2 <= len) {
						G.client_publish_packet_id = (uint16_t)((rxdata[offset] << 8) | rxdata[offset + 1]);
						lwsl_notice("%s: PUBLISH packet_id = %u\n", __func__, G.client_publish_packet_id);
						/*
						 * The client has already set unacked_publish=1 and
						 * ack_pkt_id by the time we receive this (lws_write
						 * is synchronous within the same event loop iteration).
						 * We can send PUBACK immediately.
						 */
						puback_response_pos = 0;
						G.phase = PHASE_SEND_PUBACK;
						G.client_publish_done = 1;
						lws_callback_on_writable(wsi);
					}
				}
			}
			break;

		case 0x40: /* PUBACK from client */
			lwsl_notice("%s: received PUBACK (%zu bytes)\n", __func__, len);
			if (G.test_server_qos1_pub && len >= 4) {
				uint16_t pkt_id = (uint16_t)((rxdata[2] << 8) | rxdata[3]);
				lwsl_notice("%s: PUBACK packet_id = %u (expected %u)\n",
					    __func__, pkt_id, G.server_publish_packet_id);
				if (pkt_id == G.server_publish_packet_id) {
					G.client_puback_received = 1;
					G.test_complete = 1;
				}
			}
			break;

		default:
			lwsl_debug("%s: received packet type 0x%02x (%zu bytes)\n",
				   __func__, rxdata[0] & 0xf0, len);
			break;
		}
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		lwsl_info("%s: RAW_CLOSE\n", __func__);
		G.accepted_wsi = NULL;
		break;

	default:
		break;
	}

	return 0;
}

/*
 * MQTT client callback - receives parsed packets
 */
static int
callback_mqtt_client(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_MQTT_NEW_CLIENT_INSTANTIATED:
		lwsl_info("%s: CLIENT_INSTANTIATED\n", __func__);
		G.client_wsi = wsi;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_notice("%s: ESTABLISHED (connack received), accepted_wsi=%p\n",
			    __func__, (void *)G.accepted_wsi);
		/* Only count CONNACK as a packet for CONNACK tests (type 2) */
		if (G.expected_packet_type == 2)
			G.packets_received++;
		G.connection_established = 1;
		if (G.expected_packet_type == 2) { /* CONNACK test - done */
			lwsl_notice("%s: CONNACK test complete, setting test_complete=1\n", __func__);
			G.test_complete = 1;
		} else if (G.need_subscribe) {
			/* Need to send SUBSCRIBE before server sends test packet */
			lws_callback_on_writable(wsi);
		} else if (G.accepted_wsi && G.send_pos < G.send_len) {
			/* More data to send - trigger server */
			lws_callback_on_writable(G.accepted_wsi);
		}
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		/* Send SUBSCRIBE if needed */
		if (G.need_subscribe && !G.subscription_done) {
			lwsl_notice("%s: sending SUBSCRIBE\n", __func__);
			if (lws_mqtt_client_send_subcribe(wsi, &test_sub_param)) {
				lwsl_err("%s: SUBSCRIBE failed\n", __func__);
				G.parse_errors++;
				G.test_complete = 1;
				return -1;
			}
		} else if (G.need_client_publish && G.subscription_done && !G.client_publish_done) {
			/* For PUBACK tests: send PUBLISH after subscription confirmed */
			lwsl_notice("%s: sending QoS1 PUBLISH\n", __func__);
			memset(&test_pub_param, 0, sizeof(test_pub_param));
			test_pub_param.topic = "test";
			test_pub_param.topic_len = 4;
			test_pub_param.qos = QOS1;
			test_pub_param.payload_len = 5;
			if (lws_mqtt_client_send_publish(wsi, &test_pub_param, "hello", 5, 1)) {
				lwsl_err("%s: PUBLISH failed\n", __func__);
				G.parse_errors++;
				G.test_complete = 1;
				return -1;
			}
		}
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX: {
		lws_mqtt_publish_param_t *pub =
			(lws_mqtt_publish_param_t *)in;
		lwsl_notice("%s: RX - topic: %s, payload_len: %lu, payload_pos: %lu\n",
			    __func__, pub ? pub->topic : "(null)",
			    pub ? (unsigned long)pub->payload_len : 0,
			    pub ? (unsigned long)pub->payload_pos : 0);
		G.packets_received++;
		/*
		 * For server QoS1 PUBLISH test, don't set test_complete here.
		 * We need to wait for the client to automatically send PUBACK
		 * and for the server to receive it.
		 */
		if (G.expected_packet_type == 3 && !G.test_server_qos1_pub)
			G.test_complete = 1;
		break;
	}

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		lwsl_notice("%s: SUBSCRIBED (suback received)\n", __func__);
		/* Only count SUBACK as a packet for SUBACK tests (type 9) */
		if (G.expected_packet_type == 9)
			G.packets_received++;
		G.subscription_done = 1;
		if (G.expected_packet_type == 9) { /* SUBACK test - done */
			G.test_complete = 1;
		} else if (G.need_client_publish) {
			/* For PUBACK tests: now send PUBLISH */
			lws_callback_on_writable(wsi);
		} else if (G.accepted_wsi) {
			/* For PUBLISH tests: tell server to send test packet */
			lws_callback_on_writable(G.accepted_wsi);
		}
		break;

	case LWS_CALLBACK_MQTT_UNSUBSCRIBED:
		lwsl_notice("%s: UNSUBSCRIBED (unsuback received)\n", __func__);
		G.packets_received++;
		if (G.expected_packet_type == 11) /* UNSUBACK */
			G.test_complete = 1;
		break;

	case LWS_CALLBACK_MQTT_ACK:
		lwsl_notice("%s: ACK (puback/pubrec/etc received)\n", __func__);
		G.packets_received++;
		if (G.expected_packet_type == 4 || /* PUBACK */
		    G.expected_packet_type == 5 || /* PUBREC */
		    G.expected_packet_type == 6 || /* PUBREL */
		    G.expected_packet_type == 7)   /* PUBCOMP */
			G.test_complete = 1;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		lwsl_info("%s: CLIENT_CLOSED wsi=%p, G.client_wsi=%p\n",
			  __func__, (void *)wsi, (void *)G.client_wsi);
		/*
		 * If closed unexpectedly (not during cleanup), it's an error.
		 * This catches parser errors that occur after the expected
		 * callback fires. Only count as error if this is our current
		 * test's connection (not a stale connection from previous test).
		 */
		if (wsi == G.client_wsi && !G.in_cleanup && G.expected_packet_type != 0) {
			lwsl_notice("%s: unexpected close (parse error?)\n", __func__);
			G.parse_errors++;
		}
		if (wsi == G.client_wsi) {
			G.client_wsi = NULL;
			if (!G.test_complete)
				G.test_complete = 1;
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_warn("%s: CONNECTION_ERROR: %s\n", __func__,
			  in ? (char *)in : "(null)");
		G.parse_errors++;
		G.test_complete = 1;
		break;

	default:
		break;
	}

	return 0;
}

static struct lws_protocols protocols[] = {
	{
		"raw-server",
		callback_raw_server,
		0, 1024, 0, NULL, 0
	},
	{
		"mqtt",
		callback_mqtt_client,
		0, 1024, 0, NULL, 0
	},
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Create fresh context and server for a test.
 * Each test gets its own context for clean isolation.
 */
static int
setup_test_context(void)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;

	/* Create context */
	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
		       LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	G.context = lws_create_context(&info);
	if (!G.context) {
		lwsl_err("Context creation failed\n");
		return -1;
	}

	/* Create raw server vhost with dynamic port */
	memset(&info, 0, sizeof(info));
	info.port = 0;  /* Let OS assign port */
	info.protocols = protocols;
	info.options = LWS_SERVER_OPTION_ONLY_RAW;

	vh = lws_create_vhost(G.context, &info);
	if (!vh) {
		lwsl_err("Failed to create vhost\n");
		lws_context_destroy(G.context);
		G.context = NULL;
		return -1;
	}

	/* Get the assigned port */
	test_port = lws_get_vhost_port(vh);

	return 0;
}

/*
 * Destroy test context for clean isolation
 */
static void
teardown_test_context(void)
{
	if (G.context) {
		lws_context_destroy(G.context);
		G.context = NULL;
	}
	G.client_wsi = NULL;
	G.accepted_wsi = NULL;
}

/*
 * Connect MQTT client to test server
 */
static int
connect_client(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context = G.context;
	i.address = "127.0.0.1";
	i.host = "127.0.0.1";
	i.port = test_port;
	i.protocol = "mqtt";
	i.method = "MQTT";
	i.mqtt_cp = &mqtt_connect_param;
	i.retry_and_idle_policy = &retry;

	G.client_wsi = lws_client_connect_via_info(&i);
	if (!G.client_wsi) {
		lwsl_err("Failed to create client\n");
		return -1;
	}

	return 0;
}

/*
 * Run a single packet test with specified fragmentation
 *
 * Test flags:
 *   need_sub: Test requires client to subscribe before receiving packet
 *   need_pub: Test requires client to publish QoS1 (for receiving PUBACK)
 */
static int
run_packet_test_ex(const char *name, const uint8_t *data, size_t len,
		   uint8_t packet_type, enum frag_mode mode, int expect_success,
		   int need_sub, int need_pub)
{
	int timeout = 2000; /* Max iterations (5ms each = 10s max) */
	int result;

	lwsl_user("  Testing %s [%s]...\n", name, frag_mode_names[mode]);

	/* Create fresh context for this test */
	if (setup_test_context()) {
		lwsl_err("    FAIL: Could not create test context\n");
		return 1;
	}

	/* Reset state */
	G.send_data = data;
	G.send_len = len;
	G.send_pos = 0;
	G.frag_mode = mode;
	G.packets_received = 0;
	G.expected_packets = 1;
	G.parse_errors = 0;
	G.test_complete = 0;
	G.interrupted = 0;
	G.in_cleanup = 0;
	G.test_name = name;
	G.expected_packet_type = packet_type;
	G.phase = PHASE_WAITING_CONNECT;
	G.need_subscribe = need_sub;
	G.need_client_publish = need_pub;
	G.test_server_qos1_pub = 0;
	G.subscription_done = 0;
	G.client_publish_done = 0;
	G.client_puback_received = 0;
	G.subscribe_packet_id = 0;
	G.client_publish_packet_id = 0;
	G.server_publish_packet_id = 0;

	/* Reset dynamic packet positions */
	suback_response_pos = 0;
	puback_response_pos = 0;

	/* For non-CONNACK packets without handshake flow, send CONNACK first */
	G.connection_established = 0;
	if (packet_type != 2 && expect_success && !need_sub) {
		G.prefix_data = pkt_connack_ok;
		G.prefix_len = sizeof(pkt_connack_ok);
		G.prefix_pos = 0;
		G.prefix_sent = 0;
		G.expected_packets = 2; /* CONNACK + test packet */
	} else {
		G.prefix_data = NULL;
		G.prefix_len = 0;
		G.prefix_pos = 0;
		G.prefix_sent = 0;
	}

	/* Connect client */
	if (connect_client()) {
		lwsl_err("    FAIL: Could not connect\n");
		return 1;
	}

	/* Run event loop until test completes or timeout */
	{
		int pingresp_iterations = 0;
		while (!G.test_complete && !G.interrupted && timeout-- > 0) {
			lws_service(G.context, 5);

			/* Trigger server to send data once connection is established (non-handshake mode) */
			if (!G.need_subscribe && G.connection_established &&
			    G.accepted_wsi && G.send_pos < G.send_len) {
				lws_callback_on_writable(G.accepted_wsi);
			}

			/*
			 * For packets with no callback (PINGRESP), consider test complete
			 * once all data is sent and no errors occurred after a few iterations.
			 */
			if (packet_type == 13 /* PINGRESP */ &&
			    G.connection_established &&
			    G.send_pos >= G.send_len &&
			    G.parse_errors == 0) {
				if (++pingresp_iterations >= 5)
					G.test_complete = 1;
			}
		}
	}
	lwsl_notice("Event loop exited: test_complete=%d, timeout=%d\n",
		    G.test_complete, timeout);

	/*
	 * Mark cleanup phase immediately so that connection closes during
	 * the final service calls don't get counted as parser errors.
	 */
	G.in_cleanup = 1;

	/* Evaluate results */
	if (G.interrupted) {
		lwsl_err("    SKIP: Interrupted\n");
		return 0;
	}

	if (timeout <= 0) {
		lwsl_err("    FAIL: Timeout (phase=%d, subscription_done=%d)\n",
			 G.phase, G.subscription_done);
		return 1;
	}

	if (expect_success) {
		if (G.parse_errors > 0) {
			lwsl_err("    FAIL: Parse errors occurred\n");
			result = 1;
		} else if (G.packets_received < 1 && packet_type != 13 /* PINGRESP has no callback */) {
			lwsl_err("    FAIL: No packets received\n");
			result = 1;
		} else {
			lwsl_user("    PASS\n");
			result = 0;
		}
	} else {
		/* Expected failure */
		if (G.parse_errors > 0 || !G.test_complete) {
			lwsl_user("    PASS (error detected as expected)\n");
			result = 0;
		} else {
			lwsl_err("    FAIL: Should have failed but didn't\n");
			result = 1;
		}
	}

	/* Destroy context for clean isolation */
	teardown_test_context();

	return result;
}

/*
 * Simple wrapper for basic tests (no handshake)
 */
static int
run_packet_test(const char *name, const uint8_t *data, size_t len,
		uint8_t packet_type, enum frag_mode mode, int expect_success)
{
	return run_packet_test_ex(name, data, len, packet_type, mode,
				  expect_success, 0, 0);
}

/*
 * Test server-to-client QoS1 PUBLISH with client PUBACK response
 * Flow: CONNACK -> SUBSCRIBE -> SUBACK -> server PUBLISH QoS1 -> client PUBACK
 */
static int
run_server_qos1_publish_test(const char *name, const uint8_t *pub_data, size_t pub_len,
			     uint16_t packet_id, enum frag_mode mode)
{
	int timeout = 2000;
	int result;

	lwsl_user("  Testing %s [%s]...\n", name, frag_mode_names[mode]);

	if (setup_test_context()) {
		lwsl_err("    FAIL: Could not create test context\n");
		return 1;
	}

	/* Reset state */
	G.send_data = pub_data;
	G.send_len = pub_len;
	G.send_pos = 0;
	G.frag_mode = mode;
	G.packets_received = 0;
	G.expected_packets = 1;
	G.parse_errors = 0;
	G.test_complete = 0;
	G.interrupted = 0;
	G.in_cleanup = 0;
	G.test_name = name;
	G.expected_packet_type = 3; /* PUBLISH */
	G.phase = PHASE_WAITING_CONNECT;
	G.need_subscribe = 1;
	G.need_client_publish = 0;
	G.test_server_qos1_pub = 1;
	G.subscription_done = 0;
	G.client_publish_done = 0;
	G.client_puback_received = 0;
	G.subscribe_packet_id = 0;
	G.client_publish_packet_id = 0;
	G.server_publish_packet_id = packet_id;
	G.prefix_data = NULL;
	G.prefix_len = 0;
	G.prefix_pos = 0;
	G.prefix_sent = 0;
	G.connection_established = 0;

	suback_response_pos = 0;
	puback_response_pos = 0;

	if (connect_client()) {
		lwsl_err("    FAIL: Could not connect\n");
		teardown_test_context();
		return 1;
	}

	while (!G.test_complete && !G.interrupted && timeout-- > 0) {
		lws_service(G.context, 5);
	}

	G.in_cleanup = 1;

	if (G.interrupted) {
		lwsl_err("    SKIP: Interrupted\n");
		teardown_test_context();
		return 0;
	}

	if (timeout <= 0) {
		lwsl_err("    FAIL: Timeout (phase=%d, puback_received=%d)\n",
			 G.phase, G.client_puback_received);
		result = 1;
	} else if (G.parse_errors > 0) {
		lwsl_err("    FAIL: Parse errors occurred\n");
		result = 1;
	} else if (!G.client_puback_received) {
		lwsl_err("    FAIL: Did not receive client PUBACK\n");
		result = 1;
	} else {
		lwsl_user("    PASS\n");
		result = 0;
	}

	teardown_test_context();
	return result;
}

/*
 * Test multi-packet parsing with boundary crossing
 *
 * This tests the critical edge case where one read buffer contains the
 * trailing portion of one MQTT packet and the beginning of another.
 * TCP can deliver data in arbitrary chunks, so the parser must handle
 * this correctly.
 *
 * Flow: CONNACK -> SUBSCRIBE -> SUBACK -> [multi-packet data with splits]
 *
 * The multi-packet data (e.g., PUBLISH + PINGRESP) is sent in two chunks:
 *   Chunk 1: bytes [0, split_at)
 *   Chunk 2: bytes [split_at, len)
 *
 * Key test cases:
 *   - split_at = 0: all data in second chunk (first chunk empty)
 *   - split_at = boundary: exact packet boundary (no crossing)
 *   - split_at = boundary - 1: last byte of packet A in chunk 2
 *   - split_at = boundary + 1: first byte of packet B in chunk 1
 */
static int
run_boundary_crossing_test(const char *name, const uint8_t *data, size_t len,
			   int expected_packets, size_t split_at)
{
	int timeout = 2000;
	int result;

	lwsl_user("  Testing %s [split@%zu/%zu]...\n", name, split_at, len);

	if (setup_test_context()) {
		lwsl_err("    FAIL: Could not create test context\n");
		return 1;
	}

	/* Reset state for multi-packet with subscription */
	G.send_data = data;
	G.send_len = len;
	G.send_pos = 0;
	G.frag_mode = (split_at == 0 || split_at >= len) ? FRAG_NONE : FRAG_CUSTOM_SPLIT;
	G.frag_split_at = split_at; /* Custom split point */
	G.packets_received = 0;
	G.expected_packets = expected_packets;
	G.parse_errors = 0;
	G.test_complete = 0;
	G.interrupted = 0;
	G.in_cleanup = 0;
	G.test_name = name;
	G.expected_packet_type = 0; /* Multiple types */
	G.phase = PHASE_WAITING_CONNECT;
	G.need_subscribe = 1;
	G.need_client_publish = 0;
	G.test_server_qos1_pub = 0;
	G.subscription_done = 0;
	G.client_publish_done = 0;
	G.client_puback_received = 0;
	G.subscribe_packet_id = 0;
	G.prefix_data = NULL;
	G.prefix_len = 0;
	G.prefix_pos = 0;
	G.prefix_sent = 0;
	G.connection_established = 0;

	suback_response_pos = 0;

	if (connect_client()) {
		lwsl_err("    FAIL: Could not connect\n");
		teardown_test_context();
		return 1;
	}

	/*
	 * Run event loop until we've received expected packets or timeout.
	 * For multi-packet, test_complete isn't set automatically - we
	 * count packets_received instead.
	 */
	while (!G.interrupted && timeout-- > 0 &&
	       G.packets_received < expected_packets &&
	       G.parse_errors == 0) {
		lws_service(G.context, 5);
	}

	G.in_cleanup = 1;

	if (G.interrupted) {
		lwsl_err("    SKIP: Interrupted\n");
		teardown_test_context();
		return 0;
	}

	if (timeout <= 0) {
		lwsl_err("    FAIL: Timeout (received %d/%d, phase=%d)\n",
			 G.packets_received, expected_packets, G.phase);
		result = 1;
	} else if (G.parse_errors > 0) {
		lwsl_err("    FAIL: Parse errors\n");
		result = 1;
	} else if (G.packets_received < expected_packets) {
		lwsl_err("    FAIL: Expected %d packets, got %d\n",
			 expected_packets, G.packets_received);
		result = 1;
	} else {
		lwsl_user("    PASS (%d packets)\n", G.packets_received);
		result = 0;
	}

	teardown_test_context();
	return result;
}

static void
sigint_handler(int sig)
{
	G.interrupted = 1;
}

int main(int argc, const char **argv)
{
	int fail = 0;
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *p;
	enum frag_mode mode;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS MQTT Packet Parser Tests\n");
	lwsl_user("============================\n\n");

	/*
	 * Each test creates its own context for clean isolation.
	 * This eliminates delays from stale connection cleanup.
	 */

	/*
	 * Test 1: CONNACK packets with various fragmentation modes
	 */
	lwsl_user("Test 1: CONNACK parsing with fragmentation\n");
	for (mode = FRAG_NONE; mode < FRAG_MODE_COUNT && !G.interrupted; mode++) {
		fail += run_packet_test("connack_ok", pkt_connack_ok,
					sizeof(pkt_connack_ok), 2, mode, 1);
	}

	/*
	 * Test 2: PUBLISH parsing with fragmentation
	 * Client must subscribe before receiving PUBLISH.
	 * Flow: CONNACK -> SUBSCRIBE -> SUBACK -> PUBLISH
	 */
	if (!G.interrupted) {
		lwsl_user("\nTest 2: PUBLISH parsing with fragmentation\n");
		for (mode = FRAG_NONE; mode < FRAG_MODE_COUNT && !G.interrupted; mode++) {
			fail += run_packet_test_ex("publish_qos0", pkt_publish_qos0,
						   sizeof(pkt_publish_qos0), 3, mode, 1,
						   1, 0); /* need_sub=1, need_pub=0 */
		}
	}

	/*
	 * Test 3: SUBACK parsing with fragmentation
	 * Client sends SUBSCRIBE, server responds with SUBACK.
	 * Flow: CONNACK -> SUBSCRIBE -> SUBACK
	 */
	if (!G.interrupted) {
		lwsl_user("\nTest 3: SUBACK parsing with fragmentation\n");
		for (mode = FRAG_NONE; mode < FRAG_MODE_COUNT && !G.interrupted; mode++) {
			/* SUBACK is already sent by server in handshake flow */
			/* Test the dynamic SUBACK built from SUBSCRIBE packet ID */
			fail += run_packet_test_ex("suback_dynamic", NULL, 0, 9, mode, 1,
						   1, 0); /* need_sub=1, gets SUBACK response */
		}
	}

	/*
	 * Test 4: PUBACK parsing with fragmentation
	 * Client publishes QoS1, server responds with PUBACK.
	 * Flow: CONNACK -> SUBSCRIBE -> SUBACK -> client PUBLISH -> PUBACK
	 */
	if (!G.interrupted) {
		lwsl_user("\nTest 4: PUBACK parsing with fragmentation\n");
		for (mode = FRAG_NONE; mode < FRAG_MODE_COUNT && !G.interrupted; mode++) {
			/* PUBACK built dynamically from client's PUBLISH packet ID */
			fail += run_packet_test_ex("puback_dynamic", NULL, 0, 4, mode, 1,
						   1, 1); /* need_sub=1, need_pub=1 */
		}
	}

	/*
	 * Test 5: PINGRESP parsing
	 * PINGRESP has no callback but should parse without error.
	 * Test by sending after CONNACK and verifying connection stays alive.
	 */
	if (!G.interrupted) {
		lwsl_user("\nTest 5: PINGRESP parsing\n");
		/*
		 * PINGRESP is 2 bytes (0xD0 0x00). Send after CONNACK.
		 * Success = connection stays alive (no parse error).
		 * We use expected_packet_type 13 (PINGRESP >> 4 = 0xD0 >> 4)
		 * but there's no callback, so we check for no errors.
		 */
		for (mode = FRAG_NONE; mode < FRAG_MODE_COUNT && !G.interrupted; mode++) {
			fail += run_packet_test("pingresp", pkt_pingresp,
						sizeof(pkt_pingresp), 13, mode, 1);
		}
	}

	/*
	 * Test 6: Server QoS1 PUBLISH with client PUBACK
	 * Server sends QoS1 PUBLISH, client auto-sends PUBACK, server verifies.
	 * Flow: CONNACK -> SUBSCRIBE -> SUBACK -> server PUBLISH QoS1 -> client PUBACK
	 */
	if (!G.interrupted) {
		lwsl_user("\nTest 6: Server QoS1 PUBLISH (client PUBACK)\n");
		for (mode = FRAG_NONE; mode < FRAG_MODE_COUNT && !G.interrupted; mode++) {
			/* pkt_publish_qos1 has packet_id=1 at bytes [8:9] */
			fail += run_server_qos1_publish_test("publish_qos1_from_server",
							     pkt_publish_qos1,
							     sizeof(pkt_publish_qos1),
							     1, mode);
		}
	}

	/*
	 * Test 7: Invalid packet rejection
	 * Test that malformed packets are rejected even in complete mode.
	 */
	if (!G.interrupted) {
		lwsl_user("\nTest 7: Invalid packet rejection\n");

		fail += run_packet_test("invalid_type_0", pkt_invalid_type_0,
					sizeof(pkt_invalid_type_0), 0,
					FRAG_NONE, 0);

		fail += run_packet_test("invalid_puback_flags", pkt_invalid_puback_flags,
					sizeof(pkt_invalid_puback_flags), 0,
					FRAG_NONE, 0);
	}

	/*
	 * Test 8: Multi-packet boundary crossing
	 *
	 * This tests the critical edge case where one TCP read contains
	 * the trailing bytes of one MQTT packet and the leading bytes
	 * of another. The pkt_multi_publish_publish vector contains:
	 *   - PUBLISH 1: 10 bytes (offsets 0-9)
	 *   - PUBLISH 2: 10 bytes (offsets 10-19)
	 *
	 * We test splits at every byte offset to verify the parser
	 * correctly handles all boundary crossing scenarios:
	 *   - split_at = 0:  send all at once
	 *   - split_at = 9:  last byte of PUBLISH 1 in chunk 2 (boundary-1)
	 *   - split_at = 10: exact packet boundary
	 *   - split_at = 11: first byte of PUBLISH 2 in chunk 1 (boundary+1)
	 */
	if (!G.interrupted) {
		size_t i;
		const size_t pkt_len = sizeof(pkt_multi_publish_publish);

		lwsl_user("\nTest 8: Multi-packet boundary crossing\n");

		/* Test all split points from 0 to len */
		for (i = 0; i <= pkt_len && !G.interrupted; i++) {
			fail += run_boundary_crossing_test(
				"publish+publish",
				pkt_multi_publish_publish,
				pkt_len,
				2,  /* Two PUBLISH packets expected */
				i);
		}
	}

	/* Suppress unused - static SUBACK/PUBACK tested via dynamic versions */
	(void)pkt_suback_single_qos0;
	(void)pkt_puback_1;
	(void)pkt_publish_qos1_pktid;
	(void)multi_packet_tests;

	lwsl_user("\n============================\n");
	lwsl_user("Results: %s (%d failures)\n",
		  fail ? "FAIL" : "PASS", fail);
	lwsl_user("============================\n");

	return fail ? 1 : 0;
}
