/*
 * lws-mqtt-direct-fuzzer
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Direct MQTT parser fuzzer - calls _lws_mqtt_rx_parser() directly
 * without network overhead for high-speed fuzzing.
 *
 * This fuzzer tests the MQTT packet parser by:
 * 1. Creating a minimal lws context and wsi
 * 2. Setting up parser state for different connection phases
 * 3. Feeding fuzz data directly to the parser
 *
 * Fuzz modes (selected by first byte):
 *   0x00-0x3F: Parser in IDLE state (waiting for first packet)
 *   0x40-0x7F: Parser in ESTABLISHED state (after CONNACK)
 *   0x80-0xBF: Single-byte fragmentation mode
 *     Sub-modes (bits 4-5 of byte 0):
 *       00: Basic single-byte (ESTABLISHED)
 *       01: SUBSCRIBED state (awaiting SUBACK)
 *       10: QOS_PENDING state (unacked publish in flight)
 *       11: Reserved
 *   0xC0-0xFF: Random chunk fragmentation mode
 *     Sub-modes (bits 4-5 of byte 0):
 *       00: Basic chunked (ESTABLISHED)
 *       01: SUBSCRIBED state
 *       10: QOS_PENDING state
 *       11: Reserved
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -g -O1 \
 *     -I../../../build-mqtt-test/include \
 *     mqtt-direct-fuzz.c \
 *     -L../../../build-mqtt-test/lib -lwebsockets -lssl -lcrypto \
 *     -o mqtt-direct-fuzz
 *
 * Run:
 *   mkdir -p corpus && ./mqtt-direct-fuzz corpus/ -max_len=4096
 */

/* Include private headers for internal access */
#include "private-lib-core.h"
#include "private-lib-roles-mqtt.h"

#include <string.h>
#include <stdlib.h>

/* Fuzz modes */
enum fuzz_mode {
	FUZZ_IDLE         = 0,  /* Parser waiting for packet */
	FUZZ_ESTABLISHED  = 1,  /* Parser in established state */
	FUZZ_SINGLE_BYTE  = 2,  /* Feed data one byte at a time */
	FUZZ_CHUNKED      = 3   /* Feed in random chunks */
};

/* Sub-mode for CONNACK testing (bits 2-3 of mode_byte when mode=0 or mode=1) */
enum fuzz_connack_submode {
	CONNACK_SUBMODE_DISABLED   = 0,  /* Not in CONNACK wait mode */
	CONNACK_SUBMODE_SENT_CONNECT = 1 /* Simulate client waiting for CONNACK */
};

/* Sub-modes for FUZZ_SINGLE_BYTE and FUZZ_CHUNKED (bits 4-5 of mode_byte) */
enum fuzz_submode {
	SUBMODE_BASIC      = 0,  /* Basic mode with ESTABLISHED state */
	SUBMODE_SUBSCRIBED = 1,  /* SUBSCRIBED state (sent SUBSCRIBE) */
	SUBMODE_QOS_PENDING = 2  /* QoS in flight (unacked publish) */
};

/* Global context - created once */
static struct {
	struct lws_context *ctx;
	struct lws_vhost *vhost;
	int initialized;
} G;

/*
 * Minimal MQTT callback - just tracks state, doesn't do much
 */
static int
callback_mqtt_fuzz(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	/* Silently accept all callbacks */
	return 0;
}

static struct lws_protocols fuzz_protocols[] = {
	{
		.name = "mqtt",
		.callback = callback_mqtt_fuzz,
		.per_session_data_size = 0,
		.rx_buffer_size = 4096,
	},
	LWS_PROTOCOL_LIST_TERM
};

/*
 * Initialize global context (called once)
 */
static int
fuzz_init(void)
{
	struct lws_context_creation_info info;

	if (G.initialized)
		return 0;

	lws_set_log_level(0, NULL);  /* Quiet for fuzzing */

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = fuzz_protocols;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	G.ctx = lws_create_context(&info);
	if (!G.ctx)
		return -1;

	/* Cache vhost lookup */
	G.vhost = lws_get_vhost_by_name(G.ctx, "default");
	if (!G.vhost)
		G.vhost = lws_get_vhost_by_name(G.ctx, NULL);

	G.initialized = 1;
	return 0;
}

/*
 * Feed data to parser with optional fragmentation
 */
static void
feed_parser(struct lws *wsi, lws_mqtt_parser_t *par,
	    const uint8_t *data, size_t size,
	    int single_byte, uint8_t chunk_hint)
{
	size_t pos = 0;

	while (pos < size) {
		const uint8_t *p = data + pos;
		size_t chunk;
		int ret;

		if (single_byte) {
			chunk = 1;
		} else if (chunk_hint) {
			chunk = (chunk_hint % 16) + 1;
			if (chunk > size - pos)
				chunk = size - pos;
		} else {
			chunk = size - pos;
		}

		ret = _lws_mqtt_rx_parser(wsi, par, p, chunk);
		if (ret < 0)
			break;  /* Parser error - expected for fuzz inputs */

		pos += chunk;
	}
}

/*
 * Allocate and initialize minimal wsi structure for fuzzing.
 * Uses lws internals - this is fragile but necessary for direct fuzzing.
 */
static struct lws *
create_fuzz_wsi(int connack_mode)
{
	struct lws *wsi;

	/*
	 * Allocate wsi and mqtt structures manually.
	 * This is fragile but allows direct parser testing.
	 */
	wsi = lws_zalloc(sizeof(*wsi) + sizeof(struct _lws_mqtt_related), "fuzz-wsi");
	if (!wsi)
		return NULL;

	/* Point mqtt to the space after wsi */
	wsi->mqtt = (struct _lws_mqtt_related *)(wsi + 1);
	wsi->mqtt->wsi = wsi;

	/* Set up minimal required fields (use cached values) */
	wsi->a.context = G.ctx;
	wsi->a.vhost = G.vhost;
	wsi->a.protocol = &fuzz_protocols[0];

	/*
	 * Use lws_role_transition() to properly set the client role.
	 * This ensures struct layout consistency between fuzzer and library.
	 * Using LWSIFR_CLIENT as the role flag and LRS_UNCONNECTED as state.
	 */
	lws_role_transition(wsi, LWSIFR_CLIENT, LRS_UNCONNECTED, &role_ops_mqtt);

	/* Initialize parser state */
	wsi->mqtt->client.par.state = LMQCPP_IDLE;

	/*
	 * Set estate based on mode:
	 * - connack_mode=1: LGSMQTT_SENT_CONNECT (waiting for CONNACK)
	 * - connack_mode=0: LGSMQTT_IDLE (normal mode)
	 */
	if (connack_mode)
		wsi->mqtt->client.estate = LGSMQTT_SENT_CONNECT;
	else
		wsi->mqtt->client.estate = LGSMQTT_IDLE;

	return wsi;
}

static void
destroy_fuzz_wsi(struct lws *wsi)
{
	if (wsi) {
		if (wsi->mqtt) {
			/* Free topic inside rx_cpkt_param if it's a publish */
			if (wsi->mqtt->rx_cpkt_param) {
				lws_mqtt_publish_param_t *pub =
					(lws_mqtt_publish_param_t *)
						wsi->mqtt->rx_cpkt_param;
				if (pub->topic)
					lws_free(pub->topic);
				lws_free(wsi->mqtt->rx_cpkt_param);
			}
			/*
			 * The mqtt structure may have been reallocated by the
			 * parser during CONNACK processing (mqtt.c:1422).
			 * If mqtt is NOT pointing to the embedded space (wsi+1),
			 * it was separately allocated and needs to be freed.
			 */
			if (wsi->mqtt != (struct _lws_mqtt_related *)(wsi + 1))
				lws_free(wsi->mqtt);
		}
		lws_free(wsi);
	}
}

/*
 * Set up WSI state based on sub-mode for better coverage
 */
static void
setup_wsi_submode(struct lws *wsi, enum fuzz_submode submode)
{
	switch (submode) {
	case SUBMODE_BASIC:
		/* Basic ESTABLISHED state */
		wsi->mqtt->client.estate = LGSMQTT_ESTABLISHED;
		break;
	case SUBMODE_SUBSCRIBED:
		/* SUBSCRIBED state - we've sent SUBSCRIBE and received SUBACK */
		wsi->mqtt->client.estate = LGSMQTT_SUBSCRIBED;
		wsi->mqtt->ack_pkt_id = 1;  /* Expect responses with pkt_id 1 */
		break;
	case SUBMODE_QOS_PENDING:
		/* QoS in flight - we have an unacked PUBLISH */
		wsi->mqtt->client.estate = LGSMQTT_ESTABLISHED;
		wsi->mqtt->unacked_publish = 1;
		wsi->mqtt->ack_pkt_id = 1;  /* Expect PUBACK/PUBREC for pkt_id 1 */
		break;
	}
}

/*
 * libFuzzer entry point
 *
 * Input format:
 *   Byte 0: Mode + flags
 *     bits 6-7: fuzz mode (0-3)
 *     bit 2:    CONNACK submode (1=client waiting for CONNACK, for mode 0/1)
 *     bits 4-5: sub-mode for SINGLE_BYTE/CHUNKED modes
 *     bits 0-3: chunk hint for FUZZ_CHUNKED mode
 *   Bytes 1+: MQTT packet data to parse
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lws *wsi;
	lws_mqtt_parser_t *par;
	enum fuzz_mode mode;
	enum fuzz_submode submode;
	int connack_mode;
	uint8_t mode_byte, chunk_hint;

	if (size < 2)
		return 0;

	if (fuzz_init() < 0)
		return 0;

	/* Parse mode byte */
	mode_byte = data[0];
	mode = (enum fuzz_mode)(mode_byte >> 6);
	submode = (enum fuzz_submode)((mode_byte >> 4) & 0x03);
	connack_mode = (mode_byte >> 2) & 0x01;  /* Bit 2: CONNACK submode */
	chunk_hint = mode_byte & 0x0f;  /* Lower 4 bits for chunk hint */
	data++;
	size--;

	if (size == 0)
		return 0;

	/* Limit input size */
	if (size > 4096)
		size = 4096;

	/*
	 * Create a minimal wsi for the parser.
	 * For modes 0/1: connack_mode determines if we're waiting for CONNACK.
	 * For modes 2/3: connack_mode is ignored (submode controls estate).
	 */
	wsi = create_fuzz_wsi((mode <= FUZZ_ESTABLISHED) ? connack_mode : 0);
	if (!wsi)
		return 0;

	par = &wsi->mqtt->client.par;

	switch (mode) {
	case FUZZ_IDLE:
		/*
		 * Parser starts in IDLE, waiting for first packet byte.
		 * If connack_mode is set, estate is LGSMQTT_SENT_CONNECT
		 * which allows proper CONNACK parsing.
		 */
		par->state = LMQCPP_IDLE;
		feed_parser(wsi, par, data, size, 0, 0);
		break;

	case FUZZ_ESTABLISHED:
		/*
		 * Simulate established state - set estate and parse.
		 * connack_mode is ignored since we're already established.
		 */
		wsi->mqtt->client.estate = LGSMQTT_ESTABLISHED;
		par->state = LMQCPP_IDLE;
		feed_parser(wsi, par, data, size, 0, 0);
		break;

	case FUZZ_SINGLE_BYTE:
		/* Single-byte fragmentation with sub-mode state setup */
		setup_wsi_submode(wsi, submode);
		par->state = LMQCPP_IDLE;
		feed_parser(wsi, par, data, size, 1, 0);
		break;

	case FUZZ_CHUNKED:
		/* Random chunk sizes with sub-mode state setup */
		setup_wsi_submode(wsi, submode);
		par->state = LMQCPP_IDLE;
		feed_parser(wsi, par, data, size, 0, chunk_hint ? chunk_hint : 1);
		break;
	}

	destroy_fuzz_wsi(wsi);

	return 0;
}

#ifdef CREATE_SEED_CORPUS
#include <stdio.h>
#include <sys/stat.h>

int main(void)
{
	FILE *f;
	mkdir("corpus", 0755);

	/* Mode 0: IDLE - CONNACK (with CONNACK submode bit 2 set) */
	{
		uint8_t d[] = {0x04, 0x20, 0x02, 0x00, 0x00};
		f = fopen("corpus/idle_connack.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* Mode 0: IDLE - PUBLISH QoS0 */
	{
		uint8_t d[] = {0x00, 0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'h', 'i'};
		f = fopen("corpus/idle_publish.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* Mode 1: ESTABLISHED - PUBLISH */
	{
		uint8_t d[] = {0x40, 0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'o', 'k'};
		f = fopen("corpus/est_publish.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* Mode 2: SINGLE_BYTE - SUBACK */
	{
		uint8_t d[] = {0x80, 0x90, 0x03, 0x00, 0x01, 0x00};
		f = fopen("corpus/single_suback.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* Mode 3: CHUNKED - multi-packet */
	{
		uint8_t d[] = {0xC5, 0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'a', 'b',
			       0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'c', 'd'};
		f = fopen("corpus/chunk_multi.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === QoS Flow Corpus ===
	 */

	/* QoS 1: PUBACK */
	{
		uint8_t d[] = {0x40, 0x40, 0x02, 0x00, 0x01};
		f = fopen("corpus/qos1_puback.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* QoS 2 Step 1: PUBREC */
	{
		uint8_t d[] = {0x40, 0x50, 0x02, 0x00, 0x01};
		f = fopen("corpus/qos2_pubrec.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* QoS 2 Step 2: PUBREL (flags = 0x02) */
	{
		uint8_t d[] = {0x40, 0x62, 0x02, 0x00, 0x01};
		f = fopen("corpus/qos2_pubrel.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* QoS 2 Step 3: PUBCOMP */
	{
		uint8_t d[] = {0x40, 0x70, 0x02, 0x00, 0x01};
		f = fopen("corpus/qos2_pubcomp.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH QoS 1 (0x32 = PUBLISH + QoS 1) */
	{
		uint8_t d[] = {0x40, 0x32, 0x0B, 0x00, 0x04, 't', 'e', 's', 't',
			       0x00, 0x01, 'h', 'i'};
		f = fopen("corpus/publish_qos1.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH QoS 2 (0x34 = PUBLISH + QoS 2) */
	{
		uint8_t d[] = {0x40, 0x34, 0x0B, 0x00, 0x04, 't', 'e', 's', 't',
			       0x00, 0x01, 'h', 'i'};
		f = fopen("corpus/publish_qos2.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === SUBACK/UNSUBACK Corpus ===
	 */

	/* SUBACK with single topic result */
	{
		uint8_t d[] = {0x40, 0x90, 0x03, 0x00, 0x01, 0x00};
		f = fopen("corpus/suback_single.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* SUBACK with multiple topic results (3 topics: QoS 0, 1, 2) */
	{
		uint8_t d[] = {0x40, 0x90, 0x05, 0x00, 0x01, 0x00, 0x01, 0x02};
		f = fopen("corpus/suback_multi.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* SUBACK with failure code (0x80 = unspecified error) */
	{
		uint8_t d[] = {0x40, 0x90, 0x03, 0x00, 0x01, 0x80};
		f = fopen("corpus/suback_fail.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* UNSUBACK */
	{
		uint8_t d[] = {0x40, 0xB0, 0x02, 0x00, 0x01};
		f = fopen("corpus/unsuback.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === PINGRESP Corpus ===
	 */

	/* PINGRESP (empty payload) */
	{
		uint8_t d[] = {0x40, 0xD0, 0x00};
		f = fopen("corpus/pingresp.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === Extended Sub-Mode Corpus ===
	 * Mode 2 (0x80-0xBF): FUZZ_SINGLE_BYTE
	 *   bits 4-5: sub-mode (0=basic, 1=SUBSCRIBED, 2=QOS_PENDING)
	 * Mode 3 (0xC0-0xFF): FUZZ_CHUNKED
	 *   bits 4-5: sub-mode
	 */

	/* SUBSCRIBED state (submode 1) - single-byte: 0x80 | 0x10 = 0x90 */
	/* Incoming PUBLISH after subscription */
	{
		uint8_t d[] = {0x90, 0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'h', 'i'};
		f = fopen("corpus/subscribed_publish.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* SUBSCRIBED state - PUBLISH QoS 1 */
	{
		uint8_t d[] = {0x90, 0x32, 0x0B, 0x00, 0x04, 't', 'e', 's', 't',
			       0x00, 0x01, 'h', 'i'};
		f = fopen("corpus/subscribed_publish_qos1.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* QOS_PENDING state (submode 2) - single-byte: 0x80 | 0x20 = 0xA0 */
	/* PUBACK response for pending publish */
	{
		uint8_t d[] = {0xA0, 0x40, 0x02, 0x00, 0x01};
		f = fopen("corpus/qospending_puback.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* QOS_PENDING - PUBREC response */
	{
		uint8_t d[] = {0xA0, 0x50, 0x02, 0x00, 0x01};
		f = fopen("corpus/qospending_pubrec.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* CHUNKED mode with SUBSCRIBED state: 0xC0 | 0x10 | chunk=5 = 0xD5 */
	{
		uint8_t d[] = {0xD5, 0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'o', 'k'};
		f = fopen("corpus/chunked_subscribed_publish.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* CHUNKED mode with QOS_PENDING state: 0xC0 | 0x20 | chunk=3 = 0xE3 */
	{
		uint8_t d[] = {0xE3, 0x40, 0x02, 0x00, 0x01};
		f = fopen("corpus/chunked_qospending_puback.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === MQTT 5.0 Properties Corpus ===
	 * Property IDs:
	 *   0x01: Payload Format Indicator (1 byte)
	 *   0x02: Message Expiry Interval (4 bytes)
	 *   0x11: Session Expiry Interval (4 bytes)
	 *   0x13: Server Keep Alive (2 bytes)
	 *   0x1F: Reason String (UTF-8)
	 *   0x21: Receive Maximum (2 bytes)
	 *   0x22: Topic Alias Maximum (2 bytes)
	 *   0x23: Topic Alias (2 bytes)
	 *   0x24: Maximum QoS (1 byte)
	 *   0x25: Retain Available (1 byte)
	 *   0x26: User Property (UTF-8 pair)
	 *   0x27: Maximum Packet Size (4 bytes)
	 */

	/* CONNACK with Session Expiry (0x11) and Receive Maximum (0x21) */
	{
		uint8_t d[] = {
			0x04,  /* Mode: FUZZ_IDLE + CONNACK submode (bit 2) */
			0x20,  /* CONNACK */
			0x0B,  /* Remaining length: 11 */
			0x00,  /* Session present: 0 */
			0x00,  /* Reason code: Success */
			0x08,  /* Properties length: 8 */
			0x11, 0x00, 0x00, 0x0E, 0x10,  /* Session Expiry: 3600 */
			0x21, 0x00, 0x0A               /* Receive Max: 10 */
		};
		f = fopen("corpus/connack_props.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* CONNACK with multiple properties */
	{
		uint8_t d[] = {
			0x04,  /* Mode: FUZZ_IDLE + CONNACK submode (bit 2) */
			0x20,  /* CONNACK */
			0x14,  /* Remaining length: 20 */
			0x00,  /* Session present: 0 */
			0x00,  /* Reason code: Success */
			0x11,  /* Properties length: 17 */
			0x11, 0x00, 0x00, 0x0E, 0x10,  /* Session Expiry: 3600 */
			0x21, 0x00, 0x0A,              /* Receive Max: 10 */
			0x22, 0x00, 0x10,              /* Topic Alias Max: 16 */
			0x24, 0x02,                    /* Maximum QoS: 2 */
			0x25, 0x01,                    /* Retain Available: true */
			0x27, 0x00, 0x01, 0x00, 0x00   /* Max Packet Size: 65536 */
		};
		f = fopen("corpus/connack_multi_props.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with Payload Format and Message Expiry */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x31,  /* PUBLISH QoS 0, retain */
			0x14,  /* Remaining length: 20 */
			0x00, 0x04, 't', 'e', 's', 't',  /* Topic: "test" */
			0x07,  /* Properties length: 7 */
			0x01, 0x01,                      /* Payload Format: UTF-8 */
			0x02, 0x00, 0x00, 0x00, 0x3C,    /* Expiry: 60 sec */
			'h', 'e', 'l', 'l', 'o'          /* Payload */
		};
		f = fopen("corpus/publish_props.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with Topic Alias */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x30,  /* PUBLISH QoS 0 */
			0x0F,  /* Remaining length: 15 */
			0x00, 0x04, 't', 'e', 's', 't',  /* Topic: "test" */
			0x03,  /* Properties length: 3 */
			0x23, 0x00, 0x05,               /* Topic Alias: 5 */
			'h', 'i'                        /* Payload */
		};
		f = fopen("corpus/publish_topic_alias.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with User Property (key-value pair) */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x30,  /* PUBLISH QoS 0 */
			0x18,  /* Remaining length: 24 */
			0x00, 0x04, 't', 'e', 's', 't',
			0x0D,  /* Properties length: 13 */
			0x26,  /* User Property */
			0x00, 0x03, 'k', 'e', 'y',       /* Key: "key" */
			0x00, 0x03, 'v', 'a', 'l',       /* Value: "val" */
			'h', 'i'
		};
		f = fopen("corpus/publish_user_prop.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with Response Topic (for request/response) */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x30,  /* PUBLISH QoS 0 */
			0x18,  /* Remaining length: 24 */
			0x00, 0x04, 't', 'e', 's', 't',
			0x0B,  /* Properties length: 11 */
			0x08,  /* Response Topic */
			0x00, 0x07, 'r', 'e', 'p', 'l', 'y', '/', '1',
			'h', 'i'
		};
		f = fopen("corpus/publish_response_topic.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with Content Type */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x30,  /* PUBLISH QoS 0 */
			0x1B,  /* Remaining length: 27 */
			0x00, 0x04, 't', 'e', 's', 't',
			0x0E,  /* Properties length: 14 */
			0x03,  /* Content Type */
			0x00, 0x0A, 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n',
			'h', 'i'
		};
		f = fopen("corpus/publish_content_type.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBACK MQTT 5.0 with Reason String */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x40,  /* PUBACK */
			0x0C,  /* Remaining length: 12 */
			0x00, 0x01,  /* Packet ID: 1 */
			0x00,        /* Reason: Success */
			0x08,        /* Properties length: 8 */
			0x1F, 0x00, 0x05, 'g', 'o', 'o', 'd', '!'  /* Reason string */
		};
		f = fopen("corpus/puback_v5_reason.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBREC MQTT 5.0 with Reason String */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x50,  /* PUBREC */
			0x0A,  /* Remaining length: 10 */
			0x00, 0x01,  /* Packet ID: 1 */
			0x00,        /* Reason: Success */
			0x06,        /* Properties length: 6 */
			0x1F, 0x00, 0x03, 'a', 'c', 'k'  /* Reason string */
		};
		f = fopen("corpus/pubrec_v5_reason.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* SUBACK MQTT 5.0 with Reason String */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x90,  /* SUBACK */
			0x0B,  /* Remaining length: 11 */
			0x00, 0x01,  /* Packet ID: 1 */
			0x06,        /* Properties length: 6 */
			0x1F, 0x00, 0x03, 's', 'u', 'b',  /* Reason string */
			0x00         /* Granted QoS 0 */
		};
		f = fopen("corpus/suback_v5_reason.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* CONNACK with Server Keep Alive override */
	{
		uint8_t d[] = {
			0x04,  /* Mode: FUZZ_IDLE + CONNACK submode (bit 2) */
			0x20,  /* CONNACK */
			0x07,  /* Remaining length: 7 */
			0x00,  /* Session present: 0 */
			0x00,  /* Reason code: Success */
			0x04,  /* Properties length: 4 */
			0x13, 0x00, 0x1E  /* Server Keep Alive: 30 sec */
		};
		f = fopen("corpus/connack_keepalive.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* CONNACK with Assigned Client Identifier */
	{
		uint8_t d[] = {
			0x04,  /* Mode: FUZZ_IDLE + CONNACK submode (bit 2) */
			0x20,  /* CONNACK */
			0x10,  /* Remaining length: 16 */
			0x00,  /* Session present: 0 */
			0x00,  /* Reason code: Success */
			0x0D,  /* Properties length: 13 */
			0x12, 0x00, 0x0A, 'c', 'l', 'i', 'e', 'n', 't', '-', '1', '2', '3'
		};
		f = fopen("corpus/connack_assigned_id.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH QoS 1 with multiple properties (fragmentation test) */
	{
		uint8_t d[] = {
			0x80,  /* Mode: FUZZ_SINGLE_BYTE */
			0x32,  /* PUBLISH QoS 1 */
			0x1C,  /* Remaining length: 28 */
			0x00, 0x04, 't', 'e', 's', 't',
			0x00, 0x01,  /* Packet ID: 1 */
			0x0D,  /* Properties length: 13 */
			0x01, 0x01,                      /* Payload Format: UTF-8 */
			0x02, 0x00, 0x00, 0x00, 0x78,    /* Expiry: 120 sec */
			0x23, 0x00, 0x03,                /* Topic Alias: 3 */
			'p', 'a', 'y', 'l', 'o', 'a', 'd'
		};
		f = fopen("corpus/publish_qos1_multi_props.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === Edge Cases - VBI Parsing ===
	 * VBI (Variable Byte Integer) encoding:
	 *   1 byte:  0-127
	 *   2 bytes: 128-16383
	 *   3 bytes: 16384-2097151
	 *   4 bytes: 2097152-268435455
	 */

	/* PUBLISH with 2-byte VBI remaining length (128 = 0x80 0x01) */
	{
		/* We need payload to make remaining length >= 128 */
		uint8_t d[140];
		int i;
		d[0] = 0x40;  /* Mode: FUZZ_ESTABLISHED */
		d[1] = 0x30;  /* PUBLISH QoS 0 */
		d[2] = 0x83;  /* Remaining length byte 1: 0x83 = 131 & 0x7F | 0x80 */
		d[3] = 0x01;  /* Remaining length byte 2: upper bits */
		d[4] = 0x00; d[5] = 0x04;  /* Topic length: 4 */
		d[6] = 't'; d[7] = 'e'; d[8] = 's'; d[9] = 't';  /* Topic */
		d[10] = 0x00;  /* Properties length: 0 */
		for (i = 11; i < 140; i++) d[i] = 'x';  /* Fill payload */
		f = fopen("corpus/publish_2byte_vbi.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with short topic (1 char) */
	{
		uint8_t d[] = {0x40, 0x30, 0x06, 0x00, 0x01, 't', 0x00, 'h', 'i'};
		f = fopen("corpus/publish_short_topic.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with empty payload */
	{
		uint8_t d[] = {0x40, 0x30, 0x07, 0x00, 0x04, 't', 'e', 's', 't', 0x00};
		f = fopen("corpus/publish_empty_payload.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with DUP flag set (0x38 = PUBLISH + DUP) */
	{
		uint8_t d[] = {0x40, 0x38, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'h', 'i'};
		f = fopen("corpus/publish_dup.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with RETAIN flag (0x31 = PUBLISH + RETAIN) */
	{
		uint8_t d[] = {0x40, 0x31, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'h', 'i'};
		f = fopen("corpus/publish_retain.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH QoS 2 with DUP flag (0x3C = PUBLISH + QoS2 + DUP) */
	{
		uint8_t d[] = {
			0x40, 0x3C, 0x0B, 0x00, 0x04, 't', 'e', 's', 't',
			0x00, 0x01, 'h', 'i'
		};
		f = fopen("corpus/publish_qos2_dup.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === QoS2 Flow Variations with Reason Codes ===
	 */

	/* PUBREC with reason code 0x10 (No matching subscribers) */
	{
		uint8_t d[] = {0x40, 0x50, 0x04, 0x00, 0x01, 0x10, 0x00};
		f = fopen("corpus/pubrec_no_match.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBREC with reason code 0x80 (Unspecified error) */
	{
		uint8_t d[] = {0x40, 0x50, 0x04, 0x00, 0x01, 0x80, 0x00};
		f = fopen("corpus/pubrec_error.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBREL with reason code 0x92 (Packet ID not found) */
	{
		uint8_t d[] = {0x40, 0x62, 0x04, 0x00, 0x01, 0x92, 0x00};
		f = fopen("corpus/pubrel_notfound.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBCOMP with reason code 0x92 (Packet ID not found) */
	{
		uint8_t d[] = {0x40, 0x70, 0x04, 0x00, 0x01, 0x92, 0x00};
		f = fopen("corpus/pubcomp_notfound.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* Complete QoS 2 flow: PUBREC then PUBCOMP (simulated) */
	{
		uint8_t d[] = {
			0x40,  /* Mode: FUZZ_ESTABLISHED */
			0x50, 0x02, 0x00, 0x01,  /* PUBREC packet ID 1 */
			0x70, 0x02, 0x00, 0x01   /* PUBCOMP packet ID 1 */
		};
		f = fopen("corpus/qos2_flow_complete.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === MQTT 5.0 Property Edge Cases ===
	 */

	/* CONNACK with Wildcard Subscription Available */
	{
		uint8_t d[] = {
			0x04, 0x20, 0x05, 0x00, 0x00,
			0x02,  /* Properties length: 2 */
			0x28, 0x01  /* Wildcard Sub Available: true */
		};
		f = fopen("corpus/connack_wildcard.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* CONNACK with Shared Subscription Available */
	{
		uint8_t d[] = {
			0x04, 0x20, 0x05, 0x00, 0x00,
			0x02,  /* Properties length: 2 */
			0x2A, 0x01  /* Shared Sub Available: true */
		};
		f = fopen("corpus/connack_shared_sub.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* CONNACK with error reason code */
	{
		uint8_t d[] = {
			0x04, 0x20, 0x03, 0x00,
			0x87,  /* Reason: Not authorized */
			0x00   /* No properties */
		};
		f = fopen("corpus/connack_notauth.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* CONNACK with Session Present flag set */
	{
		uint8_t d[] = {
			0x04, 0x20, 0x03, 0x01,  /* Session Present: 1 */
			0x00,  /* Reason: Success */
			0x00   /* No properties */
		};
		f = fopen("corpus/connack_session_present.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with Subscription Identifier (VBI property) */
	{
		uint8_t d[] = {
			0x40, 0x30, 0x0C, 0x00, 0x04, 't', 'e', 's', 't',
			0x02,  /* Properties length: 2 */
			0x0B, 0x05,  /* Subscription ID: 5 */
			'h', 'i'
		};
		f = fopen("corpus/publish_sub_id.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with Correlation Data */
	{
		uint8_t d[] = {
			0x40, 0x30, 0x13, 0x00, 0x04, 't', 'e', 's', 't',
			0x08,  /* Properties length: 8 */
			0x09,  /* Correlation Data property */
			0x00, 0x04, 0x01, 0x02, 0x03, 0x04,  /* Binary data */
			'h', 'i'
		};
		f = fopen("corpus/publish_correlation.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === SUBACK/UNSUBACK Variations ===
	 */

	/* SUBACK with all failure codes */
	{
		uint8_t d[] = {
			0x40, 0x90, 0x07, 0x00, 0x01,
			0x00,  /* Properties length: 0 */
			0x80, 0x83, 0x87, 0x91  /* Various failure codes */
		};
		f = fopen("corpus/suback_failures.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* SUBACK with mixed success/failure */
	{
		uint8_t d[] = {
			0x40, 0x90, 0x06, 0x00, 0x01,
			0x00,  /* Properties length: 0 */
			0x00, 0x80, 0x01  /* QoS0, fail, QoS1 */
		};
		f = fopen("corpus/suback_mixed.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* UNSUBACK with multiple results */
	{
		uint8_t d[] = {
			0x40, 0xB0, 0x05, 0x00, 0x01,
			0x00,  /* Properties length: 0 */
			0x00, 0x11  /* Success, no subscription existed */
		};
		f = fopen("corpus/unsuback_multi.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === Large Packet ID Values ===
	 */

	/* PUBACK with large packet ID */
	{
		uint8_t d[] = {0x40, 0x40, 0x02, 0xFF, 0xFF};  /* Packet ID 65535 */
		f = fopen("corpus/puback_large_id.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH QoS 1 with large packet ID */
	{
		uint8_t d[] = {
			0x40, 0x32, 0x0B, 0x00, 0x04, 't', 'e', 's', 't',
			0xFF, 0xFF,  /* Packet ID 65535 */
			'h', 'i'
		};
		f = fopen("corpus/publish_large_id.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === Multi-byte topic names ===
	 */

	/* PUBLISH with longer topic */
	{
		uint8_t d[] = {
			0x40, 0x30, 0x1A,
			0x00, 0x10, 's', 'e', 'n', 's', 'o', 'r', '/', 't', 'e', 'm', 'p',
			'/', 'd', 'a', 't', 'a',
			0x00,  /* Properties length */
			't', 'e', 's', 't'
		};
		f = fopen("corpus/publish_long_topic.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PUBLISH with nested topic structure */
	{
		uint8_t d[] = {
			0x40, 0x30, 0x1C,
			0x00, 0x12, 'h', 'o', 'm', 'e', '/', 'l', 'i', 'v', 'i', 'n', 'g',
			'/', 'l', 'a', 'm', 'p', '/', '1',
			0x00, 'o', 'n'
		};
		f = fopen("corpus/publish_nested_topic.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === Chunked Mode Edge Cases ===
	 */

	/* Chunked mode with tiny chunks (size 1) */
	{
		uint8_t d[] = {
			0xC1,  /* Mode: FUZZ_CHUNKED, chunk size 1+1=2 */
			0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'h', 'i'
		};
		f = fopen("corpus/chunked_tiny.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* Chunked mode with large chunks */
	{
		uint8_t d[] = {
			0xCF,  /* Mode: FUZZ_CHUNKED, chunk size 15+1=16 */
			0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'h', 'i'
		};
		f = fopen("corpus/chunked_large.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/*
	 * === PINGREQ, DISCONNECT, AUTH Corpus ===
	 * These packet types were previously unhandled and are now supported.
	 */

	/* PINGREQ - valid packet (remaining length = 0) */
	{
		uint8_t d[] = {0x40, 0xC0, 0x00};
		f = fopen("corpus/pingreq_valid.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* PINGREQ - invalid (non-zero remaining length) */
	{
		uint8_t d[] = {0x40, 0xC0, 0x01, 0x00};
		f = fopen("corpus/pingreq_invalid.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* DISCONNECT - MQTT 3.1.1 style (no reason code) */
	{
		uint8_t d[] = {0x40, 0xE0, 0x00};
		f = fopen("corpus/disconnect_simple.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* DISCONNECT - MQTT 5.0 with reason code only */
	{
		uint8_t d[] = {0x40, 0xE0, 0x01, 0x00};  /* Reason: Normal disconnection */
		f = fopen("corpus/disconnect_reason.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* DISCONNECT - MQTT 5.0 with reason code 0x04 (Disconnect with Will Message) */
	{
		uint8_t d[] = {0x40, 0xE0, 0x02, 0x04, 0x00};  /* Reason + empty props */
		f = fopen("corpus/disconnect_will.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* DISCONNECT - MQTT 5.0 with Reason String property */
	{
		uint8_t d[] = {
			0x40, 0xE0, 0x0C,  /* Remaining length: 12 */
			0x00,  /* Reason: Normal disconnection */
			0x09,  /* Properties length: 9 */
			0x1F, 0x00, 0x06, 'c', 'l', 'o', 's', 'e', 'd'  /* Reason string */
		};
		f = fopen("corpus/disconnect_reason_string.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* AUTH - MQTT 5.0 Success (0x00) */
	{
		uint8_t d[] = {0x40, 0xF0, 0x02, 0x00, 0x00};
		f = fopen("corpus/auth_success.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* AUTH - MQTT 5.0 Continue Authentication (0x18) */
	{
		uint8_t d[] = {0x40, 0xF0, 0x02, 0x18, 0x00};
		f = fopen("corpus/auth_continue.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* AUTH - MQTT 5.0 Re-authenticate (0x19) */
	{
		uint8_t d[] = {0x40, 0xF0, 0x02, 0x19, 0x00};
		f = fopen("corpus/auth_reauth.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* AUTH - with Authentication Method property */
	{
		uint8_t d[] = {
			0x40, 0xF0, 0x0D,  /* Remaining length: 13 */
			0x00,  /* Reason: Success */
			0x0A,  /* Properties length: 10 */
			0x15, 0x00, 0x07, 'S', 'C', 'R', 'A', 'M', '-', '1'  /* Auth Method */
		};
		f = fopen("corpus/auth_method.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* AUTH - single-byte fragmentation mode */
	{
		uint8_t d[] = {0x80, 0xF0, 0x02, 0x18, 0x00};
		f = fopen("corpus/auth_fragmented.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	/* DISCONNECT - single-byte fragmentation mode */
	{
		uint8_t d[] = {0x80, 0xE0, 0x02, 0x04, 0x00};
		f = fopen("corpus/disconnect_fragmented.bin", "wb");
		if (f) { fwrite(d, 1, sizeof(d), f); fclose(f); }
	}

	printf("Seed corpus created\n");
	return 0;
}
#endif
