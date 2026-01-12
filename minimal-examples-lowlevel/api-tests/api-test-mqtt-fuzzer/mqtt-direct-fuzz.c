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
 *   0xC0-0xFF: Random chunk fragmentation mode
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
create_fuzz_wsi(void)
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
	wsi->role_ops = &role_ops_mqtt;  /* May not be exported */

	/* Initialize parser state */
	wsi->mqtt->client.par.state = LMQCPP_IDLE;
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
		}
		lws_free(wsi);
	}
}

/*
 * libFuzzer entry point
 *
 * Input format:
 *   Byte 0: Mode + flags
 *     bits 6-7: fuzz mode (0-3)
 *     bits 0-5: chunk hint for FUZZ_CHUNKED mode
 *   Bytes 1+: MQTT packet data to parse
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lws *wsi;
	lws_mqtt_parser_t *par;
	enum fuzz_mode mode;
	uint8_t mode_byte, chunk_hint;

	if (size < 2)
		return 0;

	if (fuzz_init() < 0)
		return 0;

	/* Parse mode byte */
	mode_byte = data[0];
	mode = (enum fuzz_mode)(mode_byte >> 6);
	chunk_hint = mode_byte & 0x3f;
	data++;
	size--;

	if (size == 0)
		return 0;

	/* Limit input size */
	if (size > 4096)
		size = 4096;

	/* Create a minimal wsi for the parser */
	wsi = create_fuzz_wsi();
	if (!wsi)
		return 0;

	par = &wsi->mqtt->client.par;

	switch (mode) {
	case FUZZ_IDLE:
		/* Parser starts in IDLE, waiting for first packet byte */
		par->state = LMQCPP_IDLE;
		feed_parser(wsi, par, data, size, 0, 0);
		break;

	case FUZZ_ESTABLISHED:
		/*
		 * Simulate established state - set estate and parse
		 */
		wsi->mqtt->client.estate = LGSMQTT_ESTABLISHED;
		par->state = LMQCPP_IDLE;
		feed_parser(wsi, par, data, size, 0, 0);
		break;

	case FUZZ_SINGLE_BYTE:
		/* Single-byte fragmentation - maximum stress */
		par->state = LMQCPP_IDLE;
		feed_parser(wsi, par, data, size, 1, 0);
		break;

	case FUZZ_CHUNKED:
		/* Random chunk sizes based on chunk_hint */
		par->state = LMQCPP_IDLE;
		feed_parser(wsi, par, data, size, 0, chunk_hint);
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

	/* Mode 0: IDLE - CONNACK */
	{
		uint8_t d[] = {0x00, 0x20, 0x02, 0x00, 0x00};
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

	printf("Seed corpus created\n");
	return 0;
}
#endif
