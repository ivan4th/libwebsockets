/*
 * lws-mqtt-packet-fuzzer
 *
 * Written in 2025 for libwebsockets
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * libFuzzer harness for full MQTT packet parsing with proper connection setup.
 *
 * Unlike naive fuzzers that send random bytes, this fuzzer establishes proper
 * MQTT connection state before fuzzing, ensuring the parser is in the correct
 * state to process the fuzz data.
 *
 * Fuzz modes (selected by first byte of input):
 *   0x00-0x3F: FUZZ_CONNACK - Fuzz CONNACK response (connection setup)
 *   0x40-0x7F: FUZZ_POST_CONNECT - Fuzz after valid CONNACK
 *   0x80-0xBF: FUZZ_POST_SUBSCRIBE - Fuzz after full handshake
 *   0xC0-0xFF: FUZZ_MULTI_PACKET - Fuzz with packet boundary splitting
 *
 * Build with cmake (requires LWS_WITH_FUZZER=1):
 *   cmake .. -DLWS_ROLE_MQTT=1 -DLWS_WITH_FUZZER=1 -DCMAKE_C_COMPILER=clang
 *
 * Or standalone:
 *   clang -fsanitize=fuzzer,address,undefined -g \
 *         -I../../../include -I../../../ \
 *         mqtt-packet-fuzz.c -L../../../lib -lwebsockets -lssl -lcrypto \
 *         -o mqtt-packet-fuzz
 *
 * Run:
 *   mkdir -p corpus && ./mqtt-packet-fuzz corpus/ -max_len=4096
 */

#include <libwebsockets.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Fuzz configuration */
#define FUZZ_TIMEOUT_MS 100
#define FUZZ_PORT_BASE 40000
#define FUZZ_MAX_PACKET 4096

/* Fuzz modes */
enum fuzz_mode {
	FUZZ_CONNACK       = 0,  /* 0x00-0x3F: Fuzz CONNACK response */
	FUZZ_POST_CONNECT  = 1,  /* 0x40-0x7F: Fuzz after CONNACK */
	FUZZ_POST_SUBSCRIBE = 2, /* 0x80-0xBF: Fuzz after full handshake */
	FUZZ_MULTI_PACKET  = 3   /* 0xC0-0xFF: Fuzz with boundary splitting */
};

/* Valid MQTT packets for handshake */
static const uint8_t pkt_connack_ok[] = {0x20, 0x02, 0x00, 0x00};

/*
 * Test context for fuzzing
 */
static struct {
	struct lws_context *ctx;
	struct lws *client_wsi;
	int server_fd;
	int accepted_fd;
	int port;
	volatile int connection_established;
	volatile int subscribe_received;
	volatile int parsing_done;
	uint16_t subscribe_packet_id;
	pthread_mutex_t mutex;
} fuzz_ctx;

/*
 * MQTT client callback - tracks connection state
 */
static int
callback_mqtt_fuzz(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_MQTT_NEW_CLIENT_INSTANTIATED:
		fuzz_ctx.client_wsi = wsi;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		pthread_mutex_lock(&fuzz_ctx.mutex);
		fuzz_ctx.connection_established = 1;
		pthread_mutex_unlock(&fuzz_ctx.mutex);
		/* Request writable to trigger SUBSCRIBE */
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		/* Send SUBSCRIBE for POST_SUBSCRIBE mode */
		if (fuzz_ctx.connection_established && !fuzz_ctx.subscribe_received) {
			static lws_mqtt_topic_elem_t topics[] = {
				{ .name = "fuzz/#", .qos = QOS0 }
			};
			static lws_mqtt_subscribe_param_t sub = {
				.topic = topics,
				.num_topics = 1
			};
			lws_mqtt_client_send_subcribe(wsi, &sub);
		}
		break;

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		pthread_mutex_lock(&fuzz_ctx.mutex);
		fuzz_ctx.subscribe_received = 1;
		pthread_mutex_unlock(&fuzz_ctx.mutex);
		break;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
	case LWS_CALLBACK_MQTT_ACK:
		/* Successfully parsed a packet */
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		pthread_mutex_lock(&fuzz_ctx.mutex);
		fuzz_ctx.parsing_done = 1;
		pthread_mutex_unlock(&fuzz_ctx.mutex);
		fuzz_ctx.client_wsi = NULL;
		break;

	default:
		break;
	}

	return 0;
}

static struct lws_protocols fuzz_protocols[] = {
	{
		.name = "mqtt",
		.callback = callback_mqtt_fuzz,
		.per_session_data_size = 0,
		.rx_buffer_size = 1024,
	},
	LWS_PROTOCOL_LIST_TERM
};

static lws_mqtt_client_connect_param_t mqtt_connect = {
	.client_id = "fuzz",
	.keep_alive = 60,
	.clean_start = 1,
	.client_id_nofree = 1,
};

static const lws_retry_bo_t retry = {
	.secs_since_valid_ping = 60,
	.secs_since_valid_hangup = 120,
};

/*
 * Create TCP server socket
 */
static int
create_server_socket(int port)
{
	struct sockaddr_in addr;
	int fd, opt = 1;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = (uint16_t)htons((uint16_t)port);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	if (listen(fd, 1) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Initialize fuzzing context (called once at startup)
 */
static int
fuzz_init(void)
{
	struct lws_context_creation_info info;
	static int port = FUZZ_PORT_BASE;
	int retries = 100;

	/* Find available port */
	while (retries-- > 0) {
		fuzz_ctx.server_fd = create_server_socket(port);
		if (fuzz_ctx.server_fd >= 0) {
			fuzz_ctx.port = port;
			break;
		}
		port++;
	}

	if (fuzz_ctx.server_fd < 0)
		return -1;

	pthread_mutex_init(&fuzz_ctx.mutex, NULL);

	/* Create lws context */
	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = fuzz_protocols;
	info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	/* Quiet logs for fuzzing */
	lws_set_log_level(0, NULL);

	fuzz_ctx.ctx = lws_create_context(&info);
	if (!fuzz_ctx.ctx) {
		close(fuzz_ctx.server_fd);
		return -1;
	}

	return 0;
}

/*
 * Cleanup (called at exit)
 */
static void
fuzz_cleanup(void)
{
	if (fuzz_ctx.ctx)
		lws_context_destroy(fuzz_ctx.ctx);
	if (fuzz_ctx.server_fd >= 0)
		close(fuzz_ctx.server_fd);
	pthread_mutex_destroy(&fuzz_ctx.mutex);
}

/*
 * Parse SUBSCRIBE packet ID from raw bytes
 */
static uint16_t
parse_subscribe_packet_id(const uint8_t *data, size_t len)
{
	size_t offset = 1;
	uint32_t rem_len = 0;
	int shift = 0;

	/* Parse VBI remaining length (we just need to skip past it) */
	while (offset < len && shift < 28) {
		uint8_t b = data[offset++];
		rem_len |= (uint32_t)(b & 0x7f) << shift;
		if (!(b & 0x80))
			break;
		shift += 7;
	}
	(void)rem_len; /* Not used, just needed to skip VBI bytes */

	if (offset + 2 > len)
		return 1; /* Default packet ID */

	return (uint16_t)((data[offset] << 8) | data[offset + 1]);
}

/*
 * Build SUBACK response with matching packet ID
 */
static void
build_suback(uint8_t *buf, uint16_t packet_id)
{
	buf[0] = 0x90;  /* SUBACK */
	buf[1] = 0x03;  /* Remaining length */
	buf[2] = (uint8_t)(packet_id >> 8);
	buf[3] = (uint8_t)(packet_id & 0xff);
	buf[4] = 0x00;  /* QoS0 granted */
}

/*
 * Send data with fragmentation control
 */
static int
send_fragmented(int fd, const uint8_t *data, size_t size,
		int strategy, size_t chunk_size)
{
	size_t pos = 0;

	while (pos < size) {
		size_t to_send;
		ssize_t sent;

		switch (strategy) {
		case 0: /* All at once */
			to_send = size - pos;
			break;
		case 1: /* Single byte */
			to_send = 1;
			break;
		case 2: /* Chunked */
		default:
			to_send = chunk_size;
			if (to_send > size - pos)
				to_send = size - pos;
			break;
		}

		sent = write(fd, data + pos, to_send);
		if (sent <= 0)
			return -1;
		pos += (size_t)sent;
	}

	return 0;
}

/*
 * Wait for condition with timeout (short waits for fuzzing speed)
 */
static int
wait_for(volatile int *condition, int timeout_loops)
{
	while (!*condition && timeout_loops-- > 0)
		lws_service(fuzz_ctx.ctx, 1);
	return *condition ? 0 : -1;
}

/*
 * Feed fuzz data through MQTT parser with proper connection setup
 *
 * Input format:
 *   Byte 0: Mode + extra bits
 *     bits 6-7: fuzz mode (0-3)
 *     bits 0-5: mode-specific (e.g., split offset for MULTI_PACKET)
 *   Byte 1: Fragmentation control
 *     bits 0-1: strategy (0=all-at-once, 1=single-byte, 2=chunked)
 *     bits 2-7: chunk size for chunked mode
 *   Bytes 2+: Fuzz data
 */
static int
fuzz_packet(const uint8_t *data, size_t size)
{
	struct lws_client_connect_info conn;
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);
	struct timeval tv = { 0, 10000 };
	fd_set readfds;
	enum fuzz_mode mode;
	uint8_t mode_byte, frag_ctrl;
	int frag_strategy;
	size_t chunk_size, split_offset;
	uint8_t rx_buf[256];
	uint8_t suback_buf[5];
	ssize_t rx_len;
	int loops;

	if (size < 3)
		return 0;

	/* Parse control bytes */
	mode_byte = data[0];
	mode = (enum fuzz_mode)(mode_byte >> 6);
	split_offset = mode_byte & 0x3f;

	frag_ctrl = data[1];
	frag_strategy = frag_ctrl & 0x03;
	chunk_size = (frag_ctrl >> 2) + 1;

	data += 2;
	size -= 2;

	if (size > FUZZ_MAX_PACKET)
		size = FUZZ_MAX_PACKET;

	if (size == 0)
		return 0;

	/* Reset state */
	fuzz_ctx.connection_established = 0;
	fuzz_ctx.subscribe_received = 0;
	fuzz_ctx.parsing_done = 0;
	fuzz_ctx.subscribe_packet_id = 0;
	fuzz_ctx.accepted_fd = -1;

	/* Create MQTT client connection */
	memset(&conn, 0, sizeof(conn));
	conn.context = fuzz_ctx.ctx;
	conn.address = "127.0.0.1";
	conn.host = "127.0.0.1";
	conn.port = fuzz_ctx.port;
	conn.protocol = "mqtt";
	conn.method = "MQTT";
	conn.mqtt_cp = &mqtt_connect;
	conn.retry_and_idle_policy = &retry;

	fuzz_ctx.client_wsi = lws_client_connect_via_info(&conn);
	if (!fuzz_ctx.client_wsi)
		return 0;

	/* Accept connection from client (short timeout for fuzzing) */
	loops = 20;
	while (fuzz_ctx.accepted_fd < 0 && loops-- > 0) {
		FD_ZERO(&readfds);
		FD_SET(fuzz_ctx.server_fd, &readfds);
		tv.tv_sec = 0;
		tv.tv_usec = 1000; /* 1ms */
		if (select(fuzz_ctx.server_fd + 1, &readfds, NULL, NULL, &tv) > 0) {
			fuzz_ctx.accepted_fd = accept(fuzz_ctx.server_fd,
						      (struct sockaddr *)&client_addr,
						      &addr_len);
		}
		lws_service(fuzz_ctx.ctx, 0);
	}

	if (fuzz_ctx.accepted_fd < 0) {
		lws_service(fuzz_ctx.ctx, 10);
		return 0;
	}

	/* Read CONNECT packet from client */
	tv.tv_sec = 0;
	tv.tv_usec = 50000;
	FD_ZERO(&readfds);
	FD_SET(fuzz_ctx.accepted_fd, &readfds);
	if (select(fuzz_ctx.accepted_fd + 1, &readfds, NULL, NULL, &tv) > 0)
		read(fuzz_ctx.accepted_fd, rx_buf, sizeof(rx_buf));

	/*
	 * Mode-specific handshake
	 */
	switch (mode) {
	case FUZZ_CONNACK:
		/*
		 * Fuzz CONNACK response - tests connection setup parsing.
		 * Send fuzz data directly as the CONNACK response.
		 */
		send_fragmented(fuzz_ctx.accepted_fd, data, size,
				frag_strategy, chunk_size);
		break;

	case FUZZ_POST_CONNECT:
		/*
		 * Fuzz after valid CONNACK - tests established state.
		 * Send valid CONNACK, wait for established, then fuzz.
		 */
		if (write(fuzz_ctx.accepted_fd, pkt_connack_ok,
			  sizeof(pkt_connack_ok)) < 0)
			goto cleanup;

		if (wait_for(&fuzz_ctx.connection_established, 50) < 0)
			goto cleanup;

		send_fragmented(fuzz_ctx.accepted_fd, data, size,
				frag_strategy, chunk_size);
		break;

	case FUZZ_POST_SUBSCRIBE:
		/*
		 * Fuzz after full handshake - tests subscribed state.
		 * This is the most common real-world scenario.
		 */
		if (write(fuzz_ctx.accepted_fd, pkt_connack_ok,
			  sizeof(pkt_connack_ok)) < 0)
			goto cleanup;

		if (wait_for(&fuzz_ctx.connection_established, 50) < 0)
			goto cleanup;

		/* Wait for SUBSCRIBE from client */
		loops = 20;
		rx_len = 0;
		while (rx_len <= 0 && loops-- > 0) {
			tv.tv_sec = 0;
			tv.tv_usec = 1000; /* 1ms */
			FD_ZERO(&readfds);
			FD_SET(fuzz_ctx.accepted_fd, &readfds);
			if (select(fuzz_ctx.accepted_fd + 1, &readfds,
				   NULL, NULL, &tv) > 0) {
				rx_len = read(fuzz_ctx.accepted_fd, rx_buf,
					      sizeof(rx_buf));
			}
			lws_service(fuzz_ctx.ctx, 0);
		}

		if (rx_len > 0 && (rx_buf[0] & 0xf0) == 0x80) {
			/* Got SUBSCRIBE, send SUBACK */
			fuzz_ctx.subscribe_packet_id =
				parse_subscribe_packet_id(rx_buf, (size_t)rx_len);
			build_suback(suback_buf, fuzz_ctx.subscribe_packet_id);
			if (write(fuzz_ctx.accepted_fd, suback_buf, 5) < 0)
				goto cleanup;

			if (wait_for(&fuzz_ctx.subscribe_received, 50) < 0)
				goto cleanup;
		}

		send_fragmented(fuzz_ctx.accepted_fd, data, size,
				frag_strategy, chunk_size);
		break;

	case FUZZ_MULTI_PACKET:
		/*
		 * Fuzz with packet boundary splitting.
		 * Same as POST_SUBSCRIBE but split fuzz data at offset.
		 */
		if (write(fuzz_ctx.accepted_fd, pkt_connack_ok,
			  sizeof(pkt_connack_ok)) < 0)
			goto cleanup;

		if (wait_for(&fuzz_ctx.connection_established, 50) < 0)
			goto cleanup;

		/* Wait for SUBSCRIBE */
		loops = 50;
		rx_len = 0;
		while (rx_len <= 0 && loops-- > 0) {
			tv.tv_sec = 0;
			tv.tv_usec = 10000;
			FD_ZERO(&readfds);
			FD_SET(fuzz_ctx.accepted_fd, &readfds);
			if (select(fuzz_ctx.accepted_fd + 1, &readfds,
				   NULL, NULL, &tv) > 0) {
				rx_len = read(fuzz_ctx.accepted_fd, rx_buf,
					      sizeof(rx_buf));
			}
			lws_service(fuzz_ctx.ctx, 0);
		}

		if (rx_len > 0 && (rx_buf[0] & 0xf0) == 0x80) {
			fuzz_ctx.subscribe_packet_id =
				parse_subscribe_packet_id(rx_buf, (size_t)rx_len);
			build_suback(suback_buf, fuzz_ctx.subscribe_packet_id);
			if (write(fuzz_ctx.accepted_fd, suback_buf, 5) < 0)
				goto cleanup;

			if (wait_for(&fuzz_ctx.subscribe_received, 50) < 0)
				goto cleanup;
		}

		/* Split fuzz data at offset for boundary testing */
		if (split_offset > 0 && split_offset < size) {
			/* Send first chunk */
			if (write(fuzz_ctx.accepted_fd, data, split_offset) < 0)
				goto cleanup;
			lws_service(fuzz_ctx.ctx, 1);

			/* Send second chunk */
			send_fragmented(fuzz_ctx.accepted_fd,
					data + split_offset,
					size - split_offset,
					frag_strategy, chunk_size);
		} else {
			send_fragmented(fuzz_ctx.accepted_fd, data, size,
					frag_strategy, chunk_size);
		}
		break;
	}

	/* Let parser process */
	lws_service(fuzz_ctx.ctx, 1);

	/* Brief wait for parsing - don't wait too long for fuzzing speed */
	loops = 5;
	while (!fuzz_ctx.parsing_done && loops-- > 0)
		lws_service(fuzz_ctx.ctx, 1);

cleanup:
	if (fuzz_ctx.accepted_fd >= 0) {
		/* Shutdown socket to signal EOF to parser */
		shutdown(fuzz_ctx.accepted_fd, SHUT_RDWR);
		close(fuzz_ctx.accepted_fd);
		fuzz_ctx.accepted_fd = -1;
	}

	/* Quick service to process the close */
	lws_service(fuzz_ctx.ctx, 1);

	return 0;
}

/*
 * libFuzzer entry point
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int initialized = 0;

	if (!initialized) {
		if (fuzz_init() < 0)
			return 0;
		atexit(fuzz_cleanup);
		initialized = 1;
	}

	fuzz_packet(data, size);

	return 0;
}

/*
 * Seed corpus generator
 *
 * Build: clang -DCREATE_SEED_CORPUS mqtt-packet-fuzz.c -o gen-corpus
 * Run:   ./gen-corpus
 */
#ifdef CREATE_SEED_CORPUS
#include <stdio.h>
#include <sys/stat.h>

int main(void)
{
	FILE *f;

	mkdir("corpus", 0755);

	/* Mode 0: FUZZ_CONNACK - valid CONNACK */
	{
		uint8_t data[] = {
			0x00,        /* Mode 0, offset 0 */
			0x00,        /* Frag: all at once */
			0x20, 0x02, 0x00, 0x00  /* Valid CONNACK */
		};
		f = fopen("corpus/mode0_connack_valid.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	/* Mode 0: FUZZ_CONNACK - truncated */
	{
		uint8_t data[] = {
			0x00, 0x00,
			0x20, 0x02  /* Truncated CONNACK */
		};
		f = fopen("corpus/mode0_connack_trunc.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	/* Mode 0: FUZZ_CONNACK - wrong packet type */
	{
		uint8_t data[] = {
			0x00, 0x00,
			0x30, 0x07, 0x00, 0x03, 'a', '/', 'b', 'x'  /* PUBLISH instead */
		};
		f = fopen("corpus/mode0_wrong_type.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	/* Mode 1: FUZZ_POST_CONNECT - PUBLISH QoS0 */
	{
		uint8_t data[] = {
			0x40,        /* Mode 1 */
			0x00,        /* Frag: all at once */
			0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'h', 'i'
		};
		f = fopen("corpus/mode1_publish_qos0.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	/* Mode 1: FUZZ_POST_CONNECT - single byte frag */
	{
		uint8_t data[] = {
			0x40,        /* Mode 1 */
			0x01,        /* Frag: single byte */
			0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'h', 'i'
		};
		f = fopen("corpus/mode1_publish_fragmented.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	/* Mode 2: FUZZ_POST_SUBSCRIBE - PUBLISH after subscribe */
	{
		uint8_t data[] = {
			0x80,        /* Mode 2 */
			0x00,
			0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'o', 'k'
		};
		f = fopen("corpus/mode2_publish.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	/* Mode 2: FUZZ_POST_SUBSCRIBE - PUBLISH QoS1 */
	{
		uint8_t data[] = {
			0x80, 0x00,
			0x32, 0x0a, 0x00, 0x04, 't', 'e', 's', 't',
			0x00, 0x01, 'h', 'i'
		};
		f = fopen("corpus/mode2_publish_qos1.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	/* Mode 3: FUZZ_MULTI_PACKET - two publishes, split at boundary */
	{
		uint8_t data[] = {
			0xCA,        /* Mode 3, split at offset 10 */
			0x00,
			/* PUBLISH 1 (10 bytes) */
			0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'a', 'b',
			/* PUBLISH 2 (10 bytes) */
			0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'c', 'd'
		};
		f = fopen("corpus/mode3_multi_boundary.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	/* Mode 3: FUZZ_MULTI_PACKET - split mid-packet */
	{
		uint8_t data[] = {
			0xC5,        /* Mode 3, split at offset 5 */
			0x00,
			0x30, 0x08, 0x00, 0x04, 't', 'e', 's', 't', 'x', 'y'
		};
		f = fopen("corpus/mode3_split_mid.bin", "wb");
		if (f) { fwrite(data, 1, sizeof(data), f); fclose(f); }
	}

	printf("Seed corpus created in corpus/\n");
	return 0;
}
#endif /* CREATE_SEED_CORPUS */
