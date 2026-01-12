/*
 * MQTT Packet Test Vectors
 *
 * Pre-built MQTT packets for testing parser with fragmentation scenarios.
 * Each packet is a complete, valid MQTT packet that can be fed to the parser
 * either whole, byte-by-byte, or split at arbitrary boundaries.
 */

#ifndef MQTT_PACKETS_H
#define MQTT_PACKETS_H

#include <stdint.h>
#include <stddef.h>

/*
 * MQTT Control Packet Types (from spec section 2.1.2)
 */
#define MQTT_CONNACK	0x20
#define MQTT_PUBLISH	0x30
#define MQTT_PUBACK	0x40
#define MQTT_PUBREC	0x50
#define MQTT_PUBREL	0x62  /* Fixed flags: 0010 */
#define MQTT_PUBCOMP	0x70
#define MQTT_SUBACK	0x90
#define MQTT_UNSUBACK	0xB0
#define MQTT_PINGRESP	0xD0

/*
 * CONNACK packets
 */

/* CONNACK: Session not present, Connection Accepted */
static const uint8_t pkt_connack_ok[] = {
	0x20, 0x02,	/* Fixed header: CONNACK, remaining length 2 */
	0x00,		/* Connect Acknowledge Flags: session not present */
	0x00		/* Return code: Connection Accepted */
};

/* CONNACK: Session present, Connection Accepted */
static const uint8_t pkt_connack_session_present[] = {
	0x20, 0x02,
	0x01,		/* Connect Acknowledge Flags: session present */
	0x00
};

/* CONNACK: Connection refused - bad username/password */
static const uint8_t pkt_connack_bad_auth[] = {
	0x20, 0x02,
	0x00,
	0x05		/* Return code: Not authorized */
};

/* CONNACK: Connection refused - server unavailable */
static const uint8_t pkt_connack_unavailable[] = {
	0x20, 0x02,
	0x00,
	0x03		/* Return code: Server unavailable */
};

/*
 * PUBLISH packets - QoS 0 (no packet ID)
 */

/* PUBLISH QoS0: topic "t", payload "x" (minimal) */
static const uint8_t pkt_publish_minimal[] = {
	0x30, 0x04,	/* Fixed header: PUBLISH QoS0, remaining len 4 */
	0x00, 0x01,	/* Topic length: 1 */
	't',		/* Topic: "t" */
	'x'		/* Payload: "x" */
};

/* PUBLISH QoS0: topic "test", payload "hello" */
static const uint8_t pkt_publish_qos0[] = {
	0x30, 0x0b,	/* Fixed header: PUBLISH QoS0, remaining len 11 */
	0x00, 0x04,	/* Topic length: 4 */
	't', 'e', 's', 't',	/* Topic: "test" */
	'h', 'e', 'l', 'l', 'o'	/* Payload: "hello" */
};

/* PUBLISH QoS0 RETAIN: topic "sensor/temp", payload "23.5" */
static const uint8_t pkt_publish_qos0_retain[] = {
	0x31, 0x11,	/* Fixed header: PUBLISH QoS0 RETAIN, remaining len 17 */
	0x00, 0x0b,	/* Topic length: 11 */
	's', 'e', 'n', 's', 'o', 'r', '/', 't', 'e', 'm', 'p',
	'2', '3', '.', '5'
};

/* PUBLISH QoS0 DUP: topic "a/b", payload "dup" */
static const uint8_t pkt_publish_qos0_dup[] = {
	0x38, 0x08,	/* Fixed header: PUBLISH QoS0 DUP, remaining len 8 */
	0x00, 0x03,	/* Topic length: 3 */
	'a', '/', 'b',
	'd', 'u', 'p'
};

/*
 * PUBLISH packets - QoS 1 (with packet ID)
 */

/* PUBLISH QoS1: topic "test", packet ID 1, payload "hi" */
static const uint8_t pkt_publish_qos1[] = {
	0x32, 0x0a,	/* Fixed header: PUBLISH QoS1, remaining len 10 */
	0x00, 0x04,	/* Topic length: 4 */
	't', 'e', 's', 't',
	0x00, 0x01,	/* Packet ID: 1 */
	'h', 'i'	/* Payload: "hi" */
};

/* PUBLISH QoS1: topic "test", packet ID 0x1234, payload "data" */
static const uint8_t pkt_publish_qos1_pktid[] = {
	0x32, 0x0c,	/* Fixed header: PUBLISH QoS1, remaining len 12 */
	0x00, 0x04,	/* Topic length: 4 */
	't', 'e', 's', 't',
	0x12, 0x34,	/* Packet ID: 0x1234 */
	'd', 'a', 't', 'a'
};

/*
 * PUBLISH packets - QoS 2
 */

/* PUBLISH QoS2: topic "qos2", packet ID 42, payload "exactly once" */
static const uint8_t pkt_publish_qos2[] = {
	0x34, 0x14,	/* Fixed header: PUBLISH QoS2, remaining len 20 */
	0x00, 0x04,	/* Topic length: 4 */
	'q', 'o', 's', '2',
	0x00, 0x2a,	/* Packet ID: 42 */
	'e', 'x', 'a', 'c', 't', 'l', 'y', ' ', 'o', 'n', 'c', 'e'
};

/*
 * PUBLISH with multi-byte VBI remaining length
 */

/* PUBLISH QoS0 with 128-byte payload (2-byte VBI: 0x84 0x01 = 132) */
/* Topic "x" (3 bytes) + 128 bytes payload = 131 bytes remaining */
static const uint8_t pkt_publish_128byte_header[] = {
	0x30, 0x83, 0x01,	/* Fixed header with 2-byte VBI (131 = 0x83 + 0x01*128) */
	0x00, 0x01,		/* Topic length: 1 */
	'x'			/* Topic: "x" */
	/* 128 bytes of payload follow in separate array */
};

/*
 * PUBACK packets
 */

/* PUBACK: packet ID 1 */
static const uint8_t pkt_puback_1[] = {
	0x40, 0x02,	/* Fixed header: PUBACK, remaining len 2 */
	0x00, 0x01	/* Packet ID: 1 */
};

/* PUBACK: packet ID 0x1234 */
static const uint8_t pkt_puback_1234[] = {
	0x40, 0x02,
	0x12, 0x34
};

/* PUBACK: packet ID 0xFFFF (max) */
static const uint8_t pkt_puback_max[] = {
	0x40, 0x02,
	0xff, 0xff
};

/*
 * PUBREC packets (QoS2 step 2)
 */

/* PUBREC: packet ID 42 */
static const uint8_t pkt_pubrec[] = {
	0x50, 0x02,
	0x00, 0x2a	/* Packet ID: 42 */
};

/*
 * PUBREL packets (QoS2 step 3) - note fixed flags 0010
 */

/* PUBREL: packet ID 42 */
static const uint8_t pkt_pubrel[] = {
	0x62, 0x02,	/* Fixed flags must be 0010 */
	0x00, 0x2a
};

/*
 * PUBCOMP packets (QoS2 step 4)
 */

/* PUBCOMP: packet ID 42 */
static const uint8_t pkt_pubcomp[] = {
	0x70, 0x02,
	0x00, 0x2a
};

/*
 * SUBACK packets
 */

/* SUBACK: packet ID 1, single topic QoS0 granted */
static const uint8_t pkt_suback_single_qos0[] = {
	0x90, 0x03,	/* Fixed header: SUBACK, remaining len 3 */
	0x00, 0x01,	/* Packet ID: 1 */
	0x00		/* Return code: QoS0 granted */
};

/* SUBACK: packet ID 1, single topic QoS1 granted */
static const uint8_t pkt_suback_single_qos1[] = {
	0x90, 0x03,
	0x00, 0x01,
	0x01		/* Return code: QoS1 granted */
};

/* SUBACK: packet ID 1, single topic QoS2 granted */
static const uint8_t pkt_suback_single_qos2[] = {
	0x90, 0x03,
	0x00, 0x01,
	0x02		/* Return code: QoS2 granted */
};

/* SUBACK: packet ID 1, single topic failure */
static const uint8_t pkt_suback_failure[] = {
	0x90, 0x03,
	0x00, 0x01,
	0x80		/* Return code: Failure */
};

/* SUBACK: packet ID 5, multiple topics (QoS0, QoS1, failure) */
static const uint8_t pkt_suback_multi[] = {
	0x90, 0x05,	/* Remaining len: 2 (pkt id) + 3 (return codes) = 5 */
	0x00, 0x05,	/* Packet ID: 5 */
	0x00,		/* Topic 1: QoS0 granted */
	0x01,		/* Topic 2: QoS1 granted */
	0x80		/* Topic 3: Failure */
};

/*
 * UNSUBACK packets
 */

/* UNSUBACK: packet ID 1 */
static const uint8_t pkt_unsuback[] = {
	0xb0, 0x02,
	0x00, 0x01
};

/*
 * PINGRESP packet
 */

static const uint8_t pkt_pingresp[] = {
	0xd0, 0x00	/* Fixed header: PINGRESP, remaining len 0 */
};

/*
 * PUBLISH with empty payload (valid)
 */

static const uint8_t pkt_publish_empty_payload[] = {
	0x30, 0x05,	/* Remaining len: 2 (topic len) + 3 (topic) = 5 */
	0x00, 0x03,
	'a', '/', 'b'
	/* No payload */
};

/*
 * PUBLISH with longer topic for fragmentation testing
 */

static const uint8_t pkt_publish_long_topic[] = {
	0x30, 0x23,	/* Remaining len: 2 + 30 (topic) + 3 (payload) = 35 */
	0x00, 0x1e,	/* Topic length: 30 */
	's', 'e', 'n', 's', 'o', 'r', '/', 'd', 'e', 'v',
	'i', 'c', 'e', '/', '0', '0', '1', '/', 't', 'e',
	'm', 'p', 'e', 'r', 'a', 't', 'u', 'r', 'e', '/',
	'2', '5', 'C'	/* Payload: "25C" */
};

/*
 * Multi-packet sequence: CONNACK + PUBLISH
 * For testing multiple packets in single read buffer
 */

static const uint8_t pkt_multi_connack_publish[] = {
	/* CONNACK */
	0x20, 0x02, 0x00, 0x00,
	/* PUBLISH QoS0 */
	0x30, 0x07, 0x00, 0x03, 'a', '/', 'b', 'h', 'i'
};

/*
 * Multi-packet sequence: SUBACK + PUBLISH + PINGRESP
 */

static const uint8_t pkt_multi_suback_publish_ping[] = {
	/* SUBACK */
	0x90, 0x03, 0x00, 0x01, 0x00,
	/* PUBLISH QoS0 */
	0x30, 0x05, 0x00, 0x01, 't', 'o', 'k',
	/* PINGRESP */
	0xd0, 0x00
};

/*
 * Multi-packet sequence: PUBLISH + PUBLISH
 * For testing packet boundary crossing after subscription.
 * Two PUBLISH QoS0 packets in one buffer.
 *
 * Packet layout:
 *   PUBLISH 1: bytes 0-8 (9 bytes) - topic "test", payload "hi"
 *   PUBLISH 2: bytes 9-17 (9 bytes) - topic "test", payload "ok"
 */
static const uint8_t pkt_multi_publish_publish[] = {
	/* PUBLISH QoS0: topic "test", payload "hi" */
	0x30, 0x08,		/* Fixed header: PUBLISH, remaining len 8 */
	0x00, 0x04,		/* Topic length: 4 */
	't', 'e', 's', 't',
	'h', 'i',		/* Payload */
	/* PUBLISH QoS0: topic "test", payload "ok" */
	0x30, 0x08,		/* Fixed header: PUBLISH, remaining len 8 */
	0x00, 0x04,		/* Topic length: 4 */
	't', 'e', 's', 't',
	'o', 'k'		/* Payload */
};

/*
 * Invalid packets for error testing
 */

/* Invalid: packet type 0 (reserved) */
static const uint8_t pkt_invalid_type_0[] = {
	0x00, 0x00
};

/* Invalid: packet type 15 (reserved) */
static const uint8_t pkt_invalid_type_15[] = {
	0xf0, 0x00
};

/* Invalid: PUBACK with wrong flags (should be 0000) */
static const uint8_t pkt_invalid_puback_flags[] = {
	0x41, 0x02,	/* Wrong: flags should be 0 */
	0x00, 0x01
};

/* Invalid: PUBREL with wrong flags (should be 0010) */
static const uint8_t pkt_invalid_pubrel_flags[] = {
	0x60, 0x02,	/* Wrong: flags should be 0010 */
	0x00, 0x01
};

/* Invalid: SUBACK with zero remaining length */
static const uint8_t pkt_invalid_suback_zero[] = {
	0x90, 0x00	/* Missing packet ID and return codes */
};

/* Invalid: VBI overflow (5+ continuation bytes) */
static const uint8_t pkt_invalid_vbi_overflow[] = {
	0x30, 0x80, 0x80, 0x80, 0x80, 0x01  /* 5 VBI bytes - invalid */
};

/*
 * Test metadata structure
 */

struct mqtt_packet_test {
	const char *name;
	const uint8_t *data;
	size_t len;
	int expect_success;	/* 1 = should parse OK, 0 = should fail */
	uint8_t packet_type;	/* Expected packet type byte >> 4 */
};

#define PACKET_TEST(n, d, s, t) { n, d, sizeof(d), s, t }
#define PACKET_TEST_OK(n, d, t) PACKET_TEST(n, d, 1, t)
#define PACKET_TEST_FAIL(n, d) PACKET_TEST(n, d, 0, 0)

__attribute__((unused))
static struct mqtt_packet_test valid_packets[] = {
	PACKET_TEST_OK("connack_ok", pkt_connack_ok, 2),
	PACKET_TEST_OK("connack_session", pkt_connack_session_present, 2),
	PACKET_TEST_OK("publish_minimal", pkt_publish_minimal, 3),
	PACKET_TEST_OK("publish_qos0", pkt_publish_qos0, 3),
	PACKET_TEST_OK("publish_qos0_retain", pkt_publish_qos0_retain, 3),
	PACKET_TEST_OK("publish_qos1", pkt_publish_qos1, 3),
	PACKET_TEST_OK("publish_qos1_pktid", pkt_publish_qos1_pktid, 3),
	PACKET_TEST_OK("publish_qos2", pkt_publish_qos2, 3),
	PACKET_TEST_OK("publish_empty", pkt_publish_empty_payload, 3),
	PACKET_TEST_OK("publish_long_topic", pkt_publish_long_topic, 3),
	PACKET_TEST_OK("puback_1", pkt_puback_1, 4),
	PACKET_TEST_OK("puback_1234", pkt_puback_1234, 4),
	PACKET_TEST_OK("puback_max", pkt_puback_max, 4),
	PACKET_TEST_OK("pubrec", pkt_pubrec, 5),
	PACKET_TEST_OK("pubrel", pkt_pubrel, 6),
	PACKET_TEST_OK("pubcomp", pkt_pubcomp, 7),
	PACKET_TEST_OK("suback_qos0", pkt_suback_single_qos0, 9),
	PACKET_TEST_OK("suback_qos1", pkt_suback_single_qos1, 9),
	PACKET_TEST_OK("suback_multi", pkt_suback_multi, 9),
	PACKET_TEST_OK("unsuback", pkt_unsuback, 11),
	PACKET_TEST_OK("pingresp", pkt_pingresp, 13),
};

__attribute__((unused))
static struct mqtt_packet_test invalid_packets[] = {
	PACKET_TEST_FAIL("invalid_type_0", pkt_invalid_type_0),
	PACKET_TEST_FAIL("invalid_type_15", pkt_invalid_type_15),
	PACKET_TEST_FAIL("invalid_puback_flags", pkt_invalid_puback_flags),
	PACKET_TEST_FAIL("invalid_pubrel_flags", pkt_invalid_pubrel_flags),
};

/*
 * Multi-packet tests
 */

struct mqtt_multi_packet_test {
	const char *name;
	const uint8_t *data;
	size_t len;
	int expected_packet_count;
};

static struct mqtt_multi_packet_test multi_packet_tests[] = {
	{ "connack+publish", pkt_multi_connack_publish, sizeof(pkt_multi_connack_publish), 2 },
	{ "suback+publish+ping", pkt_multi_suback_publish_ping, sizeof(pkt_multi_suback_publish_ping), 3 },
};

#endif /* MQTT_PACKETS_H */
