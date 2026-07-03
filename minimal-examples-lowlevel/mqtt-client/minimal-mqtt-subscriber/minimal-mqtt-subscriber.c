/*
 * lws-minimal-mqtt-subscriber
 *
 * Written in 2020-2025 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A minimal MQTT subscriber that connects to a broker and prints all
 * received messages with timestamps.
 *
 * Configuration via environment variables:
 *   MQTT_BROKER - Broker IP/hostname (required)
 *   MQTT_USER   - Username (optional)
 *   MQTT_PASS   - Password (optional)
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>

enum {
	STATE_SUBSCRIBE,
	STATE_LISTENING
};

static int interrupted;
static const char *broker_addr;
static const char *mqtt_user;
static const char *mqtt_pass;
static lws_mqtt_client_connect_param_t client_connect_param;

static const lws_retry_bo_t retry = {
	.secs_since_valid_ping		= 20,
	.secs_since_valid_hangup	= 25,
};

static lws_mqtt_topic_elem_t topics[] = {
	{ .name = "#", .qos = QOS0 },
};

static lws_mqtt_subscribe_param_t sub_param = {
	.topic		= &topics[0],
	.num_topics	= LWS_ARRAY_SIZE(topics),
};

struct pss {
	int state;
};

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

static int
connect_client(struct lws_context *context)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof i);

	i.mqtt_cp = &client_connect_param;
	i.address = broker_addr;
	i.host = broker_addr;
	i.protocol = "mqtt";
	i.context = context;
	i.method = "MQTT";
	i.alpn = "mqtt";
	i.port = 1883;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: Client Connect Failed\n", __func__);
		return 1;
	}

	return 0;
}

static int
system_notify_cb(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		 int current, int target)
{
	struct lws_context *context = mgr->parent;

	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	if (connect_client(context))
		interrupted = 1;

	return 0;
}

static int
callback_mqtt(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	lws_mqtt_publish_param_t *pub;
	time_t now;
	struct tm *tm_info;
	char timestamp[32];

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: CLIENT_CONNECTION_ERROR: %s\n", __func__,
			 in ? (char *)in : "(null)");
		interrupted = 1;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_CLOSED:
		lwsl_user("%s: CLIENT_CLOSED\n", __func__);
		interrupted = 1;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_ESTABLISHED:
		lwsl_user("%s: MQTT_CLIENT_ESTABLISHED\n", __func__);
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_MQTT_SUBSCRIBED:
		lwsl_user("%s: MQTT_SUBSCRIBED - listening for messages...\n",
			  __func__);
		pss->state = STATE_LISTENING;
		break;

	case LWS_CALLBACK_MQTT_CLIENT_WRITEABLE:
		if (pss->state == STATE_SUBSCRIBE) {
			lwsl_user("%s: Subscribing to '#'\n", __func__);
			if (lws_mqtt_client_send_subcribe(wsi, &sub_param)) {
				lwsl_notice("%s: subscribe failed\n", __func__);
				return -1;
			}
		}
		return 0;

	case LWS_CALLBACK_MQTT_CLIENT_RX:
		pub = (lws_mqtt_publish_param_t *)in;
		if (!pub)
			return 0;

		now = time(NULL);
		tm_info = localtime(&now);
		strftime(timestamp, sizeof(timestamp),
			 "%Y-%m-%d %H:%M:%S", tm_info);

		printf("%s %.*s %.*s\n",
		       timestamp,
		       (int)pub->topic_len, pub->topic,
		       (int)pub->payload_len, (char *)pub->payload);
		fflush(stdout);
		return 0;

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

int main(int argc, const char **argv)
{
	lws_state_notify_link_t notifier = { { NULL, NULL, NULL },
					     system_notify_cb, "app" };
	lws_state_notify_link_t *na[] = { &notifier, NULL };
	struct lws_context_creation_info info;
	struct lws_context *context;
	int n = 0;

	/* Get configuration from environment */
	broker_addr = getenv("MQTT_BROKER");
	if (!broker_addr) {
		fprintf(stderr, "Error: MQTT_BROKER environment variable not set\n");
		fprintf(stderr, "Usage: MQTT_BROKER=ip [MQTT_USER=user MQTT_PASS=pass] %s\n",
			argv[0]);
		return 1;
	}

	mqtt_user = getenv("MQTT_USER");
	mqtt_pass = getenv("MQTT_PASS");

	/* Setup connection parameters */
	memset(&client_connect_param, 0, sizeof(client_connect_param));
	client_connect_param.client_id = "lws-mqtt-subscriber";
	client_connect_param.keep_alive = 60;
	client_connect_param.clean_start = 1;
	client_connect_param.client_id_nofree = 1;

	if (mqtt_user && mqtt_pass) {
		client_connect_param.username = mqtt_user;
		client_connect_param.password = mqtt_pass;
		client_connect_param.username_nofree = 1;
		client_connect_param.password_nofree = 1;
		lwsl_user("Connecting to %s with auth (user: %s)\n",
			  broker_addr, mqtt_user);
	} else {
		lwsl_user("Connecting to %s without auth\n", broker_addr);
	}

	signal(SIGINT, sigint_handler);
	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	info.register_notifier_list = na;
	info.fd_limit_per_thread = 1 + 1 + 1;
	info.retry_and_idle_policy = &retry;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	lwsl_user("Exiting\n");
	lws_context_destroy(context);

	return 0;
}
