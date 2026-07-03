project(lws-api-test-mqtt-parser C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-mqtt-parser)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-mqtt-parser COMMAND lws-api-test-mqtt-parser)

	# Include path for private MQTT headers (needed to test internal parser functions)
	target_include_directories(${SAMP} PRIVATE
		${LWS_LIB_BUILD_INCLUDE_DIRS}
		${CMAKE_SOURCE_DIR}/lib/roles/mqtt
	)

	# always link the static lib: these tests use internal symbols
	target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})

	# Infinite loop bug test - tests for unhandled packet types
	set(LOOP_TEST lws-api-test-mqtt-infinite-loops)
	add_executable(${LOOP_TEST} test-infinite-loops.c)
	add_test(NAME api-test-mqtt-infinite-loops COMMAND lws-api-test-mqtt-infinite-loops)
	set_tests_properties(api-test-mqtt-infinite-loops PROPERTIES TIMEOUT 30)

	# CONNACK properties bug test - tests for MQTT 5.0 CONNACK remaining length validation
	set(CONNACK_TEST lws-api-test-mqtt-connack-props)
	add_executable(${CONNACK_TEST} test-connack-props.c)
	add_test(NAME api-test-mqtt-connack-props COMMAND lws-api-test-mqtt-connack-props)
	set_tests_properties(api-test-mqtt-connack-props PROPERTIES TIMEOUT 10)

	# Need extensive include directories for internal headers
	target_include_directories(${LOOP_TEST} PRIVATE
		${LWS_LIB_BUILD_INCLUDE_DIRS}
		${CMAKE_SOURCE_DIR}/lib
		${CMAKE_SOURCE_DIR}/lib/core
		${CMAKE_SOURCE_DIR}/lib/core-net
		${CMAKE_SOURCE_DIR}/lib/roles
		${CMAKE_SOURCE_DIR}/lib/roles/mqtt
		${CMAKE_SOURCE_DIR}/lib/roles/http
		${CMAKE_SOURCE_DIR}/lib/roles/ws
		${CMAKE_SOURCE_DIR}/lib/roles/h1
		${CMAKE_SOURCE_DIR}/lib/roles/h2
		${CMAKE_SOURCE_DIR}/lib/tls
		${CMAKE_SOURCE_DIR}/lib/plat/unix
		${CMAKE_SOURCE_DIR}/lib/event-libs
		${CMAKE_SOURCE_DIR}/lib/event-libs/poll
		${CMAKE_SOURCE_DIR}/lib/system
		${CMAKE_SOURCE_DIR}/lib/system/smd
		${CMAKE_SOURCE_DIR}/lib/misc
		${CMAKE_SOURCE_DIR}/lib/secure-streams
		${CMAKE_BINARY_DIR}
	)
	target_compile_definitions(${LOOP_TEST} PRIVATE LWS_BUILDING_STATIC)

	# always link the static lib: these tests use internal symbols
	target_link_libraries(${LOOP_TEST} websockets ${LIBWEBSOCKETS_DEP_LIBS})

	# CONNACK test needs same include directories for internal headers
	target_include_directories(${CONNACK_TEST} PRIVATE
		${LWS_LIB_BUILD_INCLUDE_DIRS}
		${CMAKE_SOURCE_DIR}/lib
		${CMAKE_SOURCE_DIR}/lib/core
		${CMAKE_SOURCE_DIR}/lib/core-net
		${CMAKE_SOURCE_DIR}/lib/roles
		${CMAKE_SOURCE_DIR}/lib/roles/mqtt
		${CMAKE_SOURCE_DIR}/lib/roles/http
		${CMAKE_SOURCE_DIR}/lib/roles/ws
		${CMAKE_SOURCE_DIR}/lib/roles/h1
		${CMAKE_SOURCE_DIR}/lib/roles/h2
		${CMAKE_SOURCE_DIR}/lib/tls
		${CMAKE_SOURCE_DIR}/lib/plat/unix
		${CMAKE_SOURCE_DIR}/lib/event-libs
		${CMAKE_SOURCE_DIR}/lib/event-libs/poll
		${CMAKE_SOURCE_DIR}/lib/system
		${CMAKE_SOURCE_DIR}/lib/system/smd
		${CMAKE_SOURCE_DIR}/lib/misc
		${CMAKE_SOURCE_DIR}/lib/secure-streams
		${CMAKE_BINARY_DIR}
	)
	target_compile_definitions(${CONNACK_TEST} PRIVATE LWS_BUILDING_STATIC)

	# always link the static lib: these tests use internal symbols
	target_link_libraries(${CONNACK_TEST} websockets ${LIBWEBSOCKETS_DEP_LIBS})

	# Control packets test - tests for PINGREQ, DISCONNECT, AUTH parsing
	set(CONTROL_TEST lws-api-test-mqtt-control-packets)
	add_executable(${CONTROL_TEST} test-control-packets.c)
	add_test(NAME api-test-mqtt-control-packets COMMAND lws-api-test-mqtt-control-packets)
	set_tests_properties(api-test-mqtt-control-packets PROPERTIES TIMEOUT 10)

	target_include_directories(${CONTROL_TEST} PRIVATE
		${LWS_LIB_BUILD_INCLUDE_DIRS}
		${CMAKE_SOURCE_DIR}/lib
		${CMAKE_SOURCE_DIR}/lib/core
		${CMAKE_SOURCE_DIR}/lib/core-net
		${CMAKE_SOURCE_DIR}/lib/roles
		${CMAKE_SOURCE_DIR}/lib/roles/mqtt
		${CMAKE_SOURCE_DIR}/lib/roles/http
		${CMAKE_SOURCE_DIR}/lib/roles/ws
		${CMAKE_SOURCE_DIR}/lib/roles/h1
		${CMAKE_SOURCE_DIR}/lib/roles/h2
		${CMAKE_SOURCE_DIR}/lib/tls
		${CMAKE_SOURCE_DIR}/lib/plat/unix
		${CMAKE_SOURCE_DIR}/lib/event-libs
		${CMAKE_SOURCE_DIR}/lib/event-libs/poll
		${CMAKE_SOURCE_DIR}/lib/system
		${CMAKE_SOURCE_DIR}/lib/system/smd
		${CMAKE_SOURCE_DIR}/lib/misc
		${CMAKE_SOURCE_DIR}/lib/secure-streams
		${CMAKE_BINARY_DIR}
	)
	target_compile_definitions(${CONTROL_TEST} PRIVATE LWS_BUILDING_STATIC)

	# always link the static lib: these tests use internal symbols
	target_link_libraries(${CONTROL_TEST} websockets ${LIBWEBSOCKETS_DEP_LIBS})

endif()
