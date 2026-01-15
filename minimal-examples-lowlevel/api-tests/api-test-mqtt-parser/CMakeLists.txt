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

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

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

	if (websockets_shared)
		target_link_libraries(${LOOP_TEST} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${LOOP_TEST} websockets_shared)
	else()
		target_link_libraries(${LOOP_TEST} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

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

	if (websockets_shared)
		target_link_libraries(${CONNACK_TEST} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${CONNACK_TEST} websockets_shared)
	else()
		target_link_libraries(${CONNACK_TEST} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# Unhandled packets test - tests for PINGREQ, DISCONNECT, AUTH parsing
	set(UNHANDLED_TEST lws-api-test-mqtt-unhandled-packets)
	add_executable(${UNHANDLED_TEST} test-unhandled-packets.c)
	add_test(NAME api-test-mqtt-unhandled-packets COMMAND lws-api-test-mqtt-unhandled-packets)
	set_tests_properties(api-test-mqtt-unhandled-packets PROPERTIES TIMEOUT 10)

	target_include_directories(${UNHANDLED_TEST} PRIVATE
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
	target_compile_definitions(${UNHANDLED_TEST} PRIVATE LWS_BUILDING_STATIC)

	if (websockets_shared)
		target_link_libraries(${UNHANDLED_TEST} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${UNHANDLED_TEST} websockets_shared)
	else()
		target_link_libraries(${UNHANDLED_TEST} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
