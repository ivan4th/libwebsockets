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

endif()
