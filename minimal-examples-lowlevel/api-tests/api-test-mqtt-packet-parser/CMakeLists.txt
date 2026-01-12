project(lws-api-test-mqtt-packet-parser C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-mqtt-packet-parser)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-mqtt-packet-parser COMMAND lws-api-test-mqtt-packet-parser)

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

endif()
