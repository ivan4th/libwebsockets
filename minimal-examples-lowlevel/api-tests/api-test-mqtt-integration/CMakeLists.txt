project(lws-api-test-mqtt-integration C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-mqtt-integration)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	# Test requires mosquitto broker running on localhost:31883
	# The test will skip gracefully if the broker is not available
	add_test(NAME api-test-mqtt-integration COMMAND ${SAMP} -p 31883)
	set_tests_properties(api-test-mqtt-integration PROPERTIES
		TIMEOUT 30
		LABELS "mqtt;integration"
	)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()

# Copy mosquitto config for reference
configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/mosquitto-test.conf
	${CMAKE_CURRENT_BINARY_DIR}/mosquitto-test.conf
	COPYONLY
)
