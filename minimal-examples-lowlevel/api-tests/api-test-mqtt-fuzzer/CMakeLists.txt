project(lws-api-test-mqtt-fuzzer C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements AND LWS_WITH_FUZZER)

	# Option to control sanitizers (default ON for bug detection)
	option(LWS_FUZZER_WITH_ASAN "Enable AddressSanitizer for fuzzers" ON)
	option(LWS_FUZZER_WITH_UBSAN "Enable UndefinedBehaviorSanitizer for fuzzers" ON)

	# Build sanitizer flags based on options
	set(FUZZER_SANITIZERS "fuzzer")
	if (LWS_FUZZER_WITH_ASAN)
		set(FUZZER_SANITIZERS "${FUZZER_SANITIZERS},address")
	endif()
	if (LWS_FUZZER_WITH_UBSAN)
		set(FUZZER_SANITIZERS "${FUZZER_SANITIZERS},undefined")
	endif()

	message(STATUS "MQTT Fuzzer sanitizers: ${FUZZER_SANITIZERS}")

	# VBI-specific fuzzer
	set(VBI_FUZZ lws-mqtt-vbi-fuzzer)
	add_executable(${VBI_FUZZ} mqtt-vbi-fuzz.c)
	target_compile_options(${VBI_FUZZ} PRIVATE
		-fsanitize=${FUZZER_SANITIZERS}
		-fno-omit-frame-pointer
		-g
	)
	target_link_options(${VBI_FUZZ} PRIVATE
		-fsanitize=${FUZZER_SANITIZERS}
	)
	target_include_directories(${VBI_FUZZ} PRIVATE
		${LWS_LIB_BUILD_INCLUDE_DIRS}
		${CMAKE_SOURCE_DIR}/lib/roles/mqtt
	)
	if (websockets_shared)
		target_link_libraries(${VBI_FUZZ} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${VBI_FUZZ} websockets_shared)
	else()
		target_link_libraries(${VBI_FUZZ} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# All parser primitives fuzzer
	set(PARSER_FUZZ lws-mqtt-parser-fuzzer)
	add_executable(${PARSER_FUZZ} mqtt-parser-fuzz.c)
	target_compile_options(${PARSER_FUZZ} PRIVATE
		-fsanitize=${FUZZER_SANITIZERS}
		-fno-omit-frame-pointer
		-g
	)
	target_link_options(${PARSER_FUZZ} PRIVATE
		-fsanitize=${FUZZER_SANITIZERS}
	)
	target_include_directories(${PARSER_FUZZ} PRIVATE
		${LWS_LIB_BUILD_INCLUDE_DIRS}
		${CMAKE_SOURCE_DIR}/lib/roles/mqtt
	)
	if (websockets_shared)
		target_link_libraries(${PARSER_FUZZ} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PARSER_FUZZ} websockets_shared)
	else()
		target_link_libraries(${PARSER_FUZZ} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# Full MQTT packet fuzzer (uses loopback server)
	set(PKT_FUZZ lws-mqtt-packet-fuzzer)
	add_executable(${PKT_FUZZ} mqtt-packet-fuzz.c)
	target_compile_options(${PKT_FUZZ} PRIVATE
		-fsanitize=${FUZZER_SANITIZERS}
		-fno-omit-frame-pointer
		-g
	)
	target_link_options(${PKT_FUZZ} PRIVATE
		-fsanitize=${FUZZER_SANITIZERS}
	)
	target_include_directories(${PKT_FUZZ} PRIVATE
		${LWS_LIB_BUILD_INCLUDE_DIRS}
		${CMAKE_SOURCE_DIR}/lib/roles/mqtt
	)
	if (websockets_shared)
		target_link_libraries(${PKT_FUZZ} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS} pthread)
		add_dependencies(${PKT_FUZZ} websockets_shared)
	else()
		target_link_libraries(${PKT_FUZZ} websockets ${LIBWEBSOCKETS_DEP_LIBS} pthread)
	endif()

	# Direct parser fuzzer - calls _lws_mqtt_rx_parser() directly
	# for high-speed fuzzing without network overhead
	set(DIRECT_FUZZ lws-mqtt-direct-fuzzer)
	add_executable(${DIRECT_FUZZ} mqtt-direct-fuzz.c)
	target_compile_options(${DIRECT_FUZZ} PRIVATE
		-fsanitize=${FUZZER_SANITIZERS}
		-fno-omit-frame-pointer
		-g
	)
	target_link_options(${DIRECT_FUZZ} PRIVATE
		-fsanitize=${FUZZER_SANITIZERS}
	)
	# Direct fuzzer needs internal headers - add all lib directories
	target_include_directories(${DIRECT_FUZZ} PRIVATE
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
	target_compile_definitions(${DIRECT_FUZZ} PRIVATE LWS_BUILDING_STATIC)
	if (websockets_shared)
		target_link_libraries(${DIRECT_FUZZ} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${DIRECT_FUZZ} websockets_shared)
	else()
		target_link_libraries(${DIRECT_FUZZ} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
