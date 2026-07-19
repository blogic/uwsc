cmake_minimum_required(VERSION 3.13)

PROJECT(uwsc C)
ADD_DEFINITIONS(-Os -Wall -Werror --std=gnu99 -ffunction-sections -fwrapv -D_GNU_SOURCE)

IF(CMAKE_C_COMPILER_VERSION VERSION_GREATER 6)
	ADD_DEFINITIONS(-Wextra -Werror=implicit-function-declaration)
	ADD_DEFINITIONS(-Wformat -Werror=format-security -Werror=format-nonliteral)
ENDIF()
ADD_DEFINITIONS(-Wmissing-declarations -Wno-error=unused-variable -Wno-unused-parameter)

INCLUDE_DIRECTORIES(include)

IF(DEBUG)
  ADD_DEFINITIONS(-DDEBUG -g3 -O0)
ELSE()
  ADD_DEFINITIONS(-DNDEBUG)
ENDIF()

FIND_LIBRARY(ubox NAMES ubox)
FIND_LIBRARY(ucode NAMES ucode)
FIND_LIBRARY(ssl NAMES ssl)
FIND_LIBRARY(crypto NAMES crypto)

FOREACH(lib ubox ucode ssl crypto)
	IF(NOT ${lib})
		MESSAGE(FATAL_ERROR "lib${lib} not found")
	ENDIF()
ENDFOREACH()

ADD_LIBRARY(uwsc MODULE
	ucode-client.c
	client-lib.c
	client-url.c
	client-connect.c
	client-ws.c
	client-http.c
	client-io.c
	client-send-buffer.c
	client-ssl.c
	teeny-sha1.c
	log.c
)
TARGET_LINK_LIBRARIES(uwsc ${ubox} ${ucode} ${ssl} ${crypto})
TARGET_COMPILE_OPTIONS(uwsc PRIVATE -fPIC)
SET_TARGET_PROPERTIES(uwsc PROPERTIES PREFIX "")

INSTALL(TARGETS uwsc
	LIBRARY DESTINATION lib/ucode)
