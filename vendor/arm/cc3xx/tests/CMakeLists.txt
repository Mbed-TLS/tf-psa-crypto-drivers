#-------------------------------------------------------------------------------
# SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

# format_string is in cmake/utils.cmake in trusted-firmware-m, but provide it
# also here in case this is being used without the rest of TF-M's cmake tools
if(NOT COMMAND format_string)
    function(format_string output input size filler)
        string(LENGTH "${input}" length)

        if(length LESS size)
            math(EXPR pad "${size} - ${length}")
            string(REPEAT "${filler}" ${pad} padding)
            string(CONCAT result "${input}" "${padding}")
        else()
            set(result "${input}")
        endif()

        set(${output} "${result}" PARENT_SCOPE)
    endfunction()
endif()

set(CC3XX_TEST_TARGET_NAME ${CC3XX_TARGET_NAME}_tests)

set(AVAILABLE_CC3XX_TESTS
    TEST_CC3XX_HASH
    TEST_CC3XX_AES
    TEST_CC3XX_CHACHA
    TEST_CC3XX_PKA
    TEST_CC3XX_ECC
    TEST_CC3XX_ECDSA
    TEST_CC3XX_DRBG
    TEST_CC3XX_DPA
    TEST_CC3XX_RNG
)

set(ANY_CC3XX_TEST OFF)

# Check if any is enabled
foreach(test ${AVAILABLE_CC3XX_TESTS})
    if(${test})
        set(ANY_CC3XX_TEST ON)
        break()
    endif()
endforeach()

# If none enabled, enable them all because CC3XX_TEST is set at this point
if(NOT ANY_CC3XX_TEST)
    foreach(t ${AVAILABLE_CC3XX_TESTS})
        set(${t} ON CACHE BOOL "" FORCE)
    endforeach()
endif()

format_string(header "-------- ${CC3XX_TEST_TARGET_NAME} " 50 "-")
message(STATUS "\n-- ${header}")
message(STATUS "   CC3XX Hash Test                   ${TEST_CC3XX_HASH}")
message(STATUS "   CC3XX AES Test                    ${TEST_CC3XX_AES}")
message(STATUS "   CC3XX ChaCha Test                 ${TEST_CC3XX_CHACHA}")
message(STATUS "   CC3XX PKA Test                    ${TEST_CC3XX_PKA}")
message(STATUS "   CC3XX ECC Test                    ${TEST_CC3XX_ECC}")
message(STATUS "   CC3XX ECDSA Test                  ${TEST_CC3XX_ECDSA}")
message(STATUS "   CC3XX DRBG Test                   ${TEST_CC3XX_DRBG}")
message(STATUS "   CC3XX DPA Test                    ${TEST_CC3XX_DPA}")
message(STATUS "   CC3XX RNG Test                    ${TEST_CC3XX_RNG}")
format_string(footer "-" 50 "-")
message(STATUS "${footer}")

add_library(${CC3XX_TEST_TARGET_NAME} INTERFACE)

target_sources(${CC3XX_TEST_TARGET_NAME}
    INTERFACE
        ./src/cc3xx_test_main.c
        ./src/cc3xx_test_hash.c
        ./src/low_level_driver/test_lowlevel_hash.c
        ./src/cc3xx_test_aes.c
        ./src/low_level_driver/test_lowlevel_aes.c
        $<$<BOOL:${TEST_CC3XX_CHACHA}>:${CMAKE_CURRENT_SOURCE_DIR}/src/cc3xx_test_chacha.c>
        $<$<BOOL:${TEST_CC3XX_CHACHA}>:${CMAKE_CURRENT_SOURCE_DIR}/src/low_level_driver/test_lowlevel_chacha.c>
        ./src/cc3xx_test_pka.c
        ./src/cc3xx_test_ecc.c
        ./src/cc3xx_test_ecdsa.c
        $<$<BOOL:${TEST_CC3XX_DRBG}>:${CMAKE_CURRENT_SOURCE_DIR}/src/cc3xx_test_drbg.c>
        ./src/cc3xx_test_dpa.c
        ./src/cc3xx_test_rng.c
        ./src/cc3xx_test_utils.c
)

target_include_directories(${CC3XX_TEST_TARGET_NAME}
    INTERFACE
        ./include
        ./src
        ./src/low_level_driver
)

target_compile_definitions(${CC3XX_TEST_TARGET_NAME}
    INTERFACE
        TEST_CC3XX
        $<$<BOOL:${TEST_CC3XX_HASH}>:TEST_CC3XX_HASH>
        $<$<BOOL:${TEST_CC3XX_AES}>:TEST_CC3XX_AES>
        $<$<BOOL:${TEST_CC3XX_CHACHA}>:TEST_CC3XX_CHACHA>
        $<$<BOOL:${TEST_CC3XX_PKA}>:TEST_CC3XX_PKA>
        $<$<BOOL:${TEST_CC3XX_ECC}>:TEST_CC3XX_ECC>
        $<$<BOOL:${TEST_CC3XX_ECDSA}>:TEST_CC3XX_ECDSA>
        $<$<BOOL:${TEST_CC3XX_DRBG}>:TEST_CC3XX_DRBG>
        $<$<BOOL:${TEST_CC3XX_DPA}>:TEST_CC3XX_DPA>
        $<$<BOOL:${TEST_CC3XX_RNG}>:TEST_CC3XX_RNG>
)

target_link_libraries(${CC3XX_TEST_TARGET_NAME}
    INTERFACE
        ${CC3XX_TARGET_NAME}
)
