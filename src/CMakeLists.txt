project(tpm20)

set(
    sources
    random.c
    init.c
    sign.c
    clear.c
    pub.c
)

set(
    tools_sources
    parg.c
    utils.c
    demo.c
)

set(
    python_sources
    pytpm20.c
)

find_library(crypto.a libcrypto.a)
find_library(tss2-esys.a libtss2-esys.a)
find_library(tss2-rc.a libtss2-rc.a)
find_library(tss2-tctildr.a libtss2-tctildr.a)

find_program (PYTHON_CONFIG "python-config")
option (CORSIKA_IGNORE_PYTHON_CONFIG "Do not try to use python-config" FALSE)
if (PYTHON_CONFIG AND NOT CORSIKA_IGNORE_PYTHON_CONFIG)
  message(STATUS "Python config found at ${PYTHON_CONFIG}. Using whatever it says.")
  execute_process(COMMAND "${PYTHON_CONFIG}" "--ldflags" RESULT_VARIABLE _lib_result_ OUTPUT_VARIABLE _output_ ERROR_VARIABLE _error_)
  if (_lib_result_ EQUAL 0)
    string (STRIP "${_output_}" _a_)
    string (REPLACE "-l" "" _a_ ${_a_})
    string (REPLACE "-L" "" _a_ ${_a_})
    string (REPLACE " " ";" _a_ ${_a_})
    list (GET _a_ 0 _dir_)
    list (GET _a_ 1 _lib_)
    find_library (PYTHON_LIBRARY ${_lib_} HINTS ${_dir_} NO_DEFAULT_PATH DOC "Python library given by python-config.")
  else ()
    message (WARNING "python-config error (${_lib_result_}):\n- Output: ${_output_}\n- Error: ${_error_}")
  endif ()
  execute_process(COMMAND "${PYTHON_CONFIG}" "--includes" RESULT_VARIABLE _inc_result_ OUTPUT_VARIABLE _output_ ERROR_VARIABLE _error_)
  if (_inc_result_ EQUAL 0)
    string (STRIP "${_output_}" _a_)
    string (REPLACE "-I" "" _a_ ${_a_})
    string (REPLACE " " ";" _a_ ${_a_})
    list (GET _a_ 0 _dir_)
    set (PYTHON_INCLUDE_DIR "${_dir_}" CACHE STRING "Python includes directory given by python-config." FORCE)
  else ()
    message (WARNING "python-config error (${_inc_result_}):\n- Output: ${_output_}\n- Error: ${_error_}")
  endif ()
  if (NOT _lib_result_ EQUAL 0 OR NOT _lib_result_ EQUAL 0)
    message (SEND_ERROR "python-config error. See above.")
  endif()
endif ()

find_package(PythonInterp)


set(cflags
    -std=c99 
    -Wall
    -Wextra
    -Werror
    -ansi
    -fPIC
    # -pedantic
    -Wformat=2
    -Wshift-negative-value
    -Wstrict-prototypes
    -Wstrict-aliasing 
    -Wunreachable-code 
    -Wno-unused-parameter
)

set(libraries
    dl
    rt
    pthread
    crypto
)

set(tss_libraries
    tss2-esys
    tss2-rc
    tss2-tctildr
)

set(tss_libraries.a
    tss2-esys.a
    tss2-mu.a
    tss2-rc.a
    tss2-sys.a
    tss2-tcti-device.a
    tss2-tctildr.a
)

include_directories(
    /usr/local/include/
    include
    src
    ${PYTHON_INCLUDE_DIR}
    )

add_library(tpm20 SHARED ${sources})
target_compile_options(tpm20 PRIVATE ${cflags})
target_link_libraries(tpm20 ${tss_libraries} ${libraries})

add_library(tpm20_a STATIC ${sources})
target_compile_options(tpm20_a PRIVATE ${cflags})
target_link_libraries(tpm20_a ${tss_libraries.a} ${libraries})

add_executable(tools ${tools_sources})
target_compile_options(tools PRIVATE ${cflags})
target_link_libraries(tools tpm20 ${tss_libraries} ${libraries})

add_library(python_ext SHARED ${python_sources})
set_target_properties(
    python_ext 
    PROPERTIES
        PREFIX ""
        OUTPUT_NAME "_tpm20"
        LINKER_LANGUAGE C
)
target_compile_options(tools PRIVATE ${python_cflags} ${cflags})
target_link_libraries(python_ext tpm20_a ${libraries} ${PYTHON_LIBRARIES})

# add_executable(tools_static ${tools_sources})
# target_compile_options(tools_static PRIVATE "-static" ${cflags})
# target_link_libraries(tools_static tpm20_a ${libraries})
