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

set(cflags
    -Wall
    -fPIC
    -Wextra
    -Wstrict-prototypes
    -Wno-unused-parameter
)

set(libraries
    dl
    rt
    crypto
    tss2-esys
    tss2-rc
    tss2-tctildr
)

include_directories(
    /usr/local/include/
    include
    src
    )

add_library(tpm20 SHARED ${sources})
target_compile_options(tpm20 PRIVATE ${cflags})
target_link_libraries(tpm20 ${libraries})

add_library(tpm20_a STATIC ${sources})
target_compile_options(tpm20_a PRIVATE ${cflags})
target_link_libraries(tpm20_a ${libraries})

target_include_directories (tpm20 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(demo ${tools_sources})
target_link_libraries(demo tpm20 ${libraries})
