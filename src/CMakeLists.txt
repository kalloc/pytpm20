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

find_library(crypto.a libcrypto.a)
find_library(tss2-esys.a libtss2-esys.a)
find_library(tss2-rc.a libtss2-rc.a)
find_library(tss2-tctildr.a libtss2-tctildr.a)

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

# add_executable(tools_static ${tools_sources})
# target_compile_options(tools_static PRIVATE "-static" ${cflags})
# target_link_libraries(tools_static tpm20_a ${libraries})
