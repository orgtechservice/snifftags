find_path(PCAP_ROOT_DIR
        NAMES include/pcap.h
        )

find_path(PCAP_INCLUDE_DIR
        NAMES pcap.h
        HINTS ${PCAP_ROOT_DIR}/include
        )

find_library(PCAP_LIBRARY
        NAMES pcap
        HINTS ${PCAP_ROOT_DIR}/lib
        )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG
        PCAP_LIBRARY
        PCAP_INCLUDE_DIR
        )

include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
check_c_source_compiles("int main() { return 0; }" PCAP_LINKS_SOLO)
set(CMAKE_REQUIRED_LIBRARIES)

# check if linking against libpcap also needs to link against a thread library
if (NOT PCAP_LINKS_SOLO)
    find_package(Threads)
    if (THREADS_FOUND)
        set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
        check_c_source_compiles("int main() { return 0; }" PCAP_NEEDS_THREADS)
        set(CMAKE_REQUIRED_LIBRARIES)
    endif ()
    if (THREADS_FOUND AND PCAP_NEEDS_THREADS)
        set(_tmp ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})
        list(REMOVE_DUPLICATES _tmp)
        set(PCAP_LIBRARY ${_tmp}
                CACHE STRING "Libraries needed to link against libpcap" FORCE)
    else ()
        message(FATAL_ERROR "Couldn't determine how to link against libpcap")
    endif ()
endif ()

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})
check_function_exists(pcap_get_pfring_id HAVE_PF_RING)
set(CMAKE_REQUIRED_LIBRARIES)

mark_as_advanced(
        PCAP_ROOT_DIR
        PCAP_INCLUDE_DIR
        PCAP_LIBRARY
)