set(DMOD_DMR_PATH ${CMAKE_CURRENT_SOURCE_DIR}/secrets.dmr)

dmod_add_executable(secrets ${DMOD_MODULE_VERSION}
    main.c
)

# dmsecrets (this repository): the API
target_link_libraries(secrets dmsecrets_if)
