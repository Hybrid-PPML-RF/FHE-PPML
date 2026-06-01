cmake_minimum_required (VERSION 3.5.1)

### To use gcc/g++ on a Macintosh, you must set the Compilers
### here, not inside the project
##if(APPLE)
##       set(CMAKE_C_COMPILER "/usr/local/bin/gcc-7")
##       set(CMAKE_CXX_COMPILER "/usr/local/bin/g++-7")
##endif()
### TODO: for now, we use CLang for Mac
###
### In order to create PALISADE's static libraries you should enable
### the BUILD_STATIC option. For that, you run "cmake .. -DBUILD_STATIC=ON".
### After having your link completed you will find static libs
### with the suffix "_static" in ./build/libs/.
### Examples: PALISADEpke_static.a, PALISADEcore_static.a, etc.
### After you run "make install" in your build directory, you can build your custom application.
### If you need your application to be linked statically, then run "cmake .. -DBUILD_STATIC=ON"

project(demo CXX)
set(CMAKE_CXX_STANDARD 11)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

### find_package(Palisade REQUIRED)
find_package(SEAL REQUIRED)

### set( CMAKE_CXX_FLAGS ${PALISADE_CXX_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
### include_directories( ${PALISADE_INCLUDE} )
### include_directories( ${PALISADE_INCLUDE}/third-party/include )
### include_directories( ${PALISADE_INCLUDE}/core )
### include_directories( ${PALISADE_INCLUDE}/pke )
### include_directories( include/palisade/core )
### include_directories( include/palisade )

### link_directories( ${PALISADE_LIBDIR} )
### link_directories( ${OPENMP_LIBRARIES} )
### if(BUILD_STATIC)
###     set( CMAKE_EXE_LINKER_FLAGS "${PALISADE_EXE_LINKER_FLAGS} -static")
###     link_libraries( ${PALISADE_STATIC_LIBRARIES} )
### else()
###     set( CMAKE_EXE_LINKER_FLAGS ${PALISADE_EXE_LINKER_FLAGS} )
###     link_libraries( ${PALISADE_SHARED_LIBRARIES} )
### endif()

add_executable( ppml main.cpp )
target_link_libraries(ppml SEAL::seal_shared /opt/homebrew/lib/libntl.dylib m /opt/homebrew/lib/libgmp.dylib)

add_executable( benchmark benchmark.cpp )
target_link_libraries(benchmark SEAL::seal_shared)

add_executable( ppml_matvec main_matvec.cpp )
target_link_libraries(ppml_matvec SEAL::seal_shared /opt/homebrew/lib/libntl.dylib m /opt/homebrew/lib/libgmp.dylib)

add_executable( test_bgv_chain test_bgv_chain.cpp )
target_link_libraries(test_bgv_chain SEAL::seal_shared)

add_executable( test_protocol_64bit test_protocol_64bit.cpp )
target_link_libraries(test_protocol_64bit SEAL::seal_shared)

add_executable( extract_ops main_extract_ops.cpp )
target_link_libraries(extract_ops SEAL::seal_shared /opt/homebrew/lib/libntl.dylib m /opt/homebrew/lib/libgmp.dylib)

add_executable( extract_ops_short main_extract_ops_short.cpp )
target_link_libraries(extract_ops_short SEAL::seal_shared /opt/homebrew/lib/libntl.dylib m /opt/homebrew/lib/libgmp.dylib)
