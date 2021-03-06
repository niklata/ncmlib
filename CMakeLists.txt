cmake_minimum_required(VERSION 3.5)
####################################

# Computes the realtionship between two version strings.  A version
# string is a number delineated by '.'s such as 1.3.2 and 0.99.9.1.
# You can feed version strings with different number of dot versions,
# and the shorter version number will be padded with zeros: 9.2 <
# 9.2.1 will actually compare 9.2.0 < 9.2.1.
#
# Input: a_in - value, not variable
#        b_in - value, not variable
#        result_out - variable with value:
#                         -1 : a_in <  b_in
#                          0 : a_in == b_in
#                          1 : a_in >  b_in
#
# Written by James Bigler.
MACRO(COMPARE_VERSION_STRINGS a_in b_in result_out)
  # Since SEPARATE_ARGUMENTS using ' ' as the separation token,
  # replace '.' with ' ' to allow easy tokenization of the string.
  STRING(REPLACE "." " " a ${a_in})
  STRING(REPLACE "." " " b ${b_in})
  SEPARATE_ARGUMENTS(a)
  SEPARATE_ARGUMENTS(b)

  # Check the size of each list to see if they are equal.
  LIST(LENGTH a a_length)
  LIST(LENGTH b b_length)

  # Pad the shorter list with zeros.

  # Note that range needs to be one less than the length as the for
  # loop is inclusive (silly CMake).
  IF(a_length LESS b_length)
    # a is shorter
    SET(shorter a)
    MATH(EXPR range "${b_length} - 1")
    MATH(EXPR pad_range "${b_length} - ${a_length} - 1")
  ELSE(a_length LESS b_length)
    # b is shorter
    SET(shorter b)
    MATH(EXPR range "${a_length} - 1")
    MATH(EXPR pad_range "${a_length} - ${b_length} - 1")
  ENDIF(a_length LESS b_length)

  # PAD out if we need to
  IF(NOT pad_range LESS 0)
    FOREACH(pad RANGE ${pad_range})
      # Since shorter is an alias for b, we need to get to it by by dereferencing shorter.
      LIST(APPEND ${shorter} 0)
    ENDFOREACH(pad RANGE ${pad_range})
  ENDIF(NOT pad_range LESS 0)

  SET(result 0)
  FOREACH(index RANGE ${range})
    IF(result EQUAL 0)
      # Only continue to compare things as long as they are equal
      LIST(GET a ${index} a_version)
      LIST(GET b ${index} b_version)
      # LESS
      IF(a_version LESS b_version)
        SET(result -1)
      ENDIF(a_version LESS b_version)
      # GREATER
      IF(a_version GREATER b_version)
        SET(result 1)
      ENDIF(a_version GREATER b_version)
    ENDIF(result EQUAL 0)
  ENDFOREACH(index)

  # Copy out the return result
  SET(${result_out} ${result})
ENDMACRO(COMPARE_VERSION_STRINGS)

####################################

if (WIN32)
  set(OSNAME "Win32")
else()
execute_process(
  COMMAND uname
  COMMAND tr "\n" " "
  COMMAND sed "s/ //"
  OUTPUT_VARIABLE OSNAME
  )
endif()

if (${OSNAME} STREQUAL "Linux")
  execute_process(
    COMMAND uname -r
    COMMAND tr "\n" " "
    COMMAND sed "s/ //"
    OUTPUT_VARIABLE LINUX_VERSION
    )
  COMPARE_VERSION_STRINGS(${LINUX_VERSION} "3.5" LINUX_HAS_NO_NEW_PRIVS)
  if (NOT ${LINUX_HAS_NO_NEW_PRIVS} LESS 0)
    message("ncmlib: Enabling use of prctl SET_NO_NEW_PRIVS.")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNK_USE_NO_NEW_PRIVS")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNK_USE_NO_NEW_PRIVS")
  else()
    message("ncmlib: prctl SET_NO_NEW_PRIVS not available.")
  endif()
  COMPARE_VERSION_STRINGS(${LINUX_VERSION} "3.17" LINUX_HAS_GETRANDOM_SYSCALL)
  if (NOT ${LINUX_HAS_GETRANDOM_SYSCALL} LESS 0)
    message("ncmlib: Enabling use of getrandom syscall.")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNK_USE_GETRANDOM_SYSCALL")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNK_USE_GETRANDOM_SYSCALL")
  else()
    message("ncmlib: getrandom syscall not available.")
  endif()
endif()

if ("$ENV{CROSSCOMPILE_MACHINENAME}" STREQUAL "")
  execute_process(
    COMMAND uname -m
    COMMAND tr "\n" " "
    COMMAND sed "s/ //"
    OUTPUT_VARIABLE MACHINENAME
    )
else()
  message("skipped machine detection; MACHINENAME is '$ENV{CROSSCOMPILE_MACHINENAME}'")
  set(MACHINENAME $ENV{CROSSCOMPILE_MACHINENAME})
endif()

#if (${MACHINENAME} STREQUAL "x86_64")
#  message("Detected that the current host is x86_64.  Enabling x64 asm.")
#  file(GLOB ASM_OBJS "asm/x64-sysv/*.o")
#elseif ((${MACHINENAME} STREQUAL "i686") OR (${MACHINENAME} STREQUAL "i586") OR
#        (${MACHINENAME} STREQUAL "i486") OR (${MACHINENAME} STREQUAL "i386"))
#  message("Detected that the current host is x86.  Enabling x86 asm.")
#  file(GLOB ASM_OBJS "asm/x86-sysv/*.o")
#else()
#  message("Host machine type does not have optimized asm code.")
#  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNK_NO_ASM")
#  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNK_NO_ASM")
#endif()

include_directories("${CMAKE_SOURCE_DIR}")
file(GLOB NCMLIB_SRCS "*.c")

#add_library(ncmlib ${NCMLIB_SRCS} ${ASM_OBJS})
add_library(ncmlib ${NCMLIB_SRCS})

