add_executable (smbldr-work "smbldr-work.c" "smbldr-work.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET smbldr-work PROPERTY CXX_STANDARD 20)
endif()
