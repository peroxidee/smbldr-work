# CMakeList.txt : CMake project for smbldr-work, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (smbldr-work "smbldr-work.c" "smbldr-work.h")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET smbldr-work PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
