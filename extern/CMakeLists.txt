include(FetchContent)

FetchContent_Declare(
  opus
  SOURCE_DIR opus
  GIT_REPOSITORY https://gitlab.xiph.org/xiph/opus
  GIT_TAG e85ed7726db5d677c9c0677298ea0cb9c65bdd23 # v1.3.1
)

FetchContent_Declare(
  portaudio
  SOURCE_DIR portaudio
  GIT_REPOSITORY https://github.com/PortAudio/portaudio
  GIT_TAG 147dd722548358763a8b649b3e4b41dfffbcfbb6 # v19.7.0
)

FetchContent_MakeAvailable(opus portaudio)

