include(FetchContent)

FetchContent_Declare(
  opus
  SOURCE_DIR opus
  GIT_REPOSITORY https://gitlab.xiph.org/xiph/opus.git
  GIT_TAG e85ed7726db5d677c9c0677298ea0cb9c65bdd23 # v1.3.1
)
FetchContent_MakeAvailable(opus)

