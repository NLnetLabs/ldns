# Travis Testing

LDNS 1.7.1 and above leverage Travis CI to increase coverage of compilers and platforms. Compilers include Clang and GCC; while platforms include Android, Linux, and OS X on AMD64, Aarch64, PowerPC and s390x hardware.

Android is tested on armv7a, aarch64, x86 and x86_64. The Android recipes build and install OpenSSL and then builds and installs LDNS. The testing is tailored for Android NDK-r19 and above, and includes NDK-r20 and NDK-r21. Mips and Mips64 are not tested because they are no longer supported under current NDKs.

The LDNS Travis configuration file `.travis.yml` does not use top-level keys like `os:` and `compiler:` so there is no matrix expansion. Instead LDNS specifies the exact job to run under the `jobs:` and `include:` keys.

## Typical recipe

A typical recipe tests Clang and GCC on various hardware. The hardware includes AMD64, Aarch64, PowerPC and s390x. PowerPC is a little-endian platform, and s390x is a big-endian platform. There are pairs of recipes that are similar to the following.

```
- os: linux
  name: GCC on Linux, Aarch64
  compiler: gcc
  arch: arm64
  dist: bionic
- os: linux
  name: Clang on Linux, Aarch64
  compiler: clang
  arch: arm64
  dist: bionic
```

OS X provides a single recipe to test Clang. GCC is not tested because GCC is an alias for Clang.

## Sanitizer builds

Two sanitizer builds are tested using Clang and GCC, for a total of four builds. The first sanitizer is Undefined Behavior sanitizer (UBsan), and the second is Address sanitizer (Asan). The sanitizers are only run on AMD64 hardware. Note the environment includes `UBSAN=yes` or `ASAN=yes` for the sanitizer builds.

The recipes are similar to the following.

```
- os: linux
  name: UBsan, GCC on Linux, Amd64
  compiler: gcc
  arch: amd64
  dist: bionic
  env: UBSAN=yes
- os: linux
  name: UBsan, Clang on Linux, Amd64
  compiler: clang
  arch: amd64
  dist: bionic
  env: UBSAN=yes
```

When the Travis script encounters a sanitizer it uses different `CFLAGS` and configuration string.

```
if [ "$UBSAN" = "yes" ]; then
  export CFLAGS="-DNDEBUG -g2 -O3 -fsanitize=undefined -fno-sanitize-recover"
  bash test/test_ci.sh
elif [ "$ASAN" = "yes" ]; then
  export CFLAGS="-DNDEBUG -g2 -O3 -fsanitize=address"
  bash test/test_ci.sh
...
```

## Android builds

Travis tests Android builds for the armv7a, aarch64, x86 and x86_64 architectures. The builds are trickier than other builds for several reasons. The testing requires installation of the Android NDK and SDK, it requires a cross-compile, and requires OpenSSL prerequisites. The Android cross-compiles also require care to set the Autotools triplet, the OpenSSL triplet, the toolchain path, the tool variables, and the sysroot. The discussion below detail the steps of the Android recipes.

### Tool installation

The first step installs tools needed for OpenSSL and LDNS. This step is handled in by the script `contrib/android/install_tools.sh`, and it is run by Travis in the `before_script` in the lifecycle. The tools include curl, wget, tar, zip, unzip and java.

If you are working from a developer machine you probably already have the necessary tools installed.

### ANDROID_NDK_ROOT

The step step for Android is to set the environmental variables `ANDROID_NDK_ROOT` and `ANDROID_SDK_ROOT`. This is an important step because the NDK and SDK use the variables internally to locate their own tools. Also see [Recommended NDK Directory?](https://groups.google.com/forum/#!topic/android-ndk/qZjhOaynHXc) on the android-ndk mailing list. (Many folks botch this step, and use incorrect variables like `ANDROID_NDK_HOME` or `ANDROID_SDK_HOME`).

LDNS exports the variables in the Travis configuration script for the Android recipe:

```
export ANDROID_SDK_ROOT="$HOME/android-sdk"
export ANDROID_NDK_ROOT="$HOME/android-ndk"
```

### NDK installation

The third step installs the NDK and SDK. This step is handled in by the script `contrib/android/install_ndk.sh`. The script uses `ANDROID_NDK_ROOT` and `ANDROID_SDK_ROOT` to place the NDK and SDK in the `$HOME` directory.

If you are working from a developer machine you probably already have a NDK and SDK installed.

### Android environment

The fourth step sets the Android cross-compile environment using the script `contrib/android/setenv_android.sh`. The script is `sourced` so the variables in the script are available to the calling shell. The script sets variables like `CC`, `CXX`, `AS` and `AR`; sets `CFLAGS` and `CXXFLAGS`; sets a `sysroot` so Android headers and libraries are found; and adds the path to the toolchain to `PATH`.

`contrib/android/setenv_android.sh` knows which toolchain and architecture to select by inspecting environmental variables set by Travis for the job. In particular, the variables `ANDROID_CPU` and `ANDROID_API` tell `contrib/android/setenv_android.sh` what tools and libraries to select. For example, below is part of the Aarch64 recipe.

```
- os: linux
  name: Android aarch64, Linux, Amd64
  compiler: clang
  arch: amd64
  dist: bionic
  env:
    - ANDROID=yes
    - AUTOTOOLS_HOST=aarch64-linux-android
    - OPENSSL_HOST=android-arm64
    - ANDROID_CPU=aarch64
    - ANDROID_API=23
```

The `contrib/android/setenv_android.sh` script specifies the tools in a `case` statement like the following. There is a case for each of the architectures armv7a, aarch64, x86 and x86_64.

```
armv8a|aarch64|arm64|arm64-v8a)
  CC="aarch64-linux-android$ANDROID_API-clang"
  CXX="aarch64-linux-android$ANDROID_API-clang++"
  LD="aarch64-linux-android-ld"
  AS="aarch64-linux-android-as"
  AR="aarch64-linux-android-ar"
  RANLIB="aarch64-linux-android-ranlib"
  STRIP="aarch64-linux-android-strip"

  CFLAGS="-funwind-tables -fexceptions"
  CXXFLAGS="-funwind-tables -fexceptions -frtti"
```

### OpenSSL

The fifth step builds OpenSSL. OpenSSL are built for Android using the script `contrib/android/install_openssl.sh`. The scripts download, configure and install the latest release version of the libraries. The libraries are configured with `--prefix="$ANDROID_PREFIX"` so the headers are placed in `$ANDROID_PREFIX/include` directory, and the libraries are placed in the `$ANDROID_PREFIX/lib` directory.

`ANDROID_PREFIX` is the value `$HOME/android$ANDROID_API-$ANDROID_CPU`. The libraries will be installed in `$HOME/android23-armv7a`, `$HOME/android23-aarch64`, etc. For Autotools projects, the appropriate `PKG_CONFIG_PATH` is exported. `PKG_CONFIG_PATH` is the userland equivalent to sysroot, and allows Autotools to find non-system library's headers and libraries for an architecture. Typical `PKG_CONFIG_PATH` are `$HOME/android23-armv7a/lib/pkgconfig` and `$HOME/android23-aarch64/lib/pkgconfig`.

OpenSSL also uses a custom configuration file called `15-android.conf`. It is a copy of the OpenSSL's project file and located at `contrib/android/15-android.conf`. The LDNS version is copied to the OpenSSL source files after unpacking the OpenSSL distribution. The LDNS version has legacy NDK support removed and some other fixes, like `ANDROID_NDK_ROOT` awareness. The changes mean LDNS's `15-android.conf` will only work with LDNS, with NDK-r19 and above, and a properly set environment.

OpenSSL is configured with `no-engine`. If you want to include OpenSSL engines then edit `contrib/android/install_openssl.sh` and remove the config option.

### Android build

Finally, once OpenSSL are built, then the Travis script configures and builds LDNS. The recipe looks as follows.

```
elif [ "$ANDROID" = "yes" ]; then
  export AUTOTOOLS_BUILD="$(./config.guess)"
  export PKG_CONFIG_PATH="$ANDROID_PREFIX/lib/pkgconfig"
  ./contrib/android/install_ndk.sh
  source ./contrib/android/setenv_android.sh
  ./contrib/android/install_openssl.sh
  ./contrib/android/bootstrap_ldns.sh
  ./configure \
    --build="$AUTOTOOLS_BUILD" --host="$AUTOTOOLS_HOST" \
    --prefix="$ANDROID_PREFIX" \
    --with-ssl="$ANDROID_PREFIX" --disable-gost \
    --with-drill --with-examples
  make -j 2
  make install
```

Travis only smoke tests an Android build using a compile and link. The self tests are not run. TODO: figure out how to fire up an emulator, push the tests to the device and run them.

### Android flags

`contrib/android/setenv_android.sh` uses specific flags for `CFLAGS` and `CXXFLAGS`. They are taken from `ndk-build`, so we consider them the official flag set. It is important to use the same flags across projects to avoid subtle problems due to mixing and matching different flags.

`CXXFLAGS` includes `-fexceptions` and `-frtti` because exceptions and runtime type info are disabled by default. `CFLAGS` include `-funwind-tables` and `-fexceptions` to ensure C++ exceptions pass through C code, if needed. Also see `docs/CPLUSPLUS-SUPPORT.html` in the NDK docs.

To inspect the flags used by `ndk-build` for a platform clone ASOP's [ndk-samples](https://github.com/android/ndk-samples/tree/master/hello-jni) and build the `hello-jni` project. Use the `V=1` flag to see the full compiler output from `ndk-build`.
