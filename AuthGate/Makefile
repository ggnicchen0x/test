# Theos-free build. Requires macOS + Xcode command-line tools.
#
#   make           # build arm64 dylib
#   make install   # drop dylib into ../Payload/3105.app/Frameworks/
#   make inject    # run inject_dylib.py against the main binary
#   make all       # build + install + inject
#   make clean

SDK           := iphoneos
SDK_PATH      := $(shell xcrun --sdk $(SDK) --show-sdk-path 2>/dev/null)
CLANG         := $(shell xcrun --sdk $(SDK) -f clang 2>/dev/null)
TARGET        := AuthGate.dylib
INSTALL_NAME  := @executable_path/Frameworks/AuthGate.dylib
MIN_IOS       := 15.0
APP_FRAMEWORKS := ../Payload/Byte.app/Frameworks
APP_BINARY     := ../Payload/Byte.app/Byte

CFLAGS  := -arch arm64 -fobjc-arc -fmodules -fblocks -Os \
           -isysroot $(SDK_PATH) \
           -mios-version-min=$(MIN_IOS) \
           -Wall -Wno-unused-variable
LDFLAGS := -dynamiclib \
           -install_name $(INSTALL_NAME) \
           -framework UIKit -framework Foundation -framework Security -framework QuartzCore \
           -framework CoreGraphics

.PHONY: all build install inject sign clean

all: build

# install + inject are opt-in: CI (and most users) only need the built dylib.
local: build install inject

build: $(TARGET)

$(TARGET): AuthGate.m
	@test -n "$(CLANG)" || (echo "xcrun/clang for iOS SDK not found. Run on macOS with Xcode installed."; exit 1)
	$(CLANG) $(CFLAGS) AuthGate.m $(LDFLAGS) -o $(TARGET)
	@echo "[+] Built $(TARGET)"

install: $(TARGET)
	@mkdir -p $(APP_FRAMEWORKS)
	cp $(TARGET) $(APP_FRAMEWORKS)/
	@echo "[+] Installed to $(APP_FRAMEWORKS)/$(TARGET)"

inject:
	python3 ../inject_dylib.py $(APP_BINARY) $(INSTALL_NAME)

clean:
	rm -f $(TARGET)
