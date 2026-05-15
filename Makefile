THEOS_DEVICE_IP =
TARGET = tvos:clang:18.5:18.5
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

FRAMEWORK_NAME = InfuseBypass

InfuseBypass_FILES = InfuseBypass/InfuseBypass.m
InfuseBypass_FRAMEWORKS = Foundation
InfuseBypass_CFLAGS = -fobjc-arc

include $(THEOS)/makefiles/framework.mk
