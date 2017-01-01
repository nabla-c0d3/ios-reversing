TARGET := iphone:7.0
ARCHS := armv7 arm64

include theos/makefiles/common.mk

TWEAK_NAME = LetMeDebug
LetMeDebug_FILES = letmedebug.m

LetMeDebug_FRAMEWORKS = UIKit
include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk
