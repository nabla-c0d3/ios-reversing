TARGET := iphone:7.0
ARCHS := armv7 arm64

include theos/makefiles/common.mk

TWEAK_NAME = DecryptStrings
DecryptStrings_FILES = decryptstrings.m

DecryptStrings_FRAMEWORKS = UIKit
include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/aggregate.mk
