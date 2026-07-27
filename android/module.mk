LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tlsclient
LOCAL_SRC_FILES := lib/$(TARGET_ARCH_ABI)/libtlsclient.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_STATIC_LIBRARY)