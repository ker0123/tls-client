LOCAL_PATH := $(call my-dir)

# 需要提供 openssl/include 所在目录

include $(CLEAR_VARS)
LOCAL_MODULE := tlsclient
LOCAL_MODULE_FILENAME := libtlsclient
LOCAL_SRC_FILES := $(LOCAL_PATH)/../src/tlsclient.cpp
LOCAL_C_INCLUDES += $(OPENSSL_INCLUDE_DIR)
include $(BUILD_STATIC_LIBRARY)
