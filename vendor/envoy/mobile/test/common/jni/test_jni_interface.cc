#include <jni.h>

#include "test/common/integration/test_server_interface.h"

#include "library/common/jni/jni_support.h"
#include "library/common/jni/jni_utility.h"

// NOLINT(namespace-envoy)

// Quic Test ServerJniLibrary

extern "C" JNIEXPORT void JNICALL
Java_io_envoyproxy_envoymobile_engine_testing_TestJni_nativeStartQuicTestServer(JNIEnv* env,
                                                                                jclass clazz) {
  jni_log("[QTS]", "starting server");
  start_server(true);
}

extern "C" JNIEXPORT jint JNICALL
Java_io_envoyproxy_envoymobile_engine_testing_TestJni_nativeGetServerPort(JNIEnv* env,
                                                                          jclass clazz) {
  jni_log("[QTS]", "getting server port");
  return get_server_port();
}

extern "C" JNIEXPORT void JNICALL
Java_io_envoyproxy_envoymobile_engine_testing_TestJni_nativeShutdownQuicTestServer(JNIEnv* env,
                                                                                   jclass clazz) {
  jni_log("[QTS]", "shutting down server");
  shutdown_server();
}

extern "C" JNIEXPORT void JNICALL
Java_io_envoyproxy_envoymobile_engine_testing_TestJni_nativeStartTestServer(JNIEnv* env,
                                                                            jclass clazz) {
  jni_log("[QTS]", "starting server");
  start_server(false);
}

extern "C" JNIEXPORT void JNICALL
Java_io_envoyproxy_envoymobile_engine_testing_TestJni_nativeShutdownTestServer(JNIEnv* env,
                                                                               jclass clazz) {
  jni_log("[QTS]", "shutting down server");
  shutdown_server();
}

extern "C" JNIEXPORT jstring JNICALL
Java_io_envoyproxy_envoymobile_engine_testing_TestJni_nativeCreateYaml(JNIEnv* env, jclass,
                                                                       jlong bootstrap_ptr) {
  Envoy::Thread::SkipAsserts skip_asserts;
  std::unique_ptr<envoy::config::bootstrap::v3::Bootstrap> bootstrap(
      reinterpret_cast<envoy::config::bootstrap::v3::Bootstrap*>(bootstrap_ptr));
  std::string yaml = Envoy::MessageUtil::getYamlStringFromMessage(*bootstrap);
  return env->NewStringUTF(yaml.c_str());
}
