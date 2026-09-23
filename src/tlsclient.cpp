#include "tlsclient.h"

#include <cerrno>
#include <chrono>
#include <climits>
#include <cstring>
#include <thread>
#include <utility>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

using namespace tls;
using namespace std;

namespace {

/// 将 OpenSSL 错误队列完整取出并拼接为可读字符串
string collect_all_openssl_errors() {
  string all;
  bool first = true;

  while (true) {
    unsigned long code = ERR_get_error();
    if (code == 0) {
      break;
    }

    char buf[256] = {0};
    ERR_error_string_n(code, buf, sizeof(buf));
    if (!first) {
      all += "\n";
    }
    all += buf;
    first = false;
  }

  return all;
}

/// 从 OpenSSL 基础错误队列中获取错误码和错误信息, 并返回 Result 对象
Result from_ERR(string more_info = "") {
  unsigned long first_err = ERR_peek_error();
  if (first_err == 0) {
    return Result(0, more_info);
  }

  string err_msg = collect_all_openssl_errors();

  if (more_info.empty()) {
    return Result::Error(first_err, err_msg);
  } else {
    return Result::Error(first_err, err_msg + string("\n^ ") + more_info);
  }
}

/// 从 SSL 对象的错误队列中获取错误码和错误信息, 并返回 Result 对象
Result from_SSL(SSL *ssl, int last_ret, string more_info = "") {
  int err_code = SSL_get_error(ssl, last_ret);
  if (err_code == SSL_ERROR_NONE) {
    return Result::Ok();
  }

  string err_msg;
  if (err_code == SSL_ERROR_SSL) {
    // 真实 OpenSSL 失败原因在错误队列中，完整取出便于排查。
    err_msg = collect_all_openssl_errors();
    if (err_msg.empty()) {
      err_msg = "tls protocol or crypto failure";
    }
  } else if (err_code == SSL_ERROR_ZERO_RETURN) {
    err_msg = "tls connection closed cleanly by peer";
  } else if (err_code == SSL_ERROR_WANT_READ) {
    err_msg = "operation needs more network data (want read)";
  } else if (err_code == SSL_ERROR_WANT_WRITE) {
    err_msg = "operation needs socket writable state (want write)";
  } else if (err_code == SSL_ERROR_SYSCALL) {
    if (errno != 0) {
      err_msg = string("i/o syscall failure, errno = ") + to_string(errno);
    } else {
      err_msg = "peer closed connection unexpectedly (eof)";
    }

    // 某些 SYSCALL 场景也会带 OpenSSL 队列信息，附加输出。
    string queue_msg = collect_all_openssl_errors();
    if (!queue_msg.empty()) {
      err_msg += "\n" + queue_msg;
    }
  } else {
    err_msg = "ssl operation failed";

    string queue_msg = collect_all_openssl_errors();
    if (!queue_msg.empty()) {
      err_msg += "\n" + queue_msg;
    }
  }

  if (more_info.empty()) {
    return Result::Error(err_code, err_msg);
  } else {
    return Result::Error(err_code, err_msg + "\n^ " + more_info);
  }
}

/// 从内存字符串加载 PEM 证书链到 SSL_CTX
bool load_cert_chain_from_pem(SSL_CTX *ctx, const string &cert_pem) {
  if (ctx == nullptr || cert_pem.empty()) {
    return false;
  }

  BIO *bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
  if (bio == nullptr) {
    return false;
  }

  X509 *leaf = PEM_read_bio_X509_AUX(bio, nullptr, nullptr, nullptr);
  if (leaf == nullptr) {
    BIO_free(bio);
    return false;
  }

  int ret = SSL_CTX_use_certificate(ctx, leaf);
  X509_free(leaf);
  if (ret != 1) {
    BIO_free(bio);
    return false;
  }

  while (true) {
    X509 *chain_cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (chain_cert == nullptr) {
      break;
    }

    ret = SSL_CTX_add1_chain_cert(ctx, chain_cert);
    X509_free(chain_cert);
    if (ret != 1) {
      BIO_free(bio);
      return false;
    }
  }

  BIO_free(bio);
  ERR_clear_error();
  return true;
}

/// 从内存字符串加载 PEM 私钥到 SSL_CTX
bool load_private_key_from_pem(SSL_CTX *ctx, const string &key_pem) {
  if (ctx == nullptr || key_pem.empty()) {
    return false;
  }

  BIO *bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
  if (bio == nullptr) {
    return false;
  }

  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (pkey == nullptr) {
    return false;
  }

  int ret = SSL_CTX_use_PrivateKey(ctx, pkey);
  EVP_PKEY_free(pkey);
  return ret == 1;
}

/// 从内存字符串加载 PEM CA 证书集合到 SSL_CTX 的 verify store
bool load_ca_from_pem(SSL_CTX *ctx, const string &ca_pem) {
  if (ctx == nullptr || ca_pem.empty()) {
    return false;
  }

  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  if (store == nullptr) {
    return false;
  }

  BIO *bio = BIO_new_mem_buf(ca_pem.data(), static_cast<int>(ca_pem.size()));
  if (bio == nullptr) {
    return false;
  }

  int loaded = 0;
  while (true) {
    X509 *cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (cert == nullptr) {
      break;
    }

    ++loaded;
    int ret = X509_STORE_add_cert(store, cert);
    X509_free(cert);
    if (ret != 1) {
      unsigned long err = ERR_peek_last_error();
      bool is_duplicate = ERR_GET_LIB(err) == ERR_LIB_X509 && ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE;
      if (!is_duplicate) {
        BIO_free(bio);
        return false;
      }
      ERR_clear_error();
    }
  }

  BIO_free(bio);
  if (loaded == 0) {
    return false;
  }

  ERR_clear_error();
  return true;
}

} // namespace

/// 简单地赋值私有变量
TlsClient::TlsClient(int socket_fd, Config cfg) : socket_fd(socket_fd), cfg(std::move(cfg)) {}

/// 如果有, 释放 ssl 和 ssl_ctx, 并将其置为 nullptr
TlsClient::~TlsClient() {
  if (ssl != nullptr) {
    SSL_free(ssl);
    ssl = nullptr;
  }

  if (ssl_ctx != nullptr) {
    SSL_CTX_free(ssl_ctx);
    ssl_ctx = nullptr;
  }
}

/// 实现拷贝构造
TlsClient::TlsClient(TlsClient &&other) noexcept { *this = std::move(other); }

/// 实现移动赋值
TlsClient &TlsClient::operator=(TlsClient &&other) noexcept {
  if (this == &other) {
    return *this;
  }

  swap(socket_fd, other.socket_fd);
  swap(cfg, other.cfg);
  swap(ssl_ctx, other.ssl_ctx);
  swap(ssl, other.ssl);
  swap(handshake_done, other.handshake_done);
  swap(shutdown_done, other.shutdown_done);
  return *this;
}

/// tls 客户端初始化
///
/// - 检查传入 socket 是否有效, 是否之前没有初始化过
/// - 创建并配置 ssl 上下文(ssl_ctx)
/// - 加载证书
/// - 创建 ssl 对象
/// - 将 ssl 绑定到 socket_fd
Result TlsClient::init() {

  // 检查状态和参数
  if (socket_fd < 0) {
    return Result::Error(1, "[init] invalid socket_fd " + to_string(socket_fd));
  }

  if (ssl_ctx != nullptr || ssl != nullptr) {
    return Result::Error(1, "[init] already initialized");
  }

  if (cfg.cert_chain.empty() || cfg.private_key.empty()) {
    return Result::Error(1, "[init] cert and key must not be empty");
  }

  // 创建 ssl 上下文, 做好相关配置

  ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (ssl_ctx == nullptr) {
    auto error_code = ERR_get_error();
    auto error_msg = ERR_error_string(error_code, nullptr);
    return Result::Error(error_code, error_msg + string("\nin init() call SSL_CTX_new()"));
  }

  int ret = SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
  if (ret != 1) {
    return from_ERR("in init() call SSL_CTX_set_min_proto_version()");
  }

  if (cfg.allow_legacy_renegotiation) {
    SSL_CTX_set_options(ssl_ctx, SSL_OP_LEGACY_SERVER_CONNECT);
  }

  /// 服务器证书校验过程
  auto verify_server = [&]() {
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, nullptr);

    bool use_default_ca = cfg.ca.empty();
    ret = use_default_ca ? SSL_CTX_set_default_verify_paths(ssl_ctx) : (load_ca_from_pem(ssl_ctx, cfg.ca) ? 1 : 0);
    if (ret != 1) {
      const char *action = use_default_ca ? "SSL_CTX_set_default_verify_paths" : "load_ca_from_pem";
      return from_ERR("in init() call " + string(action));
    }

    return Result::Ok();
  };

  // 可选: 进行服务器证书校验
  if (cfg.is_verify_server) {
    Result verify_result = verify_server();
    if (verify_result.is_err()) {
      return verify_result;
    }
  } else {
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, nullptr);
  }

  // 加载客户端证书链和私钥, 并检查私钥是否匹配证书
  if (!load_cert_chain_from_pem(ssl_ctx, cfg.cert_chain)) {
    return Result::Error(1, "[init] failed to load cert from pem");
  }
  if (!load_private_key_from_pem(ssl_ctx, cfg.private_key)) {
    return Result::Error(1, "[init] failed to load private key from pem");
  }
  ret = SSL_CTX_check_private_key(ssl_ctx);
  if (ret != 1) {
    return from_ERR("in init() call SSL_CTX_check_private_key()");
  }

  // 创建 ssl 对象, 并将其绑定到 socket_fd
  ssl = SSL_new(ssl_ctx);
  if (ssl == nullptr) {
    return from_ERR("in init() call SSL_new()");
  }
  // 可选: 设置服务端名称, 用于 SNI 和证书验证
  if (!cfg.server_name.empty()) {
    ret = SSL_set_tlsext_host_name(ssl, cfg.server_name.c_str());
    if (ret != 1) {
      return from_ERR("in init() call SSL_set_tlsext_host_name()");
    }

    if (cfg.is_verify_server) {
      ret = SSL_set1_host(ssl, cfg.server_name.c_str());
      if (ret != 1) {
        return from_ERR("in init() call SSL_set1_host()");
      }
    }
  }
  // 继续设置 socket_fd
  ret = SSL_set_fd(ssl, socket_fd);
  if (ret != 1) {
    return from_SSL(ssl, ret);
  }

  // 重置状态标志, 返回成功
  handshake_done = false;
  shutdown_done = false;
  return Result::Ok();
}

/// 客户端主动发起 tls 握手
///
/// - 检查状态, 可能提前返回
/// - 调用 SSL_connect 进行握手
Result TlsClient::hand_shake(time_t timeout_ms) {
  // 检查状态, 可能提前返回
  if (!is_initialized()) {
    return Result::Error(1, "[hand_shake] not initialized");
  }
  if (shutdown_done) {
    return Result::Error(1, "[hand_shake] already shutdown");
  }
  if (handshake_done) {
    return Result::Ok();
  }

  // 尝试连接
  int ret = SSL_connect(ssl);
  auto start_time = chrono::steady_clock::now();
  while (ret != 1) {
    int error_code = SSL_get_error(ssl, ret);
    // 如果不是 WANT_READ/WANT_WRITE, 说明握手失败, 返回错误
    if (error_code != SSL_ERROR_WANT_READ && error_code != SSL_ERROR_WANT_WRITE) {
      return from_SSL(ssl, ret, "in hand_shake() call SSL_connect()");
    }
    // 如果是 WANT_READ/WANT_WRITE, 则在一定时间内重复调用 SSL_connect
    auto now = chrono::steady_clock::now();
    auto elapsed_ms = chrono::duration_cast<chrono::milliseconds>(now - start_time).count();
    if (elapsed_ms >= timeout_ms) {
      return Result::Error(1, "[hand_shake] handshake timed out (" + to_string(elapsed_ms) + " ms)");
    }
    this_thread::sleep_for(chrono::milliseconds(10));
    ret = SSL_connect(ssl);
  }

  handshake_done = true;
  return Result::Ok();
}

/// 发送数据
///
/// - data: 要发送的数据
/// - len: 要发送的数据字节数
/// - sent: 实际发送的字节数, 可选
Result TlsClient::send(const uint8_t *data, size_t len, size_t *sent) {
  if (sent != nullptr) {
    *sent = 0;
  }

  // 检查状态
  if (!is_initialized()) {
    return Result::Error(1, "[send] not initialized");
  }
  if (!handshake_done) {
    return Result::Error(1, "[send] handshake not finished");
  }
  if (shutdown_done) {
    return Result::Error(1, "[send] already shutdown");
  }

  // 检查参数
  if (data == nullptr && len > 0) {
    return Result::Error(1, "[send] data is null but len > 0");
  }
  if (len == 0) {
    return Result::Ok();
  }
  if (len > static_cast<size_t>(INT_MAX)) {
    return Result::Error(1, "[send] len exceeds SSL_write limit");
  }

  // 发送, 然后判断结果并返回
  int ret = SSL_write(ssl, data, static_cast<int>(len));
  if (ret <= 0) {
    return from_SSL(ssl, ret, "in send() call SSL_write()");
  }
  return Result(0, "sent " + to_string(ret) + " bytes");
}

/// 接收数据
///
/// - buffer: 用于接收数据的缓冲区
/// - capacity: 缓冲区容量
/// - received: 实际接收到的字节数, 可选
Result TlsClient::recv(uint8_t *buffer, size_t capacity, size_t *received) {
  if (received != nullptr) {
    *received = 0;
  }

  // 检查状态
  if (!is_initialized()) {
    return Result::Error(1, "[recv] not initialized");
  }
  if (!handshake_done) {
    return Result::Error(1, "[recv] handshake not finished");
  }
  if (shutdown_done) {
    return Result::Error(1, "[recv] already shutdown");
  }

  // 检查参数
  if (buffer == nullptr && capacity > 0) {
    return Result::Error(1, "[recv] buffer is null but capacity > 0");
  }
  if (capacity == 0) {
    return Result(0, "[recv] capacity is 0, nothing to read");
  }
  if (capacity > static_cast<size_t>(INT_MAX)) {
    return Result::Error(1, "[recv] capacity exceeds SSL_read limit");
  }

  // 接收, 然后判断结果并返回
  int ret = SSL_read(ssl, buffer, static_cast<int>(capacity));
  if (ret <= 0) {
    return from_SSL(ssl, ret, "in recv() call SSL_read()");
  }
  return Result(0, "received " + to_string(ret) + " bytes");
}

/// 关闭客户端
Result TlsClient::shutdown() {
  // 判断状态

  if (!is_initialized()) {
    return Result::Error(1, "[shutdown] not initialized");
  }

  if (shutdown_done) {
    return Result{0, "[shutdown] already shutdown"};
  }

  // 调用 ssl 函数关闭会话, 失败的话提前返回结果

  int ret = SSL_shutdown(ssl);
  if (ret < 0) {
    return from_SSL(ssl, ret, "in shutdown() call SSL_shutdown()");
  }

  // 更新状态
  shutdown_done = true;
  handshake_done = false;

  // 释放 ssl 和 ssl_ctx
  SSL_free(ssl);
  ssl = nullptr;
  SSL_CTX_free(ssl_ctx);
  ssl_ctx = nullptr;

  return Result::Ok();
}
