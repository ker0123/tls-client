#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include <openssl/ssl.h>

namespace tls {

class Result {
private:
  uint64_t code;
  std::string message;

public:
  // 构造函数
  Result(uint64_t code, std::string message)
      : code(code), message(std::move(message)) {}
  // 快速构造
  static Result Ok() { return Result{0, "Ok"}; }
  static Result Error(uint64_t code, std::string message) {
    return Result{code, std::move(message)};
  }
  // 显式判断
  bool is_ok() const { return code == 0; }
  bool is_err() const { return code != 0; }
  // 获取错误码和错误信息
  uint64_t get_code() const { return code; }
  std::string get_message() const { return message; }
  // 重载 bool 操作符
  explicit operator bool() const { return is_ok(); }
};

/// 客户端配置项
struct Config {
  /// 是否对服务器证书进行验证, 默认为 false
  bool is_verify_server = false;
  /// ca 证书, 不提供就使用默认的
  std::string ca;

  /// 客户端证书链 - 必须
  std::string cert_chain;
  /// 客户端私钥 - 必须
  std::string private_key;

  /// 服务端名称 - 建议
  std::string server_name;
};

} // namespace tls

/// 客户端
class TlsClient {
public:
  /// 创建 tls 客户端
  ///
  /// - socket_fd 必须是一个已连接的 TCP socket
  /// - 需要传入服务端配置, 其中至少保证 cert, key 两个参数不为空
  /// - 该类永远不会更改 socket_fd 的状态, 更不会关闭 socket_fd
  /// - 虽然 Client 不会改动 socket_fd, 但 Client 在使用 socket_fd 时,
  /// 也不建议外部对其进行操作.
  explicit TlsClient(int socket_fd, tls::Config cfg);

  /// 销毁 tls 客户端. 只释放 tls 相关资源, 不会关闭 socket_fd
  ~TlsClient();

  /// 禁止拷贝构造
  TlsClient(const TlsClient &) = delete;
  /// 禁止拷贝赋值
  TlsClient &operator=(const TlsClient &) = delete;
  /// 允许移动构造
  TlsClient(TlsClient &&other) noexcept;
  /// 允许移动赋值
  TlsClient &operator=(TlsClient &&other) noexcept;

  // 初始化 SSL_CTX/SSL, 加载凭证, 设置仅支持 TLS 1.2 模式,
  // 并将 SSL 绑定到 socket_fd.
  tls::Result init();

  /// 执行 TLS 握手
  tls::Result hand_shake();

  /// 发送加密的应用数据.
  tls::Result send(const uint8_t *data, size_t len, size_t *sent = nullptr);

  /// 接收解密的应用数据.
  tls::Result recv(uint8_t *buffer, size_t capacity,
                   size_t *received = nullptr);

  /// 发送 close_notify 并释放 TLS 会话状态.
  tls::Result shutdown();

  /// 返回客户端是否已初始化
  bool is_initialized() const { return ssl_ctx != nullptr && ssl != nullptr; }
  /// 返回客户端是否已完成握手
  bool is_handshake_done() const { return handshake_done; }
  /// 返回客户端的 socket_fd
  int get_socket_fd() const { return socket_fd; }

private:
  /// socket 套接字
  int socket_fd = -1;
  /// 客户端配置
  tls::Config cfg;

  /// SSL 上下文
  SSL_CTX *ssl_ctx = nullptr;
  /// SSL 对象
  SSL *ssl = nullptr;

  /// TLS 握手是否完成
  bool handshake_done = false;
  /// TLS 关闭是否完成
  bool shutdown_done = false;
};
