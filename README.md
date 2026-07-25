# TLS 客户端

极简 TLS 客户端库.

## 特点

- 仅依赖 openssl 和 c++11 标准库, 不依赖任何平台库.
- 需要外部传入连接好的 TCP socket 才能工作.
- 不关心文件读取, 请传入字符串化的密钥.
- 结构化的返回值, 含 openssl 标准错误码和错误信息, 方便定位问题.

这样设计的原因是:

- 将运行环境和 tls 部分解耦, 能更方便定位问题.
- 每个平台甚至运行环境, 创建网络连接的方式都不一样, 但一般调用的 openssl 接口是相同的.
- 每个平台甚至运行环境, 文件读取的方式都不一样, 但证书那点长度总能转换为字符串.

## 使用方式

就一个头文件, 一个源文件, 一个依赖. 没有比较特殊的处理.

如果要编译 windows 平台静态库, 建议使用 cmake, 通过 cmakelist.txt 来编译. 编译工具链可选 llvm, 或者 msvc. 不建议使用 mingw.

编译完成后想要使用, 要首先给项目引入 openssl 库, 然后在编译的时候把头文件 tlsclient.h 和库文件 libtlsclient.lib 路径带上就行了, 没什么特殊的.

如果要编译 android 平台静态库, 首先要安装 android ndk, 还要找到 openssl 的头文件 (是的只需要头文件, 不需要库文件), 将路径替换到 build.bat, 像这样:

```bat
set OPENSSL_INCLUDE_DIR=D:\scoop\apps\openssl\current\include
```

> 尽量保证 openssl 头文件的版本和最终使用的库文件版本一致.

然后使用 cmd 执行 android 目录下的 build.bat <ndk_path>, 需要传入 ndk 的路径, 例如:

```pwsh
cmd /c android\build.bat D:\android-ndk\android-ndk-$ndk
```

编译完成之后, 可以使用 sh 执行 android 目录下的 package.sh. 来打包成 android 模块, 里面包含了 android.mk 和不同架构对应的 inc/lib 的包.

使用的时候, 用任意方式为你的 android 项目引入这个模块和 openssl 模块.

## 代码示例

另见 test/main.cpp 中的 windows 上测试用例.

```c++
// 提供所有必需品, 创建 tls 客户端对象
// 参数结构:
// 1. int socket_fd: 已经连接好的 TCP socket
// 2. tls 配置
//   1. bool is_verify_server: 是否要验证服务器证书
//   2. string ca: ca 证书. 不验证服务器证书时可以不传.
//   3. string cert_chain: 客户端证书链条
//   4. string private_key: 客户端私钥
//   5. string server_name: 服务器 SNI 名称
TlsClient client(static_cast<int>(sock), {false, ""s, cert, key, "kers.site"s});

// 初始化客户端对象
auto result = client.init();
// 任何时候都可以获取返回值中的错误码和消息
cout << "init() -> " << result.get_code() << ": " << result.get_message() << endl;

// 进行握手
result = client.hand_shake();
cout << "hand_shake() -> " << result.get_code() << ": " << result.get_message() << endl;

// 构建 uint8_t 数组, 发送数据
string cmd = "\x10\x96\x09";
vector<uint8_t> buffer(cmd.begin(), cmd.end());
result = client.send(buffer.data(), buffer.size());
cout << "send() -> " << result.get_code() << ": " << result.get_message() << endl;

// 接收数据
vector<uint8_t> recv_buffer(1024);
result = client.recv(recv_buffer.data(), recv_buffer.size());
cout << "recv() -> " << result.get_code() << ": " << result.get_message() << endl;

// 关闭服务器
result = client.shutdown();
cout << "shutdown() -> " << result.get_code() << ": " << result.get_message() << endl;
```
