项目概述
本项目是针对 "Ham" 移动应用的逆向工程分析。项目旨在演示绕过客户端安全防护、分析非标准网络协议，并最终实现对应用内部 API 接口调用的完整流程。

主要成果
gRPC 接口逆向: 成功分析了应用获取课程评价的 gRPC 接口，并使用 Python 实现了自动化调用。

SSL Pinning 绕过: 通过 Frida 动态插桩，绕过了应用的多层证书校验机制，包括其自定义的 TrustManager 和客户端证书双向认证，实现了对加密流量的解密和分析。

JWT 密钥提取: 通过 Hook 原生加密库 (libcrypto.so) 中的 HMAC 函数，成功提取了用于 API 请求签名的 JWT 密钥。

API 客户端开发:

开发了多个 Python 脚本，用于模拟应用请求，查询课程信息和用户评价。

构建了一个基于 Flask 的 Web 应用，提供 API 查询的可视化界面。

技术栈
动态插桩 (Dynamic Instrumentation): Frida

静态分析 (Static Analysis): JADX

网络协议 (Network Protocol): gRPC & Protocol Buffers

后端与脚本 (Backend & Scripting): Python (gRPC, Flask, Requests)

逆向分析流程
整个逆向分析过程主要包含以下几个关键步骤：

SSL Pinning 绕过

初步分析: 使用通用 SSL Pinning 绕过脚本未能成功，表明应用存在自定义的校验逻辑。

代码定位: 通过 JADX 进行静态分析，定位到应用使用了自定义的 TrustManager (od.e) 以及需要客户端证书的 KeyStore。

Frida Hook 实现: 编写 interceptor.js 脚本，通过 Hook 禁用自定义 TrustManager 的证书校验功能。同时，在运行时从内存中克隆并导出客户端 KeyStore，以满足服务器端的双向认证要求。完成此步骤后，所有应用流量均可通过中间人代理进行解密分析。

gRPC 协议分析

协议识别: 流量分析表明，课程评价功能的网络通信采用了 gRPC 协议。

接口定义还原: 结合应用代码和网络请求的载荷，还原了 gRPC 服务所需的 .proto 定义文件 (course_detail.proto)。

客户端代码生成: 使用 protoc 编译器，根据 .proto 文件生成了 Python 语言的 gRPC 客户端桩代码 (_pb2.py 和 _pb2_grpc.py)。decode_grpc.py 脚本用于验证 protobuf 解码的正确性。

JWT 签名密钥提取

定位签名实现: 在 Java 层 Hook 加密库未能找到签名逻辑，推断签名过程在原生库（.so 文件）中实现。

原生库 Hook: 编写 jwt_spy.js 脚本，对底层的 libcrypto.so 库进行 Hook。

密钥捕获: 通过 Hook HMAC 函数，在应用执行 HS256 签名操作时，成功拦截并获取了签名的密钥及原始数据。

Python 客户端实现

组件整合: 综合已获取的客户端证书、KeyStore、gRPC 桩代码和 JWT 密钥。

代码编写: 编写 call.py 和 get_id.py 等脚本，构建 gRPC 请求，并在请求头中附加正确的 Authorization (JWT)，成功模拟了客户端与服务器的通信，实现了课程评价数据的获取。

文件结构说明
app.py: Flask Web 应用，提供一个简单的查询界面。

call.py: 封装了 gRPC 请求的核心逻辑，用于获取课程评价。

taokela.py / luoli.py: 用于调用其他公开课程信息 API 的辅助脚本。

interceptor.js: Frida 脚本，用于绕过 SSL Pinning 和导出 KeyStore。

jwt_spy.js: Frida 脚本，用于从原生层捕获 HMAC-SHA256 密钥。

*.proto: gRPC 的服务和消息定义文件。

*_pb2.py / *_pb2_grpc.py: 由 .proto 文件生成的 Python 代码。

声明
本项目仅用于技术学习和安全研究，请勿用于非法用途。所有数据均来源于应用的公开接口。