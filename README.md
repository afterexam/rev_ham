## 项目概述

Ham是武汉大学生活助手://github.com/orangeboyChen/whu-ham

本项目是针对 "Ham" 移动应用的逆向工程分析。项目旨在演示绕过客户端安全防护、分析非标准网络协议，并最终实现对应用内部 API 接口调用的完整流程。



## 主要成果

- **gRPC 接口逆向**: 成功分析了应用获取课程评价的 gRPC 接口，并使用 Python 实现了自动化调用。

- **mTLS 绕过**: 通过 Frida 动态插桩，绕过了应用的证书校验机制，实现了对加密流量的解密和分析。

- **完全摆脱app运行 **, 依靠对token缓存-获取机制的模拟实现登录状态刷新

- **API 客户端开发**:
  - 开发了多个 Python 脚本，用于模拟应用请求，查询课程信息和用户评价。
  
  - 构建了一个基于 Flask 的 Web 应用，提供 API 查询的可视化界面。
  

## 演示

**获取课程id后展示评论内容**

![image-20250728193926674](imgs/image-20250728193926674.png)

**更新登录状态, 理论上永远不用打开app**

![image-20250728194008234](imgs/image-20250728194008234.png)



## 技术栈



- **动态插桩 (Dynamic Instrumentation)**: `Frida`
- **静态分析 (Static Analysis)**: `JADX` & `mt管理器` 
- **网络协议 (Network Protocol)**: `gRPC` & `Protocol Buffers`
- **后端与脚本 (Backend & Scripting)**: `Python` (gRPC, Flask, Requests)



## 逆向分析流程

最开始ssl握手失败的原因在于服务端对证书做校验:

![image-20250731052814967](imgs/image-20250731052814967.png)



配置app内的ssl证书之后, ssl握手正常,可开始后续抓包分析:

![image-20250731052744882](imgs/image-20250731052744882.png)



整个逆向分析过程主要包含以下几个关键步骤：

1. **Frida Hook **: 编写 `interceptor.js` 脚本，在运行时从内存中克隆并导出客户端 KeyStore，以满足服务器端的双向认证要求。完成此步骤后，所有应用流量均可通过中间人代理进行解密分析。
2. **gRPC 协议分析**
   - **协议识别**: 抓包流量分析表明，课程评价功能的网络通信采用了 gRPC 协议。
   - **接口定义还原**: 结合静态分析结果，还原了 gRPC 服务所需的 `.proto` 定义文件 (`course_detail.proto`)。
   - **客户端代码生成**: 使用 `protoc` 编译器，根据 `.proto` 文件生成了 Python 语言的 gRPC 客户端桩代码 (`_pb2.py` 和 `_pb2_grpc.py`)。`decode_grpc.py` 脚本用于验证 `protobuf` 解码的正确性。
3. **JWT 签名密钥提取**
   - **密钥捕获**: 通过 Hook `HMAC` 函数，拦截不到东西, 看来JWT密钥在服务器 , 爆破验证后发现无弱口令漏洞
4. **维持登录状态的逻辑逆向** 
   - 分析发现两种长短token存储在本地(并不是由本地生成token ,而是记住服务器发来的token), 于是模拟这个思路来存储token 
4. **Python 客户端实现**
   - **组件整合**: 综合已获取的客户端证书、KeyStore、gRPC 桩代码和 JWT token
   - **代码编写**: 编写 `call.py` 和 `get_id.py` 等脚本，构建 gRPC 请求，并在请求头中附加正确的 `Authorization` (JWT)，成功模拟了客户端与服务器的通信，实现了课程评价数据的获取。



## 文件结构说明



- `app.py`: Flask Web 应用，提供一个简单的查询web界面
- `call.py`: 封装了 gRPC 请求的核心逻辑，用于获取课程评价/刷新登录状态
- `taokela.py` : 用于调用其他公开课程信息 API 的辅助脚本, 集成一切已知的查询接口, 最大程度消除信息差
- `interceptor.js`: Frida 脚本，用于导出 KeyStore。
- `jwt_spy.js`: Frida 脚本，用于从原生层捕获 HMAC-SHA256 密钥(无结果)
- `*.proto`: gRPC 的服务和消息定义文件。
- `*_pb2.py` / `*_pb2_grpc.py`: 由 `.proto` 文件生成的 Python 代码。
- `hook_key.js` , 可以捕获到token 的本地的读写过程



## TODO list

- [x] 逆向relogin/破解JWT密钥 实现自动登录, 不用手动更新access_token
- [x] 完全模拟app的token逻辑

## relogin的堆栈

```
hook is set on kp.g6$b.setRefreshToken
'setRefreshToken' was called.
==================== Refresh Token JWT ====================
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXlsb2FkIjoie1wiY3JlYXRlZFRpbWVcIjoxNzUzNjkxODk5NzA1LFwiZGV2aWNlXCI6XCJBTkQwM2Y1MTUyYzViNzQ3N2E3NDU1MDcxNTRiOWU1MjdlMDM3ZTlcIixcInR5cGVcIjpcInJlZnJlc2hcIixcInVzZXJJZFwiOlwiMmM5YTgwODI5MDVmN2UzYjAxOTA3MTRlNzE1NjAxMzJcIixcInVzZXJUeXBlXCI6XCJVc2VyXCJ9IiwidHlwZSI6InJlZnJlc2gifQ.WXNY_4rYWt8yyHTyBsKIRh9wsabws1gKkgmBN7C2XPY
==========================================================

==================== Call Stack (Where the JWT comes from) ====================
java.lang.Exception
        at kp.g6$b.setRefreshToken(Native Method)
        at nf.d.invokeSuspend(AccountManager.kt:141)
        at kotlin.coroutines.jvm.internal.BaseContinuationImpl.resumeWith(ContinuationImpl.kt:12)
        at du.v0.run(DispatchedTask.kt:129)
        at android.os.Handler.handleCallback(Handler.java:938)
        at android.os.Handler.dispatchMessage(Handler.java:99)
        at android.os.Looper.loopOnce(Looper.java:201)
        at android.os.Looper.loop(Looper.java:288)
        at android.app.ActivityThread.main(ActivityThread.java:8060)
        at java.lang.reflect.Method.invoke(Native Method)
        at com.android.internal.os.RuntimeInit$MethodAndArgsCaller.run(RuntimeInit.java:571)
        at com.android.internal.os.ZygoteInit.main(ZygoteInit.java:1091)

==============================================================================

```
nf.d.invokeSuspend(AccountManager) 其实是ig文件里面的LocalStorageManager(混淆之后为ig.d$a,这是一个文件读写器前置的哈希签名器,目的是校验是否被篡改)

反编译可知是从/data/data/com.nowcent.ham/shared_prefs/settings_5.xml 中读取上次缓存的refresh_token和access_token

- 然后doRefreshLogin会更新此文件的值, 打开app有个一读一写的过程
- 此文件的每个缓存的值(token,userid等)都有一个哈希值做校验 , 盐值为 `vTzpGEkkc7tsSDB4` , 哈希(参数名+ 值+ 盐)
- 详见hook_key.js , 可以捕获到token 的读写



## 声明



本项目仅用于技术学习和安全研究，请勿用于非法用途。所有数据均来源于应用的公开接口。