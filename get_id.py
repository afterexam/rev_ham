import grpc
import course_detail_pb2  # 导入我们编译好的模块
import course_detail_pb2_grpc


# --- [ 重要前置步骤 ] ---
# 本脚本需要独立的证书和私钥 PEM 文件。请先使用 OpenSSL 工具，
# 从你的 PFX 文件 (例如 client_with_pass.pfx) 中提取它们：
#
# 1. 提取私钥 (会要求输入 PFX 密码):
#    openssl pkcs12 -in client_with_pass.pfx -nocerts -out client_key.pem -nodes
#
# 2. 提取证书链 (会要求输入 PFX 密码):
#    openssl pkcs12 -in client_with_pass.pfx -nokeys -out client_cert.pem
#
# --- [ 脚本开始 ] ---

def get_id(JWT, course_name="音乐欣赏",instructor="王渊"):
    """
    发送 gRPC 请求并返回响应。
    """
    # ✅ 准备请求消息 (获取 ID)
    request_message = course_detail_pb2.GetCourseDetailMatchRequest(
        course_name="音乐欣赏",
        instructor="王渊"
    )
    # ✅ 从 .pem 文件加载证书和私钥
    try:
        with open("client_cert.pem", "rb") as f:
            cert_chain = f.read()
        with open("client_key.pem", "rb") as f:
            private_key = f.read()
    except FileNotFoundError as e:
        print(f"[-] 错误: 找不到证书或私钥文件 -> {e}")
        print("[-] 请确保已按照脚本开头的注释，从 PFX 文件中提取了 .pem 文件。")
        return None

    # ✅ 创建 gRPC SSL 凭证
    creds = grpc.ssl_channel_credentials(
        root_certificates=None,  # 信任系统的根证书
        private_key=private_key,
        certificate_chain=cert_chain
    )

    # ✅ 覆盖域名（否则 SNI 验证会失败）
    options = (('grpc.ssl_target_name_override', 'api.ham.nowcent.cn'),)

    # ✅ 创建安全通道
    channel = grpc.secure_channel('api.ham.nowcent.cn:4443', creds, options)

    # ✅ 创建 stub (存根)
    stub = course_detail_pb2_grpc.CourseDetailServiceStub(channel)

    # ✅ 准备 header (元数据)
    metadata = [
        ('authorization', f'bearer {JWT}'),
        ('token', 'AND03f5152c5b7477a745507154b9e527e037e9'),
        ('version_code', '121'),
        ('version_name', '1.6.3.121'),
        ('tpns_token', 'AND03f5152c5b7477a745507154b9e527e037e9'),
        ('grpc-accept-encoding', 'gzip')
    ]

    try:
        print(f"[*] 正在发送请求:\n{request_message}")
        # ✅ 调用 GetCourseDetailMatch 方法
        response = stub.GetCourseDetailMatch(request_message, metadata=metadata)
        return response
    except grpc.RpcError as e:
        print(f"\n--- [ 请求失败! ] ---")
        print(f"[*] gRPC 错误代码: {e.code()}")
        print(f"[*] 错误详情: {e.details()}")
        return None


if __name__ == '__main__':


    # ❗️❗️❗️ 你的 JWT (需要保持更新，否则会认证失败) ❗️❗️❗️
    JWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXlsb2FkIjoie1wiY3JlYXRlZFRpbWVcIjoxNzUyOTIwMzU5MTk2LFwiZGV2aWNlXCI6XCJBTkQwM2Y1MTUyYzViNzQ3N2E3NDU1MDcxNTRiOWU1MjdlMDM3ZTlcIixcInR5cGVcIjpcImJlYXJlclwiLFwidXNlcklkXCI6XCIyYzlhODA4MjkwNWY3ZTNiMDE5MDcxNGU3MTU2MDEzMlwiLFwidXNlclR5cGVcIjpcIlVzZXJcIn0iLCJ0eXBlIjoiYmVhcmVyIn0.ymTBhBkID-F4YlLhKDiywI5HGWVESj2sw0yF16fMeYI'

    resp = get_id(JWT)

    if resp:
        print("\n--- [ 请求成功! ] ---")
        print(f"[*] 是否成功 (Success): {resp.success}")
        print(f"[*] 课程 ID (course_table_id): {resp.course_table_id}")
        # print(f"[*] 消息 (Message): {resp.message}")
        # print("\n--- [ 完整响应 ] ---")
        # print(resp)
