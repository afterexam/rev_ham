import base64
import json
import re

import grpc
import ssl
import course_detail_pb2
import course_detail_pb2_grpc

# --- 开启 gRPC 底层调试日志 ---
# 这会打印出所有网络传输和 SSL 握手的详细信息
# import os
# os.environ['GRPC_TRACE'] = 'all'
# os.environ['GRPC_VERBOSITY'] = 'DEBUG'

# ✅ 从 .pfx 提取的 PEM 文件
with open("client_cert.pem", "rb") as f:
    cert_chain = f.read()
with open("client_key.pem", "rb") as f:
    private_key = f.read()
# 可选：信任的根证书（如果需要服务端验证）
# with open("D:/bqh/DeskTop/root_cert.pem", "rb") as f:
#     root_cert = f.read()
# creds = grpc.ssl_channel_credentials(root_cert, private_key, cert_chain)

# ⚠️ 如果你信任系统证书 + 用客户端证书
creds = grpc.ssl_channel_credentials(
    root_certificates=None,
    private_key=private_key,
    certificate_chain=cert_chain
)

# ✅ 覆盖域名（否则 SNI 验证会失败）
options = [('grpc.ssl_target_name_override', 'api.ham.nowcent.cn')]

# ✅ 创建安全通道
channel = grpc.secure_channel('api.ham.nowcent.cn:4443', creds, options)

import re

with open("Token_saver", "r", encoding="utf-8") as f:
    content = f.read()

ACCESS_TOKEN = re.search(r'token:\s*"([^"]+)"', content).group(1)


REFRESH_TOKEN = re.search(r'refresh_token:\s*"([^"]+)"', content).group(1)

DEVICE_FINGERPRINT = 'FC1E09E83AEBC0DAD7CDDC1B777850AE'

# ✅ 准备 header (元数据)
metadata = [
    ('authorization', f'{ACCESS_TOKEN}'),
    ('token', 'AND03f5152c5b7477a745507154b9e527e037e9'),
    ('version_code', '121'),
    ('version_name', '1.6.3.121'),
    ('tpns_token', 'AND03f5152c5b7477a745507154b9e527e037e9'),
    ('grpc-accept-encoding', 'gzip'),
    ('user-agent', 'grpc-java-okhttp/1.64.0'),
    ('te','trailers'),

]
def send_request(request_message):
    # ✅ stub
    stub = course_detail_pb2_grpc.GetCourseDetailCommentServiceStub(channel)

    response = stub.GetCourseCommentPage(request_message, metadata=metadata)
    return response

def get_id(course_name="音乐欣赏",instructor=""):
    """
    发送 gRPC 请求并返回响应。
    """
    # ✅ 准备请求消息 (获取 ID)
    # ✅ stub
    stub = course_detail_pb2_grpc.CourseDetailServiceStub(channel)

    request_message = course_detail_pb2.GetCourseDetailMatchRequest(
        course_name=course_name,
        instructor=instructor
    )
    try:
        print(f"[*] 正在发送请求:\n{request_message}")
        # ✅ 调用 GetCourseDetailMatch 方法
        response = stub.GetCourseDetailMatch(request_message, metadata=metadata)
        print(response)
        return response
    except grpc.RpcError as e:
        print(f"\n--- [ 请求失败! ] ---")
        print(f"[*] gRPC 错误代码: {e.code()}")
        print(f"[*] 错误详情: {e.details()}")
        return None


import grpc
import course_detail_pb2
import course_detail_pb2_grpc
from datetime import datetime


def refresh_login():
    """复现 DoRefreshLogin 请求"""

    # 创建一个服务的 "存根" (Stub)，就像一个本地的代理对象
    stub = course_detail_pb2_grpc.LoginServiceStub(channel)

    # 构造请求体 (按照 .proto 文件里的 RefreshLoginRequest 结构)
    request = course_detail_pb2.RefreshLoginRequest(
        refresh_token=REFRESH_TOKEN,
        extend_info=course_detail_pb2.LoginExtendInfo(
            # 注意：proto 里字段名是 student_id_secret，但根据分析我们填入设备指纹
            student_id_secret=DEVICE_FINGERPRINT
        )
    )

    print("🚀 正在发送 gRPC 请求...")
    print(f"请求体内容:\n{request}")

    try:
        # 发起 RPC 调用！
        response = stub.DoRefreshLogin(request, metadata=metadata)
        print("✅ 请求成功！")
        print("服务器响应:\n", response)
        # 文本覆盖写入 response 的字符串形式
        with open('Token_saver', 'w', encoding='utf-8') as f:
            f.write(str(response))

    except grpc.RpcError as e:
        print(f"❌ 请求失败: {e.code()} - {e.details()}")


def format_comments(resp) -> str:
    import re
    from datetime import datetime

    raw_text = str(resp)
    comments = re.findall(r'course_comment\s*{(.*?)}\s*(?=course_comment|page_cursor|$)', raw_text, re.DOTALL)

    result = []
    for i, comment in enumerate(comments, 1):
        username = re.search(r'username:\s*"([^"]+)"', comment)
        content = re.search(r'content:\s*"([^"]+)"', comment)
        star = re.search(r'rate_info\s*{[^}]*star:\s*(\d)', comment)
        seconds = re.search(r'create_time\s*{[^}]*seconds:\s*(\d+)', comment)

        username = username.group(1) if username else "未知用户"
        content = content.group(1) if content else "无内容"
        star = star.group(1) if star else "无评分"
        timestamp = int(seconds.group(1)) if seconds else 0
        date_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"

        result.append(
            f"—— 评论 {i} ——\n"
            f"👤 用户名: {username}\n"
            f"⭐ 评分  : {star}\n"
            f"🕒 时间  : {date_str}\n"
            f"📝 内容  : {content}\n"
            + "-" * 40
        )

    return "\n".join(result)

def main(course_name="音乐欣赏",instructor="王渊"):
    print(course_name)
    id_resp = get_id(course_name=course_name,instructor=instructor)
    id = id_resp.course_table_id


    request = course_detail_pb2.GetCourseCommentPageRequest(
        id=id
    )

    resp = send_request(request)
    print(resp)
    import re
    from datetime import datetime
    raw_text = str(resp)
    # 匹配每条 comment 块
    comments = re.findall(r'course_comment\s*{(.*?)}\s*(?=course_comment|page_cursor|$)', raw_text, re.DOTALL)

    # 解析每条评论
    for i, comment in enumerate(comments, 1):
        username = re.search(r'username:\s*"([^"]+)"', comment)
        content = re.search(r'content:\s*"([^"]+)"', comment)
        star = re.search(r'rate_info\s*{[^}]*star:\s*(\d)', comment)
        seconds = re.search(r'create_time\s*{[^}]*seconds:\s*(\d+)', comment)

        username = username.group(1) if username else "未知用户"
        content = content.group(1) if content else "无内容"
        star = star.group(1) if star else "无评分"
        timestamp = int(seconds.group(1)) if seconds else 0
        date_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"

        print(f"—— 评论 {i} ——")
        print(f"👤 用户名: {username}")
        print(f"⭐ 评分  : {star}")
        print(f"🕒 时间  : {date_str}")
        print(f"📝 内容  : {content}")
        print("-" * 40)
    formatted = format_comments(resp)
    return formatted

if __name__ == '__main__':
    main()
    # while True:
    refresh_login()
    # id_resp = get_id()
    # id = id_resp.course_table_id
    # get_course_comment_page_no_timestamp_lib(id,page_create_time=None, page_num=0, page_size=1)
    # 构建 stub
    # stub = course_detail_pb2_grpc.LoginServiceStub(channel)
    #
    # request = course_detail_pb2.RefreshLoginRequest(
    #     refresh_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXlsb2FkIjoie1wiY3JlYXRlZFRpbWVcIjoxNzUyOTI2NTIyMzYxLFwiZGV2aWNlXCI6XCJBTkQwM2Y1MTUyYzViNzQ3N2E3NDU1MDcxNTRiOWU1MjdlMDM3ZTlcIixcInR5cGVcIjpcInJlZnJlc2hcIixcInVzZXJJZFwiOlwiMmM5YTgwODI5MDVmN2UzYjAxOTA3MTRlNzE1NjAxMzJcIixcInVzZXJUeXBlXCI6XCJVc2VyXCJ9IiwidHlwZSI6InJlZnJlc2gifQ.A1BeWNZgDT9w1kUcYmIU3I7qBziOeBV5eWfxb0rDVTQ",
    #     extend_info=course_detail_pb2.LoginExtendInfo(
    #         student_id_secret="FC1E09E83AEBC0DAD7CDDC1B777850AE"
    #     )
    # )
    # response = stub.DoRefreshLogin(request, metadata=metadata)


