import grpc
import ssl
import course_detail_pb2
import course_detail_pb2_grpc

def send_request(JWT, request_message):
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
    options = (('grpc.ssl_target_name_override', 'api.ham.nowcent.cn'),)

    # ✅ 创建安全通道
    channel = grpc.secure_channel('api.ham.nowcent.cn:4443', creds, options)

    # ✅ stub
    stub = course_detail_pb2_grpc.GetCourseDetailCommentServiceStub(channel)

    # ✅ header
    metadata = [
        ('authorization', f'bearer {JWT}'),
        ('token', 'AND03f5152c5b7477a745507154b9e527e037e9'),
        ('version_code', '121'),
        ('version_name', '1.6.3.121'),
        ('tpns_token', 'AND03f5152c5b7477a745507154b9e527e037e9'),
        ('grpc-accept-encoding', 'gzip')
    ]

    response = stub.GetCourseCommentPage(request_message, metadata=metadata)
    return response



if __name__ == '__main__':
    JWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwYXlsb2FkIjoie1wiY3JlYXRlZFRpbWVcIjoxNzUyOTE1MTEyNDAwLFwiZGV2aWNlXCI6XCJBTkQwM2Y1MTUyYzViNzQ3N2E3NDU1MDcxNTRiOWU1MjdlMDM3ZTlcIixcInR5cGVcIjpcImJlYXJlclwiLFwidXNlcklkXCI6XCIyYzlhODA4MjkwNWY3ZTNiMDE5MDcxNGU3MTU2MDEzMlwiLFwidXNlclR5cGVcIjpcIlVzZXJcIn0iLCJ0eXBlIjoiYmVhcmVyIn0.qRO8gB4hOgs1HfzlUkD8sZsspRyjEB-jG-j5Bnz8BTQ'


    request = course_detail_pb2.DoRefreshLoginRequest(
        id=JWT
    )
    response = send_request(JWT, request)
    print(response)
