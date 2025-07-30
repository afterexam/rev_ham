import re
import grpc
from datetime import datetime

# 导入你生成的 pb2 和 pb2_grpc 文件
import course_detail_pb2
import course_detail_pb2_grpc


class HamClient:
    """
    一个用于与 Ham App 后端 gRPC 服务交互的客户端。
    封装了 mTLS 认证、Token 管理和 API 调用。
    """
    API_HOST = 'api.ham.nowcent.cn'
    API_PORT = 4443
    DEVICE_FINGERPRINT = 'FC1E09E83AEBC0DAD7CDDC1B777850AE'  # 设备指纹

    def __init__(self, cert_path='client_cert.pem', key_path='client_key.pem', token_path='Token_saver'):
        """
        初始化客户端。

        Args:
            cert_path (str): 客户端证书路径 (.pem)。
            key_path (str): 客户端私钥路径 (.pem)。
            token_path (str): 存储 token 的文件路径。
        """
        self.token_path = token_path
        self._access_token = None
        self._refresh_token = None

        # 1. 加载认证和 Token
        self._creds = self._load_credentials(cert_path, key_path)
        self.load_tokens()

        # 2. 创建 gRPC 通道
        self._channel = self._create_secure_channel()

        # 3. 初始化各个服务的 stubs
        self._course_stub = course_detail_pb2_grpc.CourseDetailServiceStub(self._channel)
        self._comment_stub = course_detail_pb2_grpc.GetCourseDetailCommentServiceStub(self._channel)
        self._login_stub = course_detail_pb2_grpc.LoginServiceStub(self._channel)

    def _load_credentials(self, cert_path, key_path):
        """加载 mTLS 证书并创建 gRPC 凭证。"""
        print(f"[*] 正在从 '{cert_path}' 和 '{key_path}' 加载 SSL客户端证书...")
        try:
            with open(cert_path, "rb") as f:
                cert_chain = f.read()
            with open(key_path, "rb") as f:
                private_key = f.read()

            return grpc.ssl_channel_credentials(
                root_certificates=None,  # 信任系统根证书
                private_key=private_key,
                certificate_chain=cert_chain
            )
        except FileNotFoundError as e:
            print(f"❌ 错误: 证书文件未找到 - {e}")
            raise

    def _create_secure_channel(self):
        """创建 gRPC 安全通道。"""
        # SNI 覆盖是必须的，否则域名验证会失败
        options = [('grpc.ssl_target_name_override', self.API_HOST)]
        target = f'{self.API_HOST}:{self.API_PORT}'
        print(f"[*] 正在连接到 gRPC 服务器: {target}")
        return grpc.secure_channel(target, self._creds, options)

    def _get_metadata(self):
        """根据当前 token 生成请求头。"""
        if not self._access_token:
            raise ValueError("Access Token 未加载，请先调用 load_tokens() 或 refresh_login()")

        return [
            ('authorization', self._access_token),
            ('token', 'AND03f5152c5b7477a745507154b9e527e037e9'),  # 这个值似乎是固定的
            ('version_code', '121'),
            ('version_name', '1.6.3.121'),
            ('tpns_token', 'AND03f5152c5b7477a745507154b9e527e037e9'),
            ('grpc-accept-encoding', 'gzip'),
            ('user-agent', 'grpc-java-okhttp/1.64.0'),
            ('te', 'trailers'),
        ]

    def load_tokens(self):
        """从文件加载 Access Token 和 Refresh Token。"""
        print(f"[*] 正在从 '{self.token_path}' 加载 Tokens...")
        try:
            with open(self.token_path, "r", encoding="utf-8") as f:
                content = f.read()

            # 使用更健壮的正则来提取带 "bearer " 前缀的 token
            access_token_match = re.search(r'token:\s*"(bearer\s+[^"]+)"', content)
            refresh_token_match = re.search(r'refresh_token:\s*"([^"]+)"', content)

            if not access_token_match or not refresh_token_match:
                raise ValueError("在文件中找不到 token 或 refresh_token。")

            self._access_token = access_token_match.group(1)
            self._refresh_token = refresh_token_match.group(1)
            print("✅ Tokens 加载成功。")
        except (FileNotFoundError, ValueError) as e:
            print(f"⚠️ 警告: 加载 Tokens 失败 - {e}。稍后可能需要刷新登录。")
            self._access_token = None
            self._refresh_token = None

    def save_tokens(self, response_text):
        """将新的 token 信息保存到文件。"""
        print(f"[*] 正在将新的 Tokens 保存到 '{self.token_path}'...")
        try:
            with open(self.token_path, 'w', encoding='utf-8') as f:
                f.write(response_text)
            print("✅ Tokens 保存成功。")
        except IOError as e:
            print(f"❌ 错误: 保存 Tokens 失败 - {e}")

    def refresh_login(self):
        """使用 Refresh Token 刷新登录状态，并更新内部 tokens。"""
        if not self._refresh_token:
            print("❌ 错误: Refresh Token 不存在，无法刷新。")
            return

        request = course_detail_pb2.RefreshLoginRequest(
            refresh_token=self._refresh_token,
            extend_info=course_detail_pb2.LoginExtendInfo(
                student_id_secret=self.DEVICE_FINGERPRINT
            )
        )

        print("🚀 正在发送 gRPC 请求来刷新登录状态...")
        print(f"请求体内容:\n{request}")

        try:
            response = self._login_stub.DoRefreshLogin(request, metadata=self._get_metadata())
            print("✅ 请求成功！")
            print(f"服务器响应:\n{response}")

            # 更新内部状态并保存到文件
            self.save_tokens(str(response))
            self.load_tokens()  # 重新加载以更新 self._access_token

        except grpc.RpcError as e:
            print(f"❌ 请求失败: {e.code()} - {e.details()}")

    def _get_course_id(self, course_name, instructor=""):
        """内部方法：根据课程名和教师名获取课程 ID。"""
        request = course_detail_pb2.GetCourseDetailMatchRequest(
            course_name=course_name,
            instructor=instructor
        )
        print(f"[*] 正在获取课程 ID: '{course_name}' - '{instructor}'")
        try:
            response = self._course_stub.GetCourseDetailMatch(request, metadata=self._get_metadata())
            if response and response.success and response.course_table_id:
                print(f"✅ 成功获取课程 ID: {response.course_table_id}")
                return response.course_table_id
            else:
                print(f"⚠️ 警告: 未能获取到课程 ID。服务器消息: {response.message}")
                return None
        except grpc.RpcError as e:
            print(f"❌ 获取课程 ID 失败: {e.code()} - {e.details()}")
            return None

    def get_course_comments(self, course_name, instructor=""):
        """
        获取指定课程的评价。

        Args:
            course_name (str): 课程名称。
            instructor (str): 讲师名称。

        Returns:
            str: 格式化后的评论字符串，或一条错误信息。
        """
        course_id = self._get_course_id(course_name, instructor)
        if not course_id:
            return "无法获取课程评价，因为未能找到课程 ID。"

        request = course_detail_pb2.GetCourseCommentPageRequest(id=course_id)

        print(f"[*] 正在获取课程 '{course_name}' (ID: {course_id}) 的评价...")
        try:
            response = self._comment_stub.GetCourseCommentPage(request, metadata=self._get_metadata())
            return self._format_comments(response)
        except grpc.RpcError as e:
            error_message = f"❌ 获取课程评价失败: {e.code()} - {e.details()}"
            print(error_message)
            return error_message

    @staticmethod
    def _format_comments(resp) -> str:
        """静态方法：将 gRPC 响应格式化为人类可读的字符串。"""
        raw_text = str(resp)
        comments = re.findall(r'course_comment\s*{(.*?)}\s*(?=course_comment|page_cursor|$)', raw_text, re.DOTALL)

        if not comments:
            return "该课程暂无评价。"

        result = []
        for i, comment_block in enumerate(comments, 1):
            username = re.search(r'username:\s*"([^"]+)"', comment_block)
            content = re.search(r'content:\s*"([^"]+)"', comment_block)
            star = re.search(r'rate_info\s*{[^}]*star:\s*(\d)', comment_block)
            seconds = re.search(r'create_time\s*{[^}]*seconds:\s*(\d+)', comment_block)

            username_str = username.group(1) if username else "未知用户"
            content_str = content.group(1) if content else "无内容"
            star_str = star.group(1) if star else "无评分"
            timestamp = int(seconds.group(1)) if seconds else 0
            date_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S") if timestamp else "未知时间"

            result.append(
                f"—— 评论 {i} ——\n"
                f"👤 用户名: {username_str}\n"
                f"⭐ 评分  : {star_str}\n"
                f"🕒 时间  : {date_str}\n"
                f"📝 内容  : {content_str}\n"
                + "-" * 40
            )
        return "\n".join(result)


if __name__ == '__main__':
    # --- 使用示例 ---

    # 1. 创建客户端实例
    client = HamClient()

    # 2. 刷新登录 (如果需要的话，比如 token 过期了)
    # client.refresh_login()

    # 3. 查询课程评价

    print("\n" + "=" * 20 + " 查询一门课程 " + "=" * 20)
    comments_music = client.get_course_comments(course_name="音乐欣赏", instructor="王渊")
    print(comments_music)

    print("\n" + "=" * 20 + " 查询课程评价 " + "=" * 20)
    comments = client.get_course_comments(course_name="操作系统", instructor="杨敏")
    print(comments)


