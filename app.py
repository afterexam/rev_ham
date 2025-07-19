# app.py

from flask import Flask, request, jsonify, render_template_string
import call  # 导入你封装好的核心逻辑
from taokela import get  # 导入你的另一个数据源
import json  # 导入 json 库用于格式化
from flask_cors import CORS
import os  # 导入 os 库

# --- [ Flask 应用设置 ] ---
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = True  # 确保返回的 JSON 中文显示正常
CORS(app)  # 允许所有来源的跨域请求

# --- [ 全局配置区 ] ---
script_dir = os.path.dirname(os.path.abspath(__file__))
PFX_FILE_PATH = os.path.join(script_dir, "client_with_pass.pfx")
print(f"[*] 证书文件的绝对路径已锁定: {PFX_FILE_PATH}")

# --- [ 前端 HTML 模板 ] ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>课程评价查询</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif, "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol", "Noto Color Emoji";
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            background-color: #f3f4f6;
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: Consolas, "Courier New", monospace;
            border: 1px solid #e5e7eb;
        }
    </style>
</head>
<body class="bg-gray-100 text-gray-800">

    <div class="container mx-auto p-4 md:p-8 max-w-3xl">
        <header class="text-center mb-8">
            <h1 class="text-4xl font-bold text-gray-900">课程评价查询系统</h1>
            <p class="text-gray-600 mt-2">输入课程名称和讲师，获取第一手评价信息。</p>
        </header>

        <main>
            <form id="search-form" class="bg-white p-6 rounded-lg shadow-md mb-8">
                 <div class="grid md:grid-cols-2 gap-4">
                    <div>
                        <label for="course_name" class="block text-sm font-medium text-gray-700">课程名称</label>
                        <input type="text" id="course_name" name="course_name" required
                               class="mt-1 block w-full px-3 py-2 bg-white border border-gray-300 rounded-md text-sm shadow-sm placeholder-gray-400
                                      focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                               placeholder="例如: 音乐欣赏">
                    </div>
                    <div>
                        <label for="instructor" class="block text-sm font-medium text-gray-700">讲师名称</label>
                        <input type="text" id="instructor" name="instructor"
                               class="mt-1 block w-full px-3 py-2 bg-white border border-gray-300 rounded-md text-sm shadow-sm placeholder-gray-400
                                      focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                               placeholder="例如: 王渊 (可留空)">
                    </div>
                </div>
                <div class="mt-6">
                    <button type="submit"
                            class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors">
                        查询评价
                    </button>
                </div>
            </form>

            <!-- 结果展示区域 -->
            <div id="results-container">
                 <div id="loader" class="text-center py-8 hidden">
                    <svg class="animate-spin h-8 w-8 text-indigo-600 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <p class="mt-2 text-gray-600">正在拼命查询中...</p>
                </div>
                <div id="error-message" class="text-center py-8 hidden">
                    <p class="text-red-500 font-medium"></p>
                </div>
                <div id="comments-list" class="space-y-4">
                </div>
            </div>
        </main>
    </div>

    <script>
        const form = document.getElementById('search-form');
        const loader = document.getElementById('loader');
        const errorMessage = document.getElementById('error-message');
        const commentsList = document.getElementById('comments-list');

        form.addEventListener('submit', async (e) => {
            e.preventDefault();

            commentsList.innerHTML = '';
            errorMessage.style.display = 'none';
            loader.style.display = 'block';

            const courseName = document.getElementById('course_name').value;
            const instructor = document.getElementById('instructor').value;

            try {
                // --- [ ❗️❗️❗️ 核心修正点在这里 ❗️❗️❗️ ] ---
                // 1. 使用 POST 方法
                const response = await fetch('/get_comments', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json; charset=utf-8',
                    },
                    // 2. 将参数放在请求体 (body) 里
                    body: JSON.stringify({
                        course_name: courseName,
                        instructor: instructor
                    })
                });
                // --- [ 修正结束 ] ---

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(`服务器响应错误: ${response.status} - ${errorText}`);
                }

                const data = await response.json();
                loader.style.display = 'none';

                if (!data) { throw new Error('服务器返回了无效或空的数据。'); }
                if (data.error) { throw new Error(data.details || data.error); }

                if (data.raw_text && typeof data.raw_text === 'string') {
                    const preBlock = document.createElement('pre');
                    preBlock.textContent = data.raw_text;
                    commentsList.appendChild(preBlock);
                } else {
                    errorMessage.querySelector('p').textContent = '没有找到任何相关课程的评价。';
                    errorMessage.style.display = 'block';
                }

            } catch (error) {
                loader.style.display = 'none';
                errorMessage.querySelector('p').textContent = '查询失败: ' + error.message;
                errorMessage.style.display = 'block';
            }
        });
    </script>
</body>
</html>
"""


# --- [ 网页路由 ] ---
@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

import re

import re

def remove_emoji(text):
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags
        "\u2700-\u27BF"          # dingbats
        "\u24C2"                 # enclosed characters (单个字符)
        "\U0001F251"             # 单个字符
        "]+",
        flags=re.UNICODE
    )
    return emoji_pattern.sub(r'', text)


# --- [ API 接口定义 ] ---
# --- [ ❗️❗️❗️ 核心修正点在这里 ❗️❗️❗️ ] ---
# 1. 允许 POST 方法
@app.route('/get_comments', methods=['POST', 'GET'], strict_slashes=False)
def get_course_comments():
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({"error": "请求体必须是 JSON 格式"}), 400

        course_name = data.get('course_name')
        instructor = data.get('instructor', "")
    else:
        # GET 方法走这里
        course_name = request.args.get('course_name')
        instructor = request.args.get('instructor', "")

    # if not course_name:
    #     return jsonify({"error": "请提供 'course_name' 参数"}), 400

    try:
        print(f"[*] 正在调用核心逻辑处理: '{course_name} - {instructor}'")
        try:
            comments_text = call.main(course_name=course_name, instructor=instructor)
        except:
            comments_text = ''
        try:
            other_info = get(instructor, course_name)
        except:
            other_info = ''
        combined_text = f"{comments_text+other_info}\n\n"


        combined_text = remove_emoji(combined_text)
        print(combined_text, 'combine')
        resp = {"raw_text": combined_text}
        # padding = " " * (2048 - len(combined_text) - 100)
        # resp['padding'] = padding

        return jsonify(resp)
    except Exception as e:
        print(f"[!] 核心逻辑执行出错: {e}")
        return jsonify({"error": "服务器内部错误"}), 500


# --- [ 启动服务器 ] ---
if __name__ == '__main__':
    print("[*] 正在启动 Flask 服务器，监听 http://0.0.0.0:3000")
    app.run(host='0.0.0.0', port=3000, debug=True)
