import requests

headers = {
    "sec-ch-ua-platform": "\"Windows\"",
    "Referer": "https://whucourses.cn/search/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
    "Accept": "application/json, text/plain, */*",
    "sec-ch-ua": "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Microsoft Edge\";v=\"138\"",
    "DNT": "1",
    "sec-ch-ua-mobile": "?0"
}

cookies = {
    "courseEvaluationFilled": "true"
}
def format_courses(data):
    lines = []
    for i, item in enumerate(data, 1):
        course_name = item.get('课程名称') or item.get('course_name') or '未知'
        teacher = item.get('授课老师') or item.get('instructor') or '未知'
        course_type = item.get('课程属性') or item.get('course_type') or '未知'
        credit = item.get('课程成绩') or item.get('credit') or item.get('score') or '未知'
        evaluation = item.get('课程内容与评价') or item.get('evaluation') or '无'
        exam_type = item.get('期末考核方式') or item.get('exam_type') or '未知'
        attendance = item.get('考勤与平时作业') or item.get('attendance') or '未知'

        lines.append(
            f"—— 课程 {i} ——\n"
            f"📚 课程名    : {course_name}\n"
            f"👩‍🏫 教师    : {teacher}\n"
            f"🏫 课程类型  : {course_type}\n"
            f"🔢 成绩/学分 : {credit}\n"
            f"📝 评价    : {evaluation}\n"
            f"📅 考核方式  : {exam_type}\n"
            f"📋 考勤作业  : {attendance}\n"
            + "-" * 30
        )
    return "\n".join(lines)

def get(teacher='', course=''):
    url = "https://whucourses.cn/api/search"
    params = {
        "course_name": course,
        "instructor": teacher
    }
    response = requests.get(url, headers=headers, cookies=cookies, params=params, verify=False)
    print(response.json())
    if response.text == 'null':
        return "😶 没有找到相关课程或老师的信息"

    data = response.json()

    return format_courses(data)


if __name__ == '__main__':
    result = get(teacher='', course='操作系统')
    print(result)
