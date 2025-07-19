Java.perform(function () {
    console.log("[*] 动态审问 - 提取评论和评分字段");

    const targetClassName = 'com.nowcent.ham.business.coursescore.ui.detail.c';
    const targetMethodName = 'a';

    function tryGetString(val) {
        try {
            if (val && val.toString) {
                return val.toString().substring(0, 200);
            }
        } catch (e) {}
        return '[无法转字符串]';
    }

    try {
        const UiClass = Java.use(targetClassName);
        console.log(`[+] 找到目标类: ${targetClassName}`);

        UiClass[targetMethodName].overloads.forEach(function (overload) {
            console.log(`[*] 挂钩重载: ${overload.signature}`);

            overload.implementation = function () {
                console.log(`\n\n[!!!] 拦截函数: ${overload.signature}`);

                const response = arguments[1];
                if (!response) {
                    console.log("[-] 没有拿到 response 参数");
                    return this[targetMethodName].apply(this, arguments);
                }

                console.log(`[+] response 类型: ${response.$className}`);

                // 尝试提取评论信息
                try {
                    var commentInfo = response.getCourseCommentInfo();
                    if (commentInfo) {
                        console.log("  评论信息 [kp.j0]:");
                        console.log("    - enableState_: " + tryGetString(commentInfo.enableState_));
                        var data = commentInfo.data_;
                        if (data) {
                            console.log("    - data_ (typeUrl_): " + tryGetString(data.typeUrl_));
                            console.log("    - data_ (value_): " + tryGetString(data.value_));
                        }
                    } else {
                        console.log("  评论信息为空");
                    }
                } catch (e) {
                    console.log("  [-] 获取评论信息失败: " + e);
                }

                // 尝试提取评分信息
                try {
                    var gradeInfo = response.getCourseGradeStatInfo();
                    if (gradeInfo) {
                        console.log("  评分信息 [kp.w0]:");
                        console.log("    - average_: " + tryGetString(gradeInfo.average_));
                        console.log("    - name_: " + tryGetString(gradeInfo.name_));
                        console.log("    - instructor_: " + tryGetString(gradeInfo.instructor_));
                        console.log("    - total_: " + tryGetString(gradeInfo.total_));
                    } else {
                        console.log("  评分信息为空");
                    }
                } catch (e) {
                    console.log("  [-] 获取评分信息失败: " + e);
                }

                console.log("\n--- 审问结束 ---");
                return this[targetMethodName].apply(this, arguments);
            };
        });

        console.log("[+] 脚本部署完成，等待触发...");
    } catch (e) {
        console.error("[-] 脚本部署失败: " + e);
    }
});
