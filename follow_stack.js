/*
 * 功能: Frida 终极仓库拦截脚本 (V5)
 * 我们不再寻找 MD5，而是直接 hook 目标 ViewModel 的构造函数($init)。
 * 当 ViewModel 被创建时，我们拦截它，打印出所有传入的参数和调用栈，
 * 从而精准定位 ID 是从哪里传递过来的。
 */
Java.perform(function() {
    console.log("[*] “终极仓库拦截脚本 V5”已部署...");

    // ❗️❗️❗️ 目标类：从之前的崩溃日志中确认的 ViewModel
    const targetClassName = 'com.nowcent.ham.business.coursescore.ui.comment.detail.CourseDetailCommentViewModel';

    try {
        const ViewModelClass = Java.use(targetClassName);
        console.log(`[+] 成功定位到目标 ViewModel: ${targetClassName}`);

        // 遍历目标类的所有构造函数
        ViewModelClass.$init.overloads.forEach(function(constructor) {

            constructor.implementation = function() {
                console.log(`\n\n[!!!] BINGO! 拦截到 ViewModel 构造函数: ${constructor.signature}`);

                // --- 核心审问环节 ---
                // 打印所有传入的参数，ID 就藏在其中！
                for (let i = 0; i < arguments.length; i++) {
                    const arg = arguments[i];
                    console.log(`    [*] 传入的参数 #${i}: ${arg}`);

                    // ViewModel 经常通过 SavedStateHandle 接收导航参数
                    if (arg && arg.$className && arg.$className.includes('SavedStateHandle')) {
                        const handle = Java.cast(arg, Java.use('androidx.lifecycle.SavedStateHandle'));
                        console.log('        [+] 这是一个 SavedStateHandle! 正在检查里面的内容...');
                        const keySet = handle.keys();
                        const iterator = keySet.iterator();
                        while(iterator.hasNext()) {
                            const key = iterator.next();
                            const value = handle.get(key);
                            console.warn(`            - 发现参数 -> Key: "${key}", Value: "${value}"`);
                        }
                    }
                }

                // 打印调用栈，这就是“幕后黑手”
                console.warn("    [*] 调用栈 (Call Stack):");
                const stackTrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
                console.log(stackTrace);
                console.log("--- [拦截结束] ---\n");

                // 调用原始构造函数，确保 App 正常运行
                return constructor.apply(this, arguments);
            };
        });

        console.log(`[+] 已成功部署对 ${targetClassName} 所有构造函数的监听！请操作 App 以触发。`);

    } catch (e) {
        console.error(`[-] 挂钩失败: ${e}. 请确认 App 已打开并加载了目标界面。`);
    }
});
