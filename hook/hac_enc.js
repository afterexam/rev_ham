/*
 * 功能: Frida 终极刺杀脚本 (V4)
 * 根据崩溃日志，我们已经精准定位到 App 自己的 MD5 工具类 (pg.f)。
 * 本脚本将直接 hook 这个工具类，以“外科手术”的方式捕获 ID 生成的原材料和调用者。
 * (这能完美规避因 hook 系统类导致的崩溃问题)
 */
Java.perform(function() {
    console.log("[*] “终极刺杀脚本 V4”已部署...");

    // ❗️❗️❗️ 目标类：从崩溃日志中发现的 MD5 工具类
    const targetClassName = 'pg.f';

    // ❗️❗️❗️ 目标方法：从崩溃日志中发现的方法名
    const targetMethodName = 'a';

    try {
        const MD5UtilsClass = Java.use(targetClassName);
        console.log(`[+] 成功定位到目标 MD5 工具类: ${targetClassName}`);

        // 遍历目标方法的所有重载，以防万一
        MD5UtilsClass[targetMethodName].overloads.forEach(function(overload) {

            overload.implementation = function() {
                console.log(`\n\n[!!!] BINGO! 拦截到 MD5 工具类方法: ${overload.signature}`);

                // 打印所有传入的参数，这就是“原材料”
                for (let i = 0; i < arguments.length; i++) {
                    console.log(`    [*] 传入的原材料 #${i}: ${arguments[i]}`);
                }

                // 调用原始方法
                const result = this[targetMethodName].apply(this, arguments);

                console.log(`    [*] 生成的 MD5 值: ${result}`);

                // 打印调用栈，这就是“幕后黑手”
                console.warn("    [*] 调用栈 (Call Stack):");
                const stackTrace = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
                console.log(stackTrace);
                console.log("--- [刺杀结束] ---\n");

                return result;
            };
        });

        console.log(`[+] 已成功部署对 ${targetClassName}.${targetMethodName} 的监听！请操作 App 以触发。`);

    } catch (e) {
        console.error(`[-] 挂钩失败: ${e}. 请确认 App 已打开并加载了目标界面。`);
    }
});
