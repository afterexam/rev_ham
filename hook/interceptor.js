/*
 * 功能: 终极决战脚本 V7 - 后院导出
 * 1. 废掉自定义 TrustManager (od.e) 的证书校验功能。
 * 2. 拦截 KeyManagerFactory.init()，在内存中克隆 KeyStore。
 * 3. 将克隆体写入到 App 自己的私有数据目录(/data/data/com.nowcent.ham/files/)，
 * 完美规避公共目录的写入权限问题。
 */
Java.perform(function () {
    console.log("[*] “终极决战脚本 V7 - 后院导出”已部署...");


    //--- 任务一：废掉自定义的 TrustManager (保持不变) ---
    try {
        const CustomTrustManager = Java.use('od.e');
        CustomTrustManager.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function(chain, authType) {
            console.log(`[+] 已成功绕过 od.e 的 checkServerTrusted (authType: ${authType})`);
        };
        console.log("[+] 已成功部署对 od.e 的绕过！");
    } catch (e) {
        console.error("[-] 尝试绕过 od.e 失败: " + e);
    }

    // --- 终极任务：以“内存克隆”模式拦截 KeyManagerFactory.init() ---
    try {
        const KeyManagerFactory = Java.use('javax.net.ssl.KeyManagerFactory');
        KeyManagerFactory.init.overload('java.security.KeyStore', '[C').implementation = function (keyStore, password) {
            console.log("\n\n[!!!] BINGO! 拦截到兵工厂 KeyManagerFactory.init()!");

            // --- 内存克隆核心 ---
            let keystoreBytes = null;
            if (keyStore) {
                const ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
                const byteArrayOutputStream = ByteArrayOutputStream.$new();
                keyStore.store(byteArrayOutputStream, password);
                keystoreBytes = byteArrayOutputStream.toByteArray();
                byteArrayOutputStream.close();
                console.log("[*] 已在内存中成功克隆 KeyStore！");
            }

            // 立刻调用原始方法
            const result = this.init(keyStore, password);
            console.log("[*] 原始的 init() 方法已调用，App 流程继续...");

            // 将克隆体交给延迟任务去处理
            if (keystoreBytes) {
                Java.scheduleOnMainThread(function () {
                    console.log("\n--- [延迟任务开始] ---");

                    // --- 修正点：将文件写入 App 的私有目录 ---
                    const File = Java.use('java.io.File');
                    const FileOutputStream = Java.use('java.io.FileOutputStream');
                    // App 的包名，用于构建私有路径
                    const packageName = "com.nowcent.ham";
                    const dumpedKeystorePath = `/data/data/${packageName}/files/dumped_keystore.bks`;

                    const dumpedFile = File.$new(dumpedKeystorePath);
                    const fileOutputStream = FileOutputStream.$new(dumpedFile);

                    console.log(`    [*] 正在将内存中的“克隆体”写入到 App 的后院: ${dumpedKeystorePath}`);
                    try {
                        fileOutputStream.write(keystoreBytes);
                        console.log(`    ✅ 导出成功！请使用 adb pull ${dumpedKeystorePath} 将其取回。`);
                    } catch (e) {
                        console.error(`    ❌ 导出失败: ${e}`);
                    } finally {
                        fileOutputStream.close();
                    }
                    console.log("--- [延迟任务结束] ---\n");
                });
            }

            return result;
        };
        console.log("[+] 已成功部署对 KeyManagerFactory 的监听！");
    } catch (e) {
        console.error("[-] 部署 KeyManagerFactory 监听失败: " + e);
    }
});
