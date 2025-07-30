Java.perform(() => {
    console.log("[*] 脚本已加载，准备追踪 'obj' 的来源...");

    let LocalStorage = Java.use("ig.d");

    LocalStorage.b.overload('ig.d$a', 'java.lang.Object').implementation = function (enumC8835a, obj) {

        // 调用原始方法，让 App 正常运行
        let result = this.b.overload('ig.d$a', 'java.lang.Object').apply(this, arguments);
        if (enumC8835a.toString().includes('Token')){
            console.log(`  [-] 传入参数: key=${enumC8835a}, obj=${obj}`);
            console.log(`  [-] 返回结果: ${result}`);
            // 打印调用堆栈 ---
        // console.log("\n[+] LocalStorage.b() 被调用! 调用路径如下:");
        // var stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        // console.log("==================== 调用堆栈 (obj的来源) ====================");
        // console.log(stack);
        // console.log("====================================================================");
        }


        return result;
    };

});