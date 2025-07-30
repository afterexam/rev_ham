Java.perform(
    () => {

        let LongCounterFactory = Java.use("is.s1");
        LongCounterFactory["c"].implementation = function (str, str2) {
            console.log(`LongCounterFactory.m7572c is called: str=${str}, str2=${str2}`);
            this["c"](str, str2);
        };
        // --- 这就是 trustAllCerts 的制作过程 ---

// 1. 找到 X509TrustManager 这张“图纸”
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');

// 2. 创建一个“万能信任”的 TrustManager
        const TrustAllManager = Java.registerClass({
            // 定义我们新类的名字
            name: 'com.example.TrustAllManager',
            // 告诉 Frida，我们的新类是按照 X509TrustManager 图纸造的
            implements: [X509TrustManager],
            // 实现图纸要求的所有方法
            methods: {
                // 这三个方法是 X509TrustManager 接口规定必须有的
                checkClientTrusted: function (chain, authType) {
                    // 啥也不干，直接放行
                },
                checkServerTrusted: function (chain, authType) {
                    // 啥也不干，直接放行 (这个是我们最关心的)
                },
                getAcceptedIssuers: function () {
                    // 返回一个空数组
                    return [];
                }
            }
        });

// 3. 把我们造好的“万能信任”管理器，放进一个数组里
//    SSLContext.init() 方法要求接收一个 TrustManager 数组
        const trustAllCerts = [TrustAllManager.$new()];

// --- 制作完成 ---


    }
)

