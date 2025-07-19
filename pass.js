/*
 * 功能: 终极通用 SSL Pinning 绕过脚本
 * 它会同时挂钩多种常见的证书验证框架和方法，
 * 以最大概率绕过 App 的 SSL Pinning 检测。
 *
 * 作者: @pcipolloni (以及社区贡献者)
 * 来源: Frida CodeShare
 */
Java.perform(function() {
    console.log("[*] “终极隐身衣”已部署，开始全面屏蔽证书验证...");

    // --- [ 屏蔽 SSLContext ] ---
    try {
        const SSLContext = Java.use('javax.net.ssl.SSLContext');
        SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManagers, trustManagers, secureRandom) {
            console.log('[+] 已拦截 SSLContext.init()');
            this.init(keyManagers, null, secureRandom); // 强制使用空的 TrustManager
        };
        console.log('[*] SSLContext 屏蔽模块已激活');
    } catch (e) {
        console.log('[-] SSLContext 屏蔽失败: ' + e);
    }

    // --- [ 屏蔽 X509TrustManager ] ---
    try {
        const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] 已绕过 TrustManagerImpl.verifyChain()');
            return untrustedChain;
        };
        console.log('[*] X509TrustManager 屏蔽模块已激活');
    } catch (e) {
        console.log('[-] X509TrustManager 屏蔽失败: ' + e);
    }

    // --- [ 屏蔽 OkHttp3 ] ---
    try {
        const okhttp3_CertificatePinner = Java.use('okhttp3.CertificatePinner');
        okhttp3_CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] 已绕过 OkHttp3 CertificatePinner.check()');
            return;
        };
        console.log('[*] OkHttp3 屏蔽模块已激活');
    } catch (e) {
        console.log('[-] OkHttp3 屏蔽失败: ' + e);
    }

    // --- [ 屏蔽 TrustKit (常见于 iOS, 但以防万一) ] ---
    try {
        const TrustKit = Java.use('com.datatheorem.android.trustkit.TrustKit');
        TrustKit.getInstance().getPinningValidator().handleTrustUpdate.implementation = function(hostname, chain) {
            console.log('[+] 已绕过 TrustKit handleTrustUpdate()');
            return;
        };
        console.log('[*] TrustKit 屏蔽模块已激活');
    } catch (e) {
        console.log('[-] TrustKit 屏蔽失败: ' + e);
    }

    console.log("[*] 所有屏蔽模块已部署完毕。");
});
