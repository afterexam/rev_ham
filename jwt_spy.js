/*
 * 功能: Frida 终极密钥扒手脚本 (V3 - 修正版)
 * 之前的 Java hook 监听无果，说明签名过程很可能在原生层 (.so) 完成。
 * 本脚本将直接 hook 底层的 OpenSSL 加密库函数 HMAC，
 * 在 App 调用它进行 HS256 签名时，当场捕获密钥和签名数据。
 * (修正了将原生 hook 放入 Java.perform 导致的错误)
 */
console.log("[*] “终极密钥扒手脚本 V3”已部署...");

// 目标库：安卓系统里负责加密的核心库之一
const libcrypto = "libcrypto.so";

// 目标函数：OpenSSL 里负责 HMAC 计算的核心函数
// HMAC(EVP_MD const *evp_md, void const *key, int key_len, uint8_t const *d, size_t n, uint8_t *md, unsigned int *md_len)
const hmacFunc = Module.findExportByName(libcrypto, "HMAC");

if (hmacFunc) {
    console.log(`[+] 成功定位到原生函数 HMAC @ ${hmacFunc}`);

    Interceptor.attach(hmacFunc, {
        onEnter: function(args) {
            // --- 核心审问环节 ---

            // args[0] 是加密算法类型，我们暂时不关心

            // args[1] 是密钥的内存地址
            const keyAddress = args[1];
            // args[2] 是密钥的长度
            const keyLength = args[2].toInt32();

            // args[3] 是待签名数据的内存地址
            const dataAddress = args[3];
            // args[4] 是待签名数据的长度
            const dataLength = args[4].toInt32();

            console.log("\n\n[!!!] BINGO! 拦截到原生 HMAC 调用!");

            // 1. 打印密钥
            try {
                const keyBytes = keyAddress.readByteArray(keyLength);
                const keyString = new TextDecoder("utf-8").decode(keyBytes);
                console.warn(`    🔑🔑🔑 捕获到密钥 (长度: ${keyLength}): "${keyString}"`);
            } catch (e) {
                console.error(`    [-] 密钥无法转为字符串，正在打印 Hex...`);
                console.log(hexdump(keyAddress, { length: keyLength }));
            }

            // 2. 打印待签名的数据
            //    对于 JWT 来说，这通常是 "header_base64.payload_base64"
            try {
                const dataBytes = dataAddress.readByteArray(dataLength);
                const dataString = new TextDecoder("utf-8").decode(dataBytes);
                console.log(`    [*] 待签名的数据 (长度: ${dataLength}):\n${dataString}`);
            } catch (e) {
                console.error(`    [-] 待签名数据无法转为字符串，正在打印 Hex...`);
                console.log(hexdump(dataAddress, { length: dataLength }));
            }

            console.log("--- [扒窃结束] ---\n");
        }
    });

} else {
    console.error(`[-] 未能在 ${libcrypto} 中找到 HMAC 函数。App 可能使用了不同的加密库。`);
}
