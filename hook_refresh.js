/**
 * Frida script to debug and hook the gRPC DoRefreshLogin method in the HAM app.
 * This script first finds the obfuscated stub class, then lists all its methods
 * to help identify the obfuscated name of 'doRefreshLogin'.
 *
 * UPDATED to enumerate methods due to method name obfuscation.
 */

console.log("[*] Script loaded. Attaching to Java VM...");

Java.perform(function () {
    console.log("[*] Inside Java.perform(). Attempting to hook the specific obfuscated class...");

    // --- Step 1: Define the Target Class ---
    // From static analysis, we know the obfuscated gRPC stub class is 'kp.n5$b'.
    const TARGET_CLASS = "kp.n5$b";
    var LoginServiceStub;

    try {
        LoginServiceStub = Java.use(TARGET_CLASS);
        console.log("[+] Successfully found target class: " + TARGET_CLASS);
    } catch (e) {
        console.error("[-] CRITICAL: Could not find class: " + TARGET_CLASS);
        console.error("[-] The obfuscated name might have changed. Please re-verify with JADX.");
        return; // Stop if the specific class isn't found.
    }

    // --- Step 2: Enumerate Methods to Find the Real Name ---
    // Since 'doRefreshLogin' was not found, its name is likely obfuscated.
    // Let's print all methods of this class to find the correct one.
    console.log("\n[*] Methods available in class " + TARGET_CLASS + ":");
    try {
        const methods = LoginServiceStub.class.getDeclaredMethods();
        methods.forEach(function(method) {
            // Print method signature to help identify it.
            // gRPC methods usually take one protobuf message object and return another.
            console.log("    -> " + method.toString());
        });
    } catch (err) {
        console.error("[-] Failed to enumerate methods: " + err);
    }

    console.log("\n[!] ACTION REQUIRED: Look at the method list above.");
    console.log("[!] The real 'doRefreshLogin' is likely one of them (e.g., a method named 'a', 'b', etc.).");
    console.log("[!] It should take one argument (e.g., kp.g6) and return another (e.g., kp.h6).");
    console.log("[!] Once you identify the correct method name, update the 'OBFUSCATED_METHOD_NAME' variable below and re-run the script.\n");


    // --- Step 3: Hook the Target Method (UPDATE THIS) ---
    // Replace "METHOD_NAME_HERE" with the real obfuscated method name from the list above.
    const OBFUSCATED_METHOD_NAME = "METHOD_NAME_HERE";

    if (OBFUSCATED_METHOD_NAME === "METHOD_NAME_HERE") {
        console.log("[*] Script is in discovery mode. Please update OBFUSCATED_METHOD_NAME to proceed with hooking.");
        return;
    }

    try {
        LoginServiceStub[OBFUSCATED_METHOD_NAME].implementation = function (request) {
            console.log("\n\n====================== Hooked " + OBFUSCATED_METHOD_NAME + " ======================");
            console.log("[!] Successfully hooked via class: " + TARGET_CLASS);

            // --- Print Request Data ---
            console.log("[>] Intercepted Request:");
            try {
                var refreshToken = request.getRefreshToken();
                var extendInfo = request.getExtendInfo();
                var deviceFingerprint = extendInfo.getStudentIdSecret();

                console.log("    [REQUEST] Refresh Token    : " + refreshToken);
                console.log("    [REQUEST] Device Fingerprint : " + deviceFingerprint);
                console.log("    --------------------------------------------------");
                console.log("    [RAW REQUEST] " + request.toString().replace(/\n/g, ''));
            } catch (err) {
                console.log("    [!] Error parsing request details: " + err);
            }

            // --- Call the Original Method ---
            var response = this[OBFUSCATED_METHOD_NAME](request);

            // --- Print Response Data ---
            console.log("[<] Intercepted Response:");
            try {
                var newAccessToken = response.getToken();
                var newRefreshToken = response.getRefreshToken();
                var userInfo = response.getUserInfo();

                console.log("    [RESPONSE] New Access Token  : " + newAccessToken);
                console.log("    [RESPONSE] New Refresh Token : " + newRefreshToken);
                if (userInfo) {
                    console.log("    [RESPONSE] User Info         : " + userInfo.toString().replace(/\n/g, ' '));
                }
                 console.log("    --------------------------------------------------");
                console.log("    [RAW RESPONSE] " + response.toString().replace(/\n/g, ''));
            } catch (err) {
                console.log("    [!] Error parsing response details: " + err);
            }

            console.log("====================================================================\n\n");

            return response;
        };

        console.log("[+] Hook for '" + OBFUSCATED_METHOD_NAME + "' is active. Waiting for the app to call it...");

    } catch (methodError) {
        console.error("[-] Found the class, but could not hook '" + OBFUSCATED_METHOD_NAME + "'.");
        console.error("[-] Are you sure this is the correct method name from the list?");
        console.error(methodError);
    }
});
