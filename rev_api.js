const CryptoJS = require('crypto-js')
function login() {
    var g = new Date();
    var h = g.toUTCString();
    var k = 'AKID5t23df2wfg2r98i5599nadhfmiehiigkgif';
    var l = 'bn8wtN6e46A2E4muFfg9djrH3pNJhu16r8r09707';
    var m = 's';
    var n = "hmac id=\"" + k + "\", algorithm=\"hmac-sha1\", headers=\"x-date source\", signature=\"";
    var o = "x-date: " + h + "\n" + "source: " + m;
    var p = CryptoJS.HmacSHA1(o, l);
    p = CryptoJS.enc.Base64.stringify(p);
    p = n + p + "\"";
    return [p,h]
}

console.log(login())