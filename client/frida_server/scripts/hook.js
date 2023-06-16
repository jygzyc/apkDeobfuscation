
function decryptQzb(inputStr){
    var result = "";
    Java.perform(function() {
        var targetClass = Java.use("kotlinx.android.extensionss.qz");
        result = targetClass.b(inputStr);
    });
    return result;
}

function decryptCgb(inputStr){
    var result = "";
    Java.perform(function() {
        var CornerTreatment = Java.use("kotlinx.android.extensionss.cg");
        result = CornerTreatment.b(inputStr);
    });
    return result;
}


rpc.exports = {
    invokemethod01: decryptQzb,
    invokemethod02: decryptCgb
} 