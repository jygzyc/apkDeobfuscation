/**
 * Replace method call with requested result deeper.
 * Useful for custom string deobfuscation.
 *
 */

import jadx.core.dex.instructions.ConstStringNode
import jadx.core.dex.instructions.InvokeNode
import jadx.core.dex.nodes.InsnNode
import jadx.core.dex.instructions.InsnType
import jadx.core.dex.instructions.args.InsnArg
import jadx.core.dex.instructions.args.InsnWrapArg
import jadx.core.dex.instructions.args.RegisterArg
import jadx.core.dex.instructions.args.LiteralArg
import jadx.core.dex.instructions.args.ArgType

val jadx = getJadxInstance()

val decodeMthSignature = "com.meituan.android.pin.dydx.StringEncryptUtils.decode(Ljava/lang/String;)Ljava/lang/String;"
val decodeToIntMthSignature = "com.meituan.android.pin.dydx.StringEncryptUtils.decodeToInt(Ljava/lang/String;)I"

jadx.replace.insns { mth, insn ->
    if (insn is InvokeNode && insn.callMth.rawFullId == decodeMthSignature) {
        val str = getConstStr(insn.getArg(0))
        if (str != null) {
            val resultStr = decode(str)
            log.info { "Decode '$str' to '$resultStr' in $mth" }
            return@insns ConstStringNode(resultStr)
        }
    } else if (insn is InvokeNode && insn.callMth.rawFullId == decodeToIntMthSignature) {
        val str = getConstStr(insn.getArg(0))
        if (str != null) {
            val resultInt = decodeToInt(str)
            log.info { "DecodeToInt '$str' to '$resultInt' in $mth" }
            val constInsn = InsnNode(InsnType.CONST, 1)
            constInsn.addArg(LiteralArg.make(resultInt.toLong(), ArgType.INT))
            return@insns constInsn
        }
    }
    null
}

fun getConstStr(arg: InsnArg): String? {
    val insn = when (arg) {
        is InsnWrapArg -> arg.wrapInsn
        is RegisterArg -> arg.assignInsn
        else -> null
    }
    if (insn is ConstStringNode) {
        return insn.string
    }
    return null
}

fun decode(str: String): String {
    if (str.isEmpty()) {
        return ""
    }
    
    val index = getIndex(str[0])
    val strJ = b_j(str, getIndex(str[1]), 2)
    val sb = StringBuilder(strJ.length)
    
    for (i in strJ.indices) {
        sb.append((getIndex(strJ[i]) + 33).toChar())
    }
    
    val length = sb.length
    var i2 = length - 2
    
    if (sb[i2] != '|') {
        i2 = length - 1
        if (sb[i2] != '|') {
            i2 = length
        }
    }
    
    val bArr = ByteArray((i2 * 6) / 8)
    var i3 = 0
    var i4 = 0
    
    while (i3 < length - 4) {
        val index2 = ((getIndex(sb[i3]) - index) shl 18) or 
                     ((getIndex(sb[i3 + 1]) - index) shl 12) or 
                     ((getIndex(sb[i3 + 2]) - index) shl 6) or 
                     (getIndex(sb[i3 + 3]) - index)
        
        var i5 = i4 + 1
        bArr[i4] = (index2 shr 16).toByte()
        var i6 = i5 + 1
        bArr[i5] = ((index2 shr 8) and 255).toByte()
        bArr[i6] = (index2 and 255).toByte()
        
        i3 += 4
        i4 = i6 + 1
    }
    
    val cCharAt = sb[i3 + 2]
    val cCharAt2 = sb[i3 + 3]
    
    val index3 = ((getIndex(sb[i3 + 1]) - index) shl 12) or 
                 ((getIndex(sb[i3]) - index) shl 18) or 
                 ((if (cCharAt == '|') 0 else getIndex(cCharAt) - index) shl 6) or 
                 (if (cCharAt2 != '|') getIndex(cCharAt2) - index else 0)
    
    var i7 = i4 + 1
    bArr[i4] = (index3 shr 16).toByte()
    
    if (cCharAt != '|') {
        bArr[i7] = ((index3 shr 8) and 255).toByte()
        i7++
    }
    
    if (cCharAt2 != '|') {
        bArr[i7] = (index3 and 255).toByte()
    }
    
    return String(bArr)
}

fun getIndex(c: Char): Int {
    val i = c - '!'
    val i2 = i / 19
    return when (i2) {
        0 -> i + 57
        1, 2 -> i
        3 -> i - 57
        4 -> i
        else -> 0
    }
}

fun b_j(str: String, i: Int, i2: Int): String {
    return str.substring(i2, str.length - i)
}

fun decodeToInt(str: String): Int {
    return try {
        decode(str).toInt()
    } catch (e: NumberFormatException) {
        throw IllegalArgumentException("Invalid encoded string: $str", e)
    }
}