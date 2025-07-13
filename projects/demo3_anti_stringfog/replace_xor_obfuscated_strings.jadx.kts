import jadx.core.dex.instructions.ConstStringNode
import jadx.core.dex.instructions.FillArrayInsn
import jadx.core.dex.instructions.FilledNewArrayNode
import jadx.core.dex.instructions.InvokeNode
import jadx.core.dex.instructions.NewArrayNode
import jadx.core.dex.instructions.args.InsnArg
import jadx.core.dex.instructions.args.InsnWrapArg
import jadx.core.dex.instructions.args.LiteralArg
import jadx.core.dex.instructions.args.PrimitiveType
import jadx.core.dex.instructions.args.RegisterArg
import java.nio.charset.StandardCharsets

val jadx = getJadxInstance()

// TODO: Replace with the full signature of the method to be replaced
val mthSignature = "com.github.megatronking.stringfog.sample1.StringFog.decrypt([B[B)Ljava/lang/String;"

jadx.replace.insns { mth, insn ->
    if (insn is InvokeNode && insn.callMth.rawFullId == mthSignature) {
        if (insn.argsCount == 2) {
            val data = getByteArray(insn.getArg(0))
            val key = getByteArray(insn.getArg(1))
            if (data != null && key != null) {
                val resultStr = decrypt(data, key)
                log.info { "Decrypted string for $mth" }
                return@insns ConstStringNode(resultStr)
            }
        }
    }
    null
}

fun getByteArray(arg: InsnArg): ByteArray? {
    val assignInsn = when (arg) {
        is InsnWrapArg -> arg.wrapInsn
        is RegisterArg -> arg.assignInsn
        else -> return null
    }

    // Case 1: Array created and filled in one instruction (filled-new-array)
    if (assignInsn is FilledNewArrayNode) {
        if (assignInsn.elemType.primitiveType == PrimitiveType.BYTE) {
            val bytes = ByteArray(assignInsn.argsCount)
            for (i in 0 until assignInsn.argsCount) {
                val literalArg = assignInsn.getArg(i) as? LiteralArg
                bytes[i] = literalArg?.literal?.toByte() ?: return null
            }
            return bytes
        }
    }

    // Case 2: Array created with new-array and filled with fill-array-data
    if (assignInsn is NewArrayNode) {
        val resultReg = assignInsn.result ?: return null
        val sVar = resultReg.sVar ?: return null
        if (sVar.useList.size == 1) {
            val parentInsn = sVar.useList[0].parentInsn
            if (parentInsn is FillArrayInsn) {
                val elemType = parentInsn.elementType
                if (elemType.primitiveType == PrimitiveType.BYTE) {
                    val literalArgs = parentInsn.getLiteralArgs(elemType)
                    val bytes = ByteArray(literalArgs.size)
                    for (i in literalArgs.indices) {
                        bytes[i] = literalArgs[i].literal.toByte()
                    }
                    return bytes
                }
            }
        }
    }
    return null
}

fun decrypt(data: ByteArray, key: ByteArray): String {
    return String(xor(data, key), StandardCharsets.UTF_8)
}

fun xor(data: ByteArray, key: ByteArray): ByteArray {
    val len = data.size
    val lenKey = key.size
    val result = data.copyOf() // Create a copy to avoid modifying the original array
    var i = 0
    var j = 0
    while (i < len) {
        if (j >= lenKey) {
            j = 0
        }
        result[i] = (result[i].toInt() xor key[j].toInt()).toByte()
        i++
        j++
    }
    return result
}
