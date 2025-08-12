/**
 * Replaces method calls with decrypted StringFog strings.
 * Credits to @skylot at https://github.com/skylot/jadx/discussions/2564
 * Author: Yves
 */

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
import jadx.core.dex.nodes.MethodNode
import jadx.core.utils.InsnUtils
import java.nio.charset.StandardCharsets

val jadx = getJadxInstance()

jadx.replace.insns { mth, insn ->
	if (insn is InvokeNode) {
		val mthFullId = insn.callMth.rawFullId
		if (mthFullId.endsWith("([B[B)Ljava/lang/String;")) {
			val data = getByteArray(mth, insn.getArg(0))
			val key = getByteArray(mth, insn.getArg(1))
			if (data != null && key != null) {
				val resultStr = stringFogDecrypt(data, key)
				log.info { "[*] $mthFullId in '${mth.name}': '$resultStr'" }
				return@insns ConstStringNode(resultStr)
			}
		}	
	}
	null
}

fun getByteArray(mth: MethodNode, arg: InsnArg): ByteArray? {
	val assignInsn = when (arg) {
		is InsnWrapArg -> arg.wrapInsn
		is RegisterArg -> arg.assignInsn
		else -> return null
	}

	// Case 1: filled-new-array
	if (assignInsn is FilledNewArrayNode && assignInsn.elemType.primitiveType == PrimitiveType.BYTE) {
		val bytes = ByteArray(assignInsn.argsCount)
		var i = 0
		assignInsn.arguments.forEach { elem ->
			val constVal = InsnUtils.getConstValueByArg(mth.root(), elem)
			if (constVal != null && constVal is LiteralArg) {
				bytes[i++] = constVal.literal.toByte()
			}
		}
		return bytes
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

fun stringFogDecrypt(data: ByteArray, key: ByteArray): String = String(xor(data, key), StandardCharsets.UTF_8)

fun xor(data: ByteArray, key: ByteArray): ByteArray {
	val len = data.size
	val lenKey = key.size
	val result = data.copyOf() // Create singleArg copy to avoid modifying the original array
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