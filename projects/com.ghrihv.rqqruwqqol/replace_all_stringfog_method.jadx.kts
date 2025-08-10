/**
 * Replace all stringfog method call with calculated result.
 * Useful for custom string deobfuscation.
 *
 * Bug: This script only completely works when loading the application in first time.
 * If you have already loaded the application, you need to restart jadx-gui. 
 */

import jadx.core.dex.info.FieldInfo
import jadx.core.dex.instructions.ConstStringNode
import jadx.core.dex.instructions.FillArrayInsn
import jadx.core.dex.instructions.FilledNewArrayNode
import jadx.core.dex.instructions.IndexInsnNode
import jadx.core.dex.instructions.InsnType
import jadx.core.dex.instructions.InvokeNode
import jadx.core.dex.instructions.NewArrayNode
import jadx.core.dex.instructions.args.*
import jadx.core.dex.visitors.prepare.CollectConstValues
import java.nio.charset.StandardCharsets


val jadx = getJadxInstance()
val allClasses = jadx.classes
val fieldsMap = allClasses.flatMap { cls -> cls.fields.map { "${cls.fullName}.${it.getRawName()}" to it } }.toMap()

jadx.replace.insns { mth, insn ->
	if (insn is InvokeNode) {
		val mthFullId = insn.callMth.rawFullId
		if (mthFullId.endsWith("([B[B)Ljava/lang/String;")) {
			val data = getByteArray(insn.getArg(0))
			val key = getByteArray(insn.getArg(1))
			if (data != null && key != null) {
				val resultStr = stringFogDecrypt(data, key)
				log.info { "[*] $mthFullId for '${mth.name}': '$resultStr'" }
				return@insns ConstStringNode(resultStr)
			}
		}
	}
	null
}

private fun getFieldConstValue(fld: FieldInfo): Long? {
	val fieldKey = "${fld.declClass.fullName}.${fld.name}"
	val javaField = fieldsMap[fieldKey]
	return CollectConstValues.getFieldConstValue(javaField?.fieldNode)?.let { (it as? Number)?.toLong() }
}

private fun resolveConstValueFromArg(singleArg: InsnArg?): Long? {
	if (singleArg == null) return null
	return when (singleArg) {
		is LiteralArg -> singleArg.literal
		is InsnWrapArg -> {
			val insn = singleArg.wrapInsn
			if (insn != null && insn.type == InsnType.SGET && insn is IndexInsnNode) {
				val fieldInfo = insn.index as? FieldInfo ?: return null
				return getFieldConstValue(fieldInfo)
			} else {
				null
			}
		}
		else -> null
	}
}

fun getByteArray(arg: InsnArg): ByteArray? {
	val assignInsn = when (arg) {
		is InsnWrapArg -> arg.wrapInsn
		is RegisterArg -> arg.assignInsn
		else -> return null
	}

	// Case 1: filled-new-array
	if (assignInsn is FilledNewArrayNode && assignInsn.elemType.primitiveType == PrimitiveType.BYTE) {
		val bytes = ByteArray(assignInsn.argsCount)
		for (i in 0 until assignInsn.argsCount) {
			val value = resolveConstValueFromArg(assignInsn.getArg(i))
			if (value != null) {
				bytes[i] = value.toByte()
			} else {
				return null
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
