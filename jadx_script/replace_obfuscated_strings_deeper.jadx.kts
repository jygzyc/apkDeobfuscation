/**
 * Replace method call with requested result deeper.
 * Useful for custom string deobfuscation.
 *
 */
@file:DependsOn("com.squareup.okhttp3:okhttp:4.11.0")

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response

import jadx.core.dex.instructions.ConstStringNode
import jadx.core.dex.instructions.InvokeNode
import jadx.core.dex.instructions.args.InsnArg
import jadx.core.dex.instructions.args.InsnWrapArg
import jadx.core.dex.instructions.args.RegisterArg

val jadx = getJadxInstance()

val mthSignature = "kotlinx.android.extensionss.cg.b(Ljava/lang/String;)Ljava/lang/String;"

jadx.replace.insns { mth, insn ->
	if (insn is InvokeNode && insn.callMth.rawFullId == mthSignature) {
		val str = getConstStr(insn.getArg(0))
		if (str != null) {
			val resultStr = decrypt(mthSignature, str)
			log.info { "Decrypt '$str' to '$resultStr' in $mth" }
			return@insns ConstStringNode(resultStr)
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

fun decrypt(mthSignature: String, param: String): String?{
	val client = OkHttpClient()
    val json = """
        {
            "method": "${mthSignature}",
			"param": "${param}"
        }
    """.trimIndent()

	val requestBody = json.toRequestBody("application/json; charset=utf-8".toMediaType())

	val request = Request.Builder()
        .url("http://127.0.0.1:5000/decrypt")
        .post(requestBody)
        .build()

    val response = client.newCall(request).execute()
	return response.body?.string().toString()
}