# apkDeobfuscation

## Preparation

- JDK environment at least version 1.8 (Recommend JDK version 17)
- python3

## Usage

1. use `jadx/jadx-gui` to load the target file, such as `.apk` or `.dex`
2. use `frida` or `unidbg` to run the decryption server
3. load the jadx-script and decrypt

## Development

### First case: local decryption.

> [replace_method_call.jadx.kts](https://github.com/skylot/jadx/blob/1a642108ef7fe0322f343187a9c21f7b3658aafb/jadx-plugins/jadx-script/examples/scripts/replace_method_call.jadx.kts)

```kotlin
/**
 * Replace method call with calculated result.
 * Useful for custom string deobfuscation.
 *
 * Example for sample from issue https://github.com/skylot/jadx/issues/1251
 */

import jadx.core.dex.instructions.ConstStringNode
import jadx.core.dex.instructions.InvokeNode
import jadx.core.dex.instructions.args.InsnArg
import jadx.core.dex.instructions.args.InsnWrapArg
import jadx.core.dex.instructions.args.RegisterArg

val jadx = getJadxInstance()

val mthSignature = "com.xshield.aa.iIiIiiiiII(Ljava/lang/String;)Ljava/lang/String;"

jadx.replace.insns { mth, insn ->
	if (insn is InvokeNode && insn.callMth.rawFullId == mthSignature) {
		val str = getConstStr(insn.getArg(0))
		if (str != null) {
			val resultStr = decode(str)
			log.info { "Decode '$str' to '$resultStr' in $mth" }
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

/**
 * Decompiled method, automatically converted to Kotlin by IntelliJ Idea
 */
fun decode(str: String): String {
	val length = str.length
	val cArr = CharArray(length)
	var i = length - 1
	while (i >= 0) {
		val i2 = i - 1
		cArr[i] = (str[i].code xor 'z'.code).toChar()
		if (i2 < 0) {
			break
		}
		i = i2 - 1
		cArr[i2] = (str[i2].code xor '\u000c'.code).toChar()
	}
	return String(cArr)
}

```

### Second case: remote decryption.

```kotlin
/**
 * Replace method call with requested result.
 * Useful for custom string deobfuscation.
 *
 */

// That is the path relative to the jadx/bin execution directory, or it can be changed to an absolute path.
@file:DependsOn("../external_library/okhttp-4.11.0.jar")
@file:DependsOn("../external_library/okio-jvm-3.2.0.jar")
@file:DependsOn("../external_library/okio-3.2.0.jar")

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

val mthSignature = "kotlinx.android.extensionss.qz.b(Ljava/lang/String;)Ljava/lang/String;"

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
```

## Thanks

- [jadx](https://github.com/skylot/jadx/)
- [frida](https://github.com/frida/frida)