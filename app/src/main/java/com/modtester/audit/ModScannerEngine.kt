package com.modtester.audit

import android.content.Context
import android.net.Uri
import com.google.gson.JsonParser
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.regex.Pattern
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

object ModScannerEngine {

    private val DISCORD_WEBHOOK = Pattern.compile("discord(?:app)?\\.com/api/webhooks/\\d+/[A-Za-z0-9_-]+")
    private val IPV4_PORT = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}:\\d{2,5}\\b")
    private val DANGEROUS_METHODS = setOf(
        "java/lang/Runtime.exec",
        "java/lang/ProcessBuilder.<init>",
        "java/lang/System.load",
        "java/lang/System.loadLibrary",
        "java/net/URLClassLoader.<init>",
        "java/net/Socket.<init>"
    )

    fun scanJarFromUri(context: Context, uri: Uri): List<String> {
        val findings = mutableListOf<String>()
        val declaredTextures = mutableSetOf<String>()
        val modelRefs = mutableMapOf<String, List<String>>()

        try {
            context.contentResolver.openInputStream(uri)?.use { inputStream ->
                val zip = ZipInputStream(inputStream)
                var entry: ZipEntry? = zip.nextEntry

                while (entry != null) {
                    val name = entry.name

                    if (name.endsWith(".class")) {
                        val classBytes = zip.readBytes()
                        scanClassBytes(classBytes, name, findings)
                    } else if (name.startsWith("assets/") && name.endsWith(".png")) {
                        declaredTextures.add(name)
                    } else if (name.startsWith("assets/") && name.endsWith(".json") && name.contains("/models/")) {
                        val jsonReader = InputStreamReader(zip, StandardCharsets.UTF_8)
                        extractModelTextures(jsonReader, name, modelRefs)
                    }

                    zip.closeEntry()
                    entry = zip.nextEntry
                }
            }

            for ((model, textures) in modelRefs) {
                for (ref in textures) {
                    val expected = if (ref.contains(":")) {
                        val parts = ref.split(":", limit = 2)
                        "assets/${parts[0]}/textures/${parts[1]}.png"
                    } else {
                        "assets/minecraft/textures/$ref.png"
                    }

                    if (!declaredTextures.contains(expected)) {
                        findings.add("[MISSING ASSET] $model requires: $expected")
                    }
                }
            }

        } catch (e: Exception) {
            findings.add("[ERROR] Failed to parse mod file: ${e.message}")
        }

        return findings
    }

    private fun scanClassBytes(bytes: ByteArray, className: String, findings: MutableList<String>) {
        val cr = ClassReader(bytes)
        val cn = ClassNode()
        cr.accept(cn, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)

        for (mn in cn.methods) {
            for (insn in mn.instructions) {
                if (insn is MethodInsnNode) {
                    val sig = "${insn.owner}.${insn.name}"
                    if (DANGEROUS_METHODS.contains(sig)) {
                        findings.add("[HIGH-RISK CALL] $className -> ${mn.name}() calls $sig")
                    }
                }
                if (insn is LdcInsnNode && insn.cst is String) {
                    val s = insn.cst as String
                    if (DISCORD_WEBHOOK.matcher(s).find()) {
                        findings.add("[WEBHOOK/STEALER] $className: \"$s\"")
                    }
                    if (IPV4_PORT.matcher(s).find()) {
                        findings.add("[SUSPICIOUS IP] $className: \"$s\"")
                    }
                }
            }
        }
    }

    private fun extractModelTextures(reader: InputStreamReader, modelPath: String, modelRefs: MutableMap<String, List<String>>) {
        try {
            val json = JsonParser.parseReader(reader).asJsonObject
            if (json.has("textures")) {
                val list = mutableListOf<String>()
                val tex = json.getAsJsonObject("textures")
                for (entry in tex.entrySet()) {
                    val v = entry.value.asString
                    if (!v.startsWith("#")) list.add(v)
                }
                modelRefs[modelPath] = list
            }
        } catch (_: Exception) {}
    }
}
