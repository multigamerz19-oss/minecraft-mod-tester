package com.modtester.audit

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                ModTesterScreen()
            }
        }
    }
}

@Composable
fun ModTesterScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var isScanning by remember { mutableStateOf(false) }
    var selectedFileUri by remember { mutableStateOf<Uri?>(null) }
    var findings by remember { mutableStateOf<List<String>>(emptyList()) }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let {
            selectedFileUri = it
            isScanning = true
            scope.launch {
                val results = withContext(Dispatchers.IO) {
                    ModScannerEngine.scanJarFromUri(context, it)
                }
                findings = results
                isScanning = false
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("ModAudit: Minecraft Inspector", style = MaterialTheme.typography.titleLarge)
        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = { filePicker.launch(arrayOf("*/*")) },
            enabled = !isScanning
        ) {
            Text(if (isScanning) "Analyzing Mod..." else "Select .jar Mod File")
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (isScanning) {
            CircularProgressIndicator()
        } else if (selectedFileUri != null) {
            if (findings.isEmpty()) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("✓ Mod is clean! No suspicious bytecode or missing textures detected.", modifier = Modifier.padding(16.dp))
                }
            } else {
                Text("Issues Detected (${findings.size}):", style = MaterialTheme.typography.titleMedium)
                Spacer(modifier = Modifier.height(8.dp))
                LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(findings) { issue ->
                        Card(
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 4.dp)
                        ) {
                            Text(issue, modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }
    }
}
