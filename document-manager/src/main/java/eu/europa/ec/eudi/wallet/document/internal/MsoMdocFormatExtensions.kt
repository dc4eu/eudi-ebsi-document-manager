/*
 * Copyright (c) 2024 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package eu.europa.ec.eudi.wallet.document.internal

import COSE.Message
import COSE.MessageTag
import COSE.Sign1Message
import com.android.identity.mdoc.credential.MdocCredential
import com.android.identity.mdoc.mso.MobileSecurityObjectParser
import com.android.identity.mdoc.mso.StaticAuthDataGenerator
import com.android.identity.securearea.CreateKeySettings
import com.android.identity.securearea.SecureArea
import com.upokecenter.cbor.CBORObject
import eu.europa.ec.eudi.wallet.document.UnsignedDocument
import eu.europa.ec.eudi.wallet.document.format.MsoMdocFormat
import io.ktor.client.HttpClient
import io.ktor.client.engine.android.Android
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import io.ktor.http.isSuccess
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.io.IOException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import java.util.concurrent.CountDownLatch
import com.android.identity.document.Document as IdentityDocument

@Serializable
private data class VerifyToken(
    val token: String
)

@JvmSynthetic
internal fun addDataFromResponse(nameSpaces: CBORObject, response: String) {
    val pidNamespace = nameSpaces["eu.europa.ec.eudi.pid.1"]
    if (pidNamespace != null && !pidNamespace.isNull) {
        // Create new array with the existing data
        val newPidArray = CBORObject.NewArray()
        // Add the existing element first
        newPidArray.Add(pidNamespace[0])

        // Parse the response
        val json = Json { ignoreUnknownKeys = true }
        val jsonElement = json.parseToJsonElement(response)

        // Navigate to eu.europa.ec.eudi.pid.1 data
        val pidData = jsonElement.jsonObject["vcDocument"]
            ?.jsonObject?.get("credentialSubject")
            ?.jsonObject?.get("eu.europa.ec.eudi.pid.1")
            ?.jsonObject

        if (pidData != null) {
            var currentDigestId = 1

            for ((key, value) in pidData) {
                val docData = CBORObject.NewMap()
                docData.Set("elementIdentifier", key)
                docData.Set("elementValue", CBORObject.FromObject((value as JsonPrimitive).contentOrNull))
                docData.Set("digestID", currentDigestId++)
                newPidArray.Add(CBORObject.FromObjectAndTag(docData.EncodeToBytes(), 24))
            }
        }

        // Update the nameSpaces with the modified array
        nameSpaces.Set("eu.europa.ec.eudi.pid.1", newPidArray)
    }
}

@JvmSynthetic
internal fun MsoMdocFormat.createCredential(
    domain: String,
    identityDocument: IdentityDocument,
    secureArea: SecureArea,
    createKeySettings: CreateKeySettings,
): MdocCredential {
    return MdocCredential(
        document = identityDocument,
        asReplacementFor = null,
        domain = domain,
        secureArea = secureArea,
        createKeySettings = createKeySettings,
        docType = docType
    )
}

fun runBlockingForResult(block: suspend () -> String): String {
    var result: String? = null
    var error: Throwable? = null
    val latch = CountDownLatch(1)

    CoroutineScope(Dispatchers.IO).launch {
        try {
            result = block()
        } catch (e: Throwable) {
            error = e
        } finally {
            latch.countDown()
        }
    }

    latch.await()
    error?.let { throw it }
    return result!!
}

@JvmSynthetic
internal fun MsoMdocFormat.storeIssuedDocument(
    unsignedDocument: UnsignedDocument,
    identityDocument: IdentityDocument,
    data: ByteArray,
    checkDevicePublicKey: Boolean
) {
    val issuerSigned = CBORObject.DecodeFromBytes(data)
    val issuerAuthBytes = issuerSigned["issuerAuth"].EncodeToBytes()
    val issuerAuth = Message.DecodeFromBytes(issuerAuthBytes, MessageTag.Sign1) as Sign1Message
    val msoBytes = issuerAuth.GetContent().getEmbeddedCBORObject().EncodeToBytes()
    val mso = MobileSecurityObjectParser(msoBytes).parse()
    if (mso.deviceKey != unsignedDocument.keyInfo.publicKey) {
        val msg = "Public key in MSO does not match the one in the request"
        if (checkDevicePublicKey) {
            throw IllegalArgumentException(msg)
        }
    }

    val nameSpaces = issuerSigned["nameSpaces"]
    val pidNamespace = nameSpaces["eu.europa.ec.eudi.pid.1"]
    if (pidNamespace != null && !pidNamespace.isNull) {
        val vcToken = pidNamespace[0].getEmbeddedCBORObject()["elementValue"].AsString()
        val response = runBlockingForResult { verifyVcToken(vcToken) }
        addDataFromResponse(nameSpaces, response)
    }

    val digestIdMapping = nameSpaces.toDigestIdMapping()
    val staticAuthData = StaticAuthDataGenerator(digestIdMapping, issuerAuthBytes)
        .generate()
    identityDocument.pendingCredentials.forEach { credential ->
        credential.certify(staticAuthData, mso.validFrom, mso.validUntil)
    }

    identityDocument.nameSpacedData = nameSpaces.asNameSpacedData()
}

@JvmSynthetic
internal suspend fun verifyVcToken(vcToken: String): String {
    val client = HttpClient(Android) {
        install(ContentNegotiation) {
            json(Json {
                ignoreUnknownKeys = true
            })
        }
    }

    val EBSI_AGENT_ADDRESS = "https://snf-36159.ok-kno.grnetcloud.net/ebsi-agent"
    val url = "$EBSI_AGENT_ADDRESS/verify-vc"

    val response: HttpResponse = client.post(url) {
        contentType(ContentType.Application.Json)
        setBody(VerifyToken(vcToken))
    }

    if (!response.status.isSuccess()) {
        throw IOException("EUDI Wallet EBSI! Unexpected code ${response.status}, body: ${response.bodyAsText()}")
    }

    return response.bodyAsText()
}
