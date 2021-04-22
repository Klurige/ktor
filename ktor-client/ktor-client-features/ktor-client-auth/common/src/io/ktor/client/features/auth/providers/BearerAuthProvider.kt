/*
 * Copyright 2014-2020 JetBrains s.r.o and contributors. Use of this source code is governed by the Apache 2.0 license.
 */

package io.ktor.client.features.auth.providers

import io.ktor.client.call.*
import io.ktor.client.features.auth.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.auth.*
import kotlinx.atomicfu.*
import kotlinx.coroutines.*

/**
 * Add [BasicAuthProvider] to client [Auth] providers.
 */
public fun Auth.bearer(block: BearerAuthConfig.() -> Unit) {
    with(BearerAuthConfig().apply(block)) {
        providers.add(BearerAuthProvider(_refreshTokens, _loadTokens, true, realm))
    }
}

public data class BearerTokens(
    val accessToken: String,
    val refreshToken: String
)

/**
 * [DigestAuthProvider] configuration.
 */
public class BearerAuthConfig {
    internal var _refreshTokens: suspend (call: HttpClientCall) -> BearerTokens? = { null }
    internal var _loadTokens: suspend () -> BearerTokens? = { null }

    public var realm: String? = null

    public fun refreshTokens(block: suspend (call: HttpClientCall) -> BearerTokens?) {
        _refreshTokens = block
    }

    public fun loadTokens(block: suspend () -> BearerTokens?) {
        _loadTokens = block
    }
}

/**
 * Client digest [AuthProvider].
 */
public class BearerAuthProvider(
    public val refreshTokens: suspend (call: HttpClientCall) -> BearerTokens?,
    public val loadTokens: suspend () -> BearerTokens?,
    override val sendWithoutRequest: Boolean = true,
    private val realm: String?
) : AuthProvider {
    private val cachedBearerTokens: AtomicRef<CompletableDeferred<BearerTokens?>> =
        atomic(CompletableDeferred<BearerTokens?>().apply {
            complete(null)
        })

    /**
     * Check if current provider is applicable to the request.
     */
    override fun isApplicable(auth: HttpAuthHeader): Boolean {
        if (auth.authScheme != AuthScheme.Bearer) return false
        if (realm == null) return true
        if (auth !is HttpAuthHeader.Parameterized) return false

        return auth.parameter("realm") == realm
    }

    /**
     * Add authentication method headers and creds.
     */
    override suspend fun addRequestHeaders(request: HttpRequestBuilder) {
        val token = loadToken() ?: return

        request.headers {
            val tokenValue = "Bearer ${token.accessToken}"
            if (contains(HttpHeaders.Authorization)) {
                remove(HttpHeaders.Authorization)
            }
            append(HttpHeaders.Authorization, tokenValue)
        }
    }

    public override suspend fun refreshToken(call: HttpClientCall): Boolean = setToken { refreshTokens(call) } != null

    public fun clearToken() {
        cachedBearerTokens.value = CompletableDeferred<BearerTokens?>().apply { complete(null) }
    }

    private suspend fun loadToken(): BearerTokens? {
        val cachedToken = cachedBearerTokens.value.await()
        if (cachedToken != null) return cachedToken

        return setToken(loadTokens)
    }

    private suspend fun setToken(block: suspend () -> BearerTokens?): BearerTokens? {
        val old = cachedBearerTokens.value
        val deferred = CompletableDeferred<BearerTokens?>()
        if (!cachedBearerTokens.compareAndSet(old, deferred)) {
            return cachedBearerTokens.value.await()
        }

        try {
            val token = block()
            deferred.complete(token)
            return token
        } catch (cause: Throwable) {
            deferred.completeExceptionally(cause)
            throw cause
        }
    }
}
