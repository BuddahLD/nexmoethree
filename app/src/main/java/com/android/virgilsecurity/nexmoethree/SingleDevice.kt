/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.android.virgilsecurity.nexmoethree

import android.util.Log
import com.nexmo.sdk.conversation.client.*
import com.nexmo.sdk.conversation.client.event.EventType
import com.nexmo.sdk.conversation.client.event.NexmoAPIError
import com.nexmo.sdk.conversation.client.event.RequestHandler
import com.virgilsecurity.android.ethree.kotlin.interaction.EThree
import com.virgilsecurity.sdk.crypto.PublicKey


/**
 * . _  _
 * .| || | _
 * -| || || |   Created by:
 * .| || || |-  Danylo Oliinyk
 * ..\_  || |   on
 * ....|  _/    12/22/18
 * ...-| | \    at Virgil Security
 * ....|_|-
 */

/**
 * Integration
 */

private var eThree: EThree? = null
private val subscriptions: List<Subscription<*>> = listOf()

private fun singleDevice() {

    // Init EThree SDK
    EThree.initialize(context, virgilToken, object : EThree.OnResultListener<EThree> {
        override fun onSuccess(result: EThree) {
            eThree = result
        }

        override fun onError(throwable: Throwable) {
            // TODO Implement body or it will be empty ):
        }
    })

    // Init Nexmo SDK
    val conversationClient = ConversationClient.ConversationClientBuilder().context(context).build()

    // Wait for EThree registration
    val onRegisterListener =
        object : EThree.OnCompleteListener {
            override fun onSuccess() {
                nexmoLogin(conversationClient)
            }

            override fun onError(throwable: Throwable) {
                Log.d("TAG", "onSent: " + throwable.message)
            }
        }

    // Any authorization system which will determine whether this new user or not
    val yourAuthorization = object : YourAuthorization {
        override fun signIn() {
            nexmoLogin(conversationClient)
        }

        override fun signUp() {
            eThree!!.register(onRegisterListener)
        }
    }

    // Call what you need - sign in
    yourAuthorization.signIn()
    // Or sign up
    yourAuthorization.signUp()
}

private fun sendMessage(conversation: Conversation, body: String) {
    conversation.sendText(body, object : RequestHandler<Event> {
        override fun onSuccess(event: Event) {
            if (event.type == EventType.TEXT) {
                Log.d("TAG", "onSent: " + (event as Text).text)
            }
        }

        override fun onError(apiError: NexmoAPIError) {
            Log.d("TAG", "onSent: " + apiError.message)
        }
    })
}

private fun addListener(conversation: Conversation) {
    conversation.messageEvent().add { message -> showMessage(message) }.addTo(subscriptions)
}

private fun removeListeners() {
    subscriptions.forEach { it.unsubscribe() }
}

private fun showMessage(message: Event) {
    if (message.type == EventType.TEXT) {
        val text = message as Text
        // Wait for users lookup
        val lookupListener =
            object : EThree.OnResultListener<Map<String, PublicKey>> {
                override fun onSuccess(result: Map<String, PublicKey>) {
                    // Decrypt message and verify that it was really sent by the sender
                    val decryptedMessage = eThree!!.decrypt(text.text, result[message.member.name])
                }

                override fun onError(throwable: Throwable) {
                    Log.d("TAG", "onSent: " + throwable.message)
                }
            }

        // Lookup for the sender's public key
        eThree!!.lookupPublicKeys(listOf(message.member.name) , lookupListener)
    }
}

private fun nexmoLogin(conversationClient: ConversationClient) {
    val conversation = conversationClient.getConversation(conversationId)
    // Listen for incoming messages
    addListener(conversation)

    // Wait for users lookup
    val lookupListener =
        object : EThree.OnResultListener<Map<String, PublicKey>> {
            override fun onSuccess(result: Map<String, PublicKey>) {
                // Encrypt message for all recipients
                val encryptedMessage = eThree.encrypt(someMessage, result.values.toList())
                sendMessage(conversation, encryptedMessage)
            }

            override fun onError(throwable: Throwable) {
                Log.d("TAG", "onSent: " + throwable.message)
            }
        }

    conversationClient.login(userToken, object : RequestHandler<User> {
        override fun onSuccess(user: User) {
            // Lookup for conversation members public keys except current user
            eThree!!.lookupPublicKeys(conversation.members
                .filter { member -> member.name != currentUserName }
                .map { member -> member.name },
                lookupListener
            )
        }

        override fun onError(apiError: NexmoAPIError) {
            Log.d("TAG", "onSent: " + apiError.message)
        }
    })
}

private interface YourAuthorization {
    fun signIn()

    fun signUp()
}
  