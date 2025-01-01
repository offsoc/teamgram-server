package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "errors"
    "io"
)

// EncryptMessage encrypts the given message using AES encryption.
func EncryptMessage(message, key string) (string, error) {
    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, aes.BlockSize+len(message))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return "", err
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(message))

    return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts the given encrypted message using AES encryption.
func DecryptMessage(encryptedMessage, key string) (string, error) {
    ciphertext, err := base64.URLEncoding.DecodeString(encryptedMessage)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher([]byte(key))
    if err != nil {
        return "", err
    }

    if len(ciphertext) < aes.BlockSize {
        return "", errors.New("ciphertext too short")
    }

    iv := ciphertext[:aes.BlockSize]
    ciphertext = ciphertext[aes.BlockSize:]

    stream := cipher.NewCFBDecrypter(block, iv)
    stream.XORKeyStream(ciphertext, ciphertext)

    return string(ciphertext), nil
}

// EncryptVoiceMessage encrypts the given voice message using AES encryption.
func EncryptVoiceMessage(voiceMessage, key string) (string, error) {
    return EncryptMessage(voiceMessage, key)
}

// DecryptVoiceMessage decrypts the given encrypted voice message using AES encryption.
func DecryptVoiceMessage(encryptedVoiceMessage, key string) (string, error) {
    return DecryptMessage(encryptedVoiceMessage, key)
}

// EncryptVideoMessage encrypts the given video message using AES encryption.
func EncryptVideoMessage(videoMessage, key string) (string, error) {
    return EncryptMessage(videoMessage, key)
}

// DecryptVideoMessage decrypts the given encrypted video message using AES encryption.
func DecryptVideoMessage(encryptedVideoMessage, key string) (string, error) {
    return DecryptMessage(encryptedVideoMessage, key)
}

// EncryptClientServerMessage encrypts the given message using AES encryption for client-server communication.
func EncryptClientServerMessage(message, key string) (string, error) {
    return EncryptMessage(message, key)
}

// DecryptClientServerMessage decrypts the given encrypted message using AES encryption for client-server communication.
func DecryptClientServerMessage(encryptedMessage, key string) (string, error) {
    return DecryptMessage(encryptedMessage, key)
}

// EncryptSecretChatMessage encrypts the given message using AES encryption for secret chats.
func EncryptSecretChatMessage(message, key string) (string, error) {
    return EncryptMessage(message, key)
}

// DecryptSecretChatMessage decrypts the given encrypted message using AES encryption for secret chats.
func DecryptSecretChatMessage(encryptedMessage, key string) (string, error) {
    return DecryptMessage(encryptedMessage, key)
}

// EncryptVoiceCall encrypts the given voice call data using AES encryption.
func EncryptVoiceCall(voiceCallData, key string) (string, error) {
    return EncryptMessage(voiceCallData, key)
}

// DecryptVoiceCall decrypts the given encrypted voice call data using AES encryption.
func DecryptVoiceCall(encryptedVoiceCallData, key string) (string, error) {
    return DecryptMessage(encryptedVoiceCallData, key)
}

// EncryptVideoCall encrypts the given video call data using AES encryption.
func EncryptVideoCall(videoCallData, key string) (string, error) {
    return EncryptMessage(videoCallData, key)
}

// DecryptVideoCall decrypts the given encrypted video call data using AES encryption.
func DecryptVideoCall(encryptedVideoCallData, key string) (string, error) {
    return DecryptMessage(encryptedVideoCallData, key)
}

// EncryptGroupCall encrypts the given group call data using AES encryption.
func EncryptGroupCall(groupCallData, key string) (string, error) {
    return EncryptMessage(groupCallData, key)
}

// DecryptGroupCall decrypts the given encrypted group call data using AES encryption.
func DecryptGroupCall(encryptedGroupCallData, key string) (string, error) {
    return DecryptMessage(encryptedGroupCallData, key)
}

// EncryptChannelCall encrypts the given channel call data using AES encryption.
func EncryptChannelCall(channelCallData, key string) (string, error) {
    return EncryptMessage(channelCallData, key)
}

// DecryptChannelCall decrypts the given encrypted channel call data using AES encryption.
func DecryptChannelCall(encryptedChannelCallData, key string) (string, error) {
    return DecryptMessage(encryptedChannelCallData, key)
}

// EncryptScreenSharing encrypts the given screen sharing data using AES encryption.
func EncryptScreenSharing(screenSharingData, key string) (string, error) {
    return EncryptMessage(screenSharingData, key)
}

// DecryptScreenSharing decrypts the given encrypted screen sharing data using AES encryption.
func DecryptScreenSharing(encryptedScreenSharingData, key string) (string, error) {
    return DecryptMessage(encryptedScreenSharingData, key)
}

// EncryptRealTimeTranslation encrypts the given real-time translation data using AES encryption.
func EncryptRealTimeTranslation(realTimeTranslationData, key string) (string, error) {
    return EncryptMessage(realTimeTranslationData, key)
}

// DecryptRealTimeTranslation decrypts the given encrypted real-time translation data using AES encryption.
func DecryptRealTimeTranslation(encryptedRealTimeTranslationData, key string) (string, error) {
    return DecryptMessage(encryptedRealTimeTranslationData, key)
}
