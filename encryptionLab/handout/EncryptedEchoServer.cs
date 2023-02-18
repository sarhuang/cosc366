/* Name: Sarah Huang
 * Date: 2/17/2023
 * Program: EncryptedEchoServer.cs
 * Purpose: An echo server receives string from clients and simply echos those strings back to the clients. 
 */

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

internal sealed class EncryptedEchoServer : EchoServerBase {

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoServer> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoServer>()!;

    /// <inheritdoc />
    internal EncryptedEchoServer(ushort port) : base(port) { }

    // todo: Step 1: Generate a RSA key (2048 bits) for the server.
    RSA rsa = RSA.Create(2048);  


    /// <inheritdoc />
    public override string GetServerHello() {
        // todo: Step 1: Send the public key to the client in PKCS#1 format.        
        // Encode using Base64: Convert.ToBase64String
        return Convert.ToBase64String(rsa.ExportRSAPublicKey());        
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        var message = JsonSerializer.Deserialize<EncryptedMessage>(input);

        // todo: Step 2: Decrypt the message using hybrid encryption.
        Aes aes = Aes.Create();
        aes.Key = rsa.Decrypt(message.AesKeyWrap, RSAEncryptionPadding.OaepSHA256);
        aes.IV = message.AESIV;
        byte[] decryptedMessage = aes.DecryptCbc(message.Message, aes.IV, PaddingMode.PKCS7);

        // todo: Step 3: Verify the HMAC. Use the SHA256 variant of the HMAC algorithm.
        // Throw an InvalidSignatureException if the received hmac is bad.
        byte[] decryptedHmacKey = rsa.Decrypt(message.HMACKeyWrap, RSAEncryptionPadding.OaepSHA256);
        byte[] calculatedHmacHash = HMACSHA256.HashData(decryptedHmacKey, decryptedMessage);
        if(!calculatedHmacHash.SequenceEqual(message.HMAC)){
            throw new InvalidSignatureException("Received HMAC is invalid");
        }
        
        // todo: Step 3: Return the decrypted and verified message from the server.
        return Settings.Encoding.GetString(decryptedMessage);
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Sign the message.
        // Use PSS padding with SHA256.
        byte[] signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // todo: Step 2: Put the data in an SignedMessage object and serialize to JSON.
        // Return that JSON.
        var message = new SignedMessage(data, signature);
        return JsonSerializer.Serialize(message);
    }
}