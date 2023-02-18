/* Name: Sarah Huang
 * Date: 2/17/2023
 * Program: EncryptedEchoClient.cs
 * Purpose: Reads input from the command line, sends that input to the echo server,
            and prints to the command line anything it receives from the server.
 */

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase {

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) { }
    RSA rsa = RSA.Create(2048);


    /// <inheritdoc />
    public override void ProcessServerHello(string message) {
        //  todo: Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
        try{
            var publicKey = Convert.FromBase64String(message);
            rsa.ImportRSAPublicKey(publicKey, out int bytesRead);
            if(bytesRead < 256){  //2048 bits = 256 bytes
                throw new CryptographicException("Received key is invalid");
            }
        }catch(CryptographicException e){
            Console.WriteLine("Exception caught: {0}", e);
        }
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);
        // todo: Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        Aes aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();
        byte[] encryptedMessage = aes.EncryptCbc(data, aes.IV, PaddingMode.PKCS7);

        // todo: Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        byte[] randomHmacKey = RandomNumberGenerator.GetBytes(32);
        byte[] hmacHash = HMACSHA256.HashData(randomHmacKey, data);

        // todo: Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        byte[] aesEncryptKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
        byte[] hmacEncryptKey = rsa.Encrypt(randomHmacKey, RSAEncryptionPadding.OaepSHA256);

        // todo: Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        var message = new EncryptedMessage(aesEncryptKey, aes.IV, encryptedMessage, hmacEncryptKey, hmacHash);
        return JsonSerializer.Serialize(message);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        bool signatureMatching = rsa.VerifyData(signedMessage.Message, signedMessage.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        if(!signatureMatching){
            throw new InvalidSignatureException("Signature is invalid");
        }

        // todo: Step 3: Return the message from the server.
        return Settings.Encoding.GetString(signedMessage.Message);
    }
}