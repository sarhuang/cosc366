/* Name: Sarah Huang
 * Date: 2/25/2023
 * Program: IterativeHasher.cs
 * Purpose: For this hasher, you will be using SHA256 to hash passwords.
 */

using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using iterative SHA256 hashing.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] digest = new byte[32];

        // todo: Use 100,000 iterations and the SHA256 algorithm.
        byte[] passwordBytes = Utils.Encoding.GetBytes(password);
        byte[] saltPasswordBytes = new byte[passwordBytes.Length + salt.Length];
        Buffer.BlockCopy(salt, 0, saltPasswordBytes, 0, salt.Length);
        Buffer.BlockCopy(passwordBytes, 0, saltPasswordBytes, salt.Length, passwordBytes.Length);

        //Only the first iteration incorporates salt
        digest = SHA256.HashData(saltPasswordBytes);
        for (int i = 1; i < 100000; i++){
            digest = SHA256.HashData(digest);
        }
        // todo: Encode as "Base64(salt):Base64(digest)"
        return (Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(digest));
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword) {
        // todo: Verify that the given password matches the hashedPassword (as originally encoded by HashPassword)
        
        //Real true values
        string[] hasedPasswordHalves = hashedPassword.Split(':');
        byte[] salt = Convert.FromBase64String(hasedPasswordHalves[0]);
        byte[] digest = Convert.FromBase64String(hasedPasswordHalves[1]);
        
        //Need to calculate
        byte[] computedDigest = new byte[32];
        byte[] providedPasswordBytes = Utils.Encoding.GetBytes(providedPassword);
        byte[] saltedPasswordBytes = new byte[providedPasswordBytes.Length + salt.Length];

        Buffer.BlockCopy(salt, 0, saltedPasswordBytes, 0, salt.Length);
        Buffer.BlockCopy(providedPasswordBytes, 0, saltedPasswordBytes, 32, providedPasswordBytes.Length);
        
        computedDigest = SHA256.HashData(saltedPasswordBytes);
        for (int i = 1; i < 100000; i++){
            computedDigest = SHA256.HashData(computedDigest);
        }

        if (computedDigest.SequenceEqual(digest)){
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }
}