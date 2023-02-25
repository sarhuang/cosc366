/* Name: Sarah Huang
 * Date: 2/25/2023
 * Program: Argon2idHasher.cs
 * Purpose: For this hasher, you will be using Argon2id  to hash passwords. 
 */

using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Konscious.Security.Cryptography;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by Argon2id.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
//https://github.com/kmaragon/Konscious.Security.Cryptography
/// </remarks>
internal class Argon2idHasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using Argon2id.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] digest = new byte[32];

        // todo: Degrees of parallelism is 8, iterations is 4, and memory size is 128MB.
        byte[] passwordBytes = Utils.Encoding.GetBytes(password);
        var argon2 = new Argon2id(passwordBytes);
        argon2.DegreeOfParallelism = 8;
        argon2.Iterations = 4;
        argon2.MemorySize = 128 * 1000; /// The number of 1kB memory blocks to use while proessing the hash
        argon2.Salt = salt;
        digest = argon2.GetBytes(digest.Length);

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

        byte[] computedDigest = new byte[32];
        byte[] passwordBytes = Utils.Encoding.GetBytes(providedPassword);

        var argon2 = new Argon2id(passwordBytes);
        argon2.DegreeOfParallelism = 8;
        argon2.Iterations = 4;
        argon2.MemorySize = 128 * 1000; /// The number of 1kB memory blocks to use while proessing the hash
        argon2.Salt = salt;
        computedDigest = argon2.GetBytes(computedDigest.Length);
        
        if (computedDigest.SequenceEqual(digest)){
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }
}