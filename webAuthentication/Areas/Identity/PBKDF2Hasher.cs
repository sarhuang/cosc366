/* Name: Sarah Huang
 * Date: 2/25/2023
 * Program: PBKDF2Hasher.cs
 * Purpose: For this hasher, you will be using PBKDF2 to hash passwords.
 */

using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by PBKDF2.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
//https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes.pbkdf2?view=net-7.0
/// </remarks>
internal class PBKDF2Hasher : IPasswordHasher<IdentityUser> {

    /// <summary>
    /// Hash a password using PBKDF2.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password) {
        // todo: Use a random 32-byte salt. Use a 32-byte digest.
        byte[] salt = RandomNumberGenerator.GetBytes(32);
        byte[] digest = new byte[32];

        // todo: Use 100,000 iterations and the SHA256 algorithm.
        digest = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100000, HashAlgorithmName.SHA256, digest.Length);
        
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
        string[] hasedPasswordHalves = hashedPassword.Split(':');
        byte[] salt = Convert.FromBase64String(hasedPasswordHalves[0]);
        byte[] digest = Convert.FromBase64String(hasedPasswordHalves[1]);

        byte[] computedDigest = new byte[32];
        computedDigest = Rfc2898DeriveBytes.Pbkdf2(providedPassword, salt, 100000, HashAlgorithmName.SHA256, computedDigest.Length);
        
        if(computedDigest.SequenceEqual(digest)){
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }
}