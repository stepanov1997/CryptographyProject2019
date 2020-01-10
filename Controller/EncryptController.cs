using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CryptographyProject2019.Model;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace CryptographyProject2019.Controller
{
    internal class EncryptController
    {
        public static bool EncryptFile((string, byte[]) file, Account receiverAccount, SymmetricAlgorithm sa,
            HashAlgorithm hashAlgorithm)
        {
            var senderUsername = AccountsController.GetInstance().CurrentAccount.Username;
            var receiverCertificatePath = receiverAccount.PathToCertificate;
            var receiverUsername = Path.GetFileNameWithoutExtension(receiverAccount.PathToCertificate);
            Directory.CreateDirectory(Directory.GetCurrentDirectory() + $"/../../ReceivedMessages/{receiverUsername}/");

            //========================================================================
            // Validate sender and receiver certificate.
            var senderAccount = AccountsController.GetInstance().CurrentAccount;
            var senderCertificate = new X509Certificate2();
            senderCertificate.Import(senderAccount.PathToCertificate);

            var receiverCertificate = new X509Certificate2();
            receiverCertificate.Import(receiverAccount.PathToCertificate);

            if (!ValidateController.ValidateCertificates(receiverCertificate)) return false;
            if (!ValidateController.ValidateCertificates(senderCertificate)) return false;

            //========================================================================
            // Generate symmetric key
            sa.GenerateIV();
            sa.GenerateKey();
            var symmetricKey = Encoding.Unicode.GetString(sa.Key);

            //========================================================================
            // Encrypt symmetric key with receiver public key and save it into textfile.
            // Receiver can only read it, only he has his private key.
            var rsaprovider = (RSACryptoServiceProvider) receiverCertificate.PublicKey.Key;
            var encryptedSymmetricKey =
                Convert.ToBase64String(rsaprovider.Encrypt(Encoding.Unicode.GetBytes(symmetricKey), false));

            //========================================================================
            // Encrypt sender name and filename.
            var encryptedName = Cipher.Encrypt(senderUsername, symmetricKey, sa);
            var encryptedFileName = Cipher.Encrypt(file.Item1, symmetricKey, sa);
            var encryptedHashAlg = Cipher.Encrypt(CheckHashAlgorithm(hashAlgorithm), symmetricKey, sa);

            //========================================================================
            // Encrypt hash of file with user private key to make digital signature.
            var rsa = ImportPrivateKey(Directory.GetCurrentDirectory() + "/../../CurrentUser/private.key");
            var signature = SignData(Encoding.Unicode.GetString(file.Item2), rsa.ExportParameters(true), hashAlgorithm);

            // Encrypt digital signature with symmetric key and save it as text file
            var encryptedSignature = Cipher.Encrypt(signature, symmetricKey, sa);

            //========================================================================
            // Encrypt file data with symmetric key and save it as text file
            var encryptedData = Cipher.Encrypt(Encoding.Unicode.GetString(file.Item2), symmetricKey, sa);

            //========================================================================
            var cryptedFile =
                $"ENCRYPTED SYMMETRIC KEY:\n{encryptedSymmetricKey}\n\n" +
                $"ENCRYPTED HASH ALGORITHM:\n{encryptedHashAlg}\n\n" +
                $"ENCRYPTED FILE SENDER:\n{encryptedName}\n\n" +
                $"ENCRYPTED DIGITAL SIGNATURE:\n{encryptedSignature}\n\n" +
                $"ENCRYPTED FILENAME\n{encryptedFileName}\n\n" +
                $"ENCRYPTED FILE:\n{encryptedData}\n\n";

            var path = makePathOfCryptedFile(receiverUsername, CheckSymmetricAlgorithm(sa));
            var algExt = CheckSymmetricAlgorithm(sa);

            File.WriteAllText(path, cryptedFile);

            return true;
        }

        private static string makePathOfCryptedFile(string toFolder, string algExt)
        {
            var i = 1;
            var numOfFile = "";
            while (File.Exists(
                $"{Directory.GetCurrentDirectory()}/../../ReceivedMessages/{toFolder}/cryptedFile{numOfFile}.{algExt}"))
                numOfFile = (++i).ToString();
            return
                $"{Directory.GetCurrentDirectory()}/../../ReceivedMessages/{toFolder}/cryptedFile{numOfFile}.{algExt}";
        }

        private static string CheckSymmetricAlgorithm(SymmetricAlgorithm symmetricAlgorithm)
        {
            switch (symmetricAlgorithm)
            {
                case Aes _:
                    return "aes";
                case RC2 _:
                    return "rc2";
                case TripleDES _:
                    return "des3";
                default:
                    return "aes";
            }
        }

        private static string CheckHashAlgorithm(HashAlgorithm hashAlgorithm)
        {
            return hashAlgorithm is SHA256 ? "SHA256" : "SHA1";
        }

        public static RSACryptoServiceProvider ImportPrivateKey(string path)
        {
            var sr = new StreamReader(path);
            var pr = new PemReader(sr);
            var KeyPair = (AsymmetricCipherKeyPair) pr.ReadObject();
            var rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters) KeyPair.Private);

            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParams);
            return rsa;
        }

        public static string ComputeSha1Hash(string rawData, HashAlgorithm hashAlgorithm)
        {
            using (var sha1Hash = SHA1.Create())
            {
                var bytes = sha1Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                var builder = new StringBuilder();
                for (var i = 0; i < bytes.Length; i++) builder.Append(bytes[i].ToString("x2"));
                return builder.ToString();
            }
        }

        public static string SignData(string message, RSAParameters privateKey, HashAlgorithm hashAlgorithm)
        {
            byte[] signedBytes;

            using (var rsa = new RSACryptoServiceProvider())
            {
                // Write the message to a byte array using ASCII as the encoding.
                var originalData = Encoding.Unicode.GetBytes(message);

                try
                {
                    // Import the private key used for signing the message
                    rsa.ImportParameters(privateKey);

                    string alg;
                    alg = hashAlgorithm is SHA256 ? "SHA256" : "SHA1";

                    signedBytes = rsa.SignData(originalData, CryptoConfig.MapNameToOID(alg));
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                    return null;
                }
                finally
                {
                    // Set the keycontainer to be cleared when rsa is garbage collected.
                    rsa.PersistKeyInCsp = false;
                }
            }

            // Convert the byte array back to a string message
            return Convert.ToBase64String(signedBytes);
        }
    }
}