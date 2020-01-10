using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;

namespace CryptographyProject2019.Controller
{
    internal class DecryptController
    {
        public static string DecryptEncryptedFile(EncryptedFileParameters @params)
        {
            //========================================================================
            // Decrypt encrypted symmetric key with private key.
            var rsa = EncryptController.ImportPrivateKey(Directory.GetCurrentDirectory() +
                                                         "/../../CurrentUser/private.key");
            var symmetricKey =
                Encoding.Unicode.GetString(rsa.Decrypt(Convert.FromBase64String(@params.EncryptedSymmetricKey), false));

            //========================================================================
            // Decrypt encrypted sender and filename.
            var decryptedName = Cipher.Decrypt(@params.EncryptedName, symmetricKey, @params.SymmetricAlgorithm);

            //========================================================================
            // Validate sender and receiver certificate.
            var senderAccount = AccountsController.GetInstance().Accounts[decryptedName];
            var senderCertificate = new X509Certificate2();
            senderCertificate.Import(senderAccount.PathToCertificate);

            var receiverAccount = AccountsController.GetInstance().CurrentAccount;
            var receiverCertificate = new X509Certificate2();
            receiverCertificate.Import(receiverAccount.PathToCertificate);

            if (!ValidateController.ValidateCertificates(receiverCertificate)) return "";
            if (!ValidateController.ValidateCertificates(senderCertificate)) return "";

            //========================================================================
            // Decrypt digital signature with symmetric key.
            var digitalSignature = Convert.FromBase64String(
                Cipher.Decrypt(@params.EncryptedSignature, symmetricKey, @params.SymmetricAlgorithm));

            //========================================================================
            // Decrypt file with symmetric key.
            var decryptedFileName = Cipher.Decrypt(@params.EncryptedFileName, symmetricKey, @params.SymmetricAlgorithm);
            var decryptedFile = Encoding.Unicode.GetBytes(
                Cipher.Decrypt(@params.EncryptedData, symmetricKey, @params.SymmetricAlgorithm));

            //========================================================================
            // Verify filehash with signature.
            var decryptedHashAlg = Cipher.Decrypt(@params.EncryptedHashAlg, symmetricKey, @params.SymmetricAlgorithm);
            var rsaCrypto = (RSACryptoServiceProvider) senderCertificate.PublicKey.Key;
            if (!VerifyData(decryptedFile, digitalSignature, rsaCrypto.ExportParameters(false), decryptedHashAlg))
            {
                MessageBox.Show("File is changed! Unsuccessfully decrypt. 😐");
                return "";
            }

            //========================================================================
            // Write file on filesystem.
            var parentPath = Directory.GetCurrentDirectory() + "/../../DecryptedMessages";
            var currentUsername = AccountsController.GetInstance().CurrentAccount.Username;
            var path = $"{parentPath}/{currentUsername}/{decryptedName}/{Path.GetFileName(decryptedFileName)}";
            if (!Directory.Exists($"{parentPath}/{currentUsername}/{decryptedName}/"))
                Directory.CreateDirectory($"{parentPath}/{currentUsername}/{decryptedName}/");
            File.WriteAllBytes(path, decryptedFile);
            return path;
        }

        public static EncryptedFileParameters EncryptedFileParametersParser(string path)
        {
            var ext = Path.GetExtension(path);
            SymmetricAlgorithm symmetricAlgorithm;
            switch (ext)
            {
                case ".aes":
                    symmetricAlgorithm = Aes.Create();
                    break;
                case ".des3":
                    symmetricAlgorithm = TripleDES.Create();
                    break;
                case ".rc2":
                    symmetricAlgorithm = RC2.Create();
                    break;
                default:
                    symmetricAlgorithm = Aes.Create();
                    break;
            }

            var content = File.ReadAllText(path);
            var match = Regex.Match(content,
                "ENCRYPTED SYMMETRIC KEY:\n(.*?)\n\n" +
                "ENCRYPTED HASH ALGORITHM:\n(.*?)\n\n" +
                "ENCRYPTED FILE SENDER:\n(.*?)\n\n" +
                "ENCRYPTED DIGITAL SIGNATURE:\n(.*?)\n\n" +
                "ENCRYPTED FILENAME\n(.*?)\n\n" +
                "ENCRYPTED FILE:\n(.*?)\n\n");

            var @params = new EncryptedFileParameters
            {
                EncryptedSymmetricKey = match.Groups[1].Value,
                EncryptedHashAlg = match.Groups[2].Value,
                EncryptedName = match.Groups[3].Value,
                EncryptedSignature = match.Groups[4].Value,
                EncryptedFileName = match.Groups[5].Value,
                EncryptedData = match.Groups[6].Value,
                SymmetricAlgorithm = symmetricAlgorithm
            };

            return @params;
        }

        private static HashAlgorithm getHashAlgorithm(string hashalg)
        {
            return hashalg == "SHA256" ? (HashAlgorithm) SHA256.Create() : SHA1.Create();
        }

        public static bool VerifyData(byte[] originalMessage, byte[] signedMessage, RSAParameters publicKey,
            string hashAlgorithm)
        {
            var success = false;
            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    rsa.ImportParameters(publicKey);
                    success = rsa.VerifyData(originalMessage, CryptoConfig.MapNameToOID(hashAlgorithm), signedMessage);
                }
                catch (CryptographicException e)
                {
                    Console.WriteLine(e.Message);
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }

            return success;
        }

        private static string FromBase64(string encoded)
        {
            return Encoding.Unicode.GetString(Convert.FromBase64String(encoded));
        }

        public struct EncryptedFileParameters
        {
            public string EncryptedSymmetricKey;
            public string EncryptedHashAlg;
            public string EncryptedName;
            public string EncryptedSignature;
            public string EncryptedFileName;
            public string EncryptedData;
            public SymmetricAlgorithm SymmetricAlgorithm;
        }
    }
}