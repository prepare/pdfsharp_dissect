#region PDFsharp - A .NET library for processing PDF
//
// Authors:
//   Stefan Lange
//
// Copyright (c) 2005-2016 empira Software GmbH, Cologne Area (Germany)
//
// http://www.pdfsharp.com
// http://sourceforge.net/projects/pdfsharp
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
// DEALINGS IN THE SOFTWARE.
#endregion

// ReSharper disable InconsistentNaming

namespace PdfSharp.Pdf.Security
{
    /// <summary>
    /// Represents the Cryptography Filter dictionary.
    /// </summary>
    public class PdfCryptoFilter : PdfDictionary
    {
        /// <summary>
        /// The 'Identity' CF dictionary means the data stream is used as it is.
        /// </summary>
        public const string Identity = "/Identity";

        /// <summary>
        /// The 'StdCF' CF dictionary means the data stream is encrypted using
        /// the algorithm described by the Standard Cryptographic Filter dictionary.
        /// </summary>
        public const string StdCF = "/StdCF";

        /// <summary>
        /// The application asks the security handler for the encryption key and
        /// implicitly decrypts data with Algorithm 3.1, using the RC4 algorithm.
        /// </summary>
        public const string V2 = "/V2";

        /// <summary>
        /// (PDF 1.6) The application asks the security handler for the encryption key
        /// and implicitly decrypts data with Algorithm 3.1, using the AES algorithm in
        /// Cipher Block Chaining (CBC) mode with a 16-byte block size and an
        /// initialization vector that is randomly generated and placed as the first
        /// 16 bytes in the stream or string.
        /// </summary>
        public const string AESV2 = "/AESV2";

        /// <summary>
        /// NoneThe application does not decrypt data but directs the input stream to
        /// the security handler for decryption.
        /// </summary>
        public const string None = "/None";

        internal PdfCryptoFilter(PdfDocument document)
            : base(document)
        { }

        internal PdfCryptoFilter(PdfDictionary dict)
            : base(dict)
        { }

        /// <summary>
        /// Predefined keys of this dictionary.
        /// </summary>
        internal class Keys : KeysBase
        {
            /// <summary>
            /// Optional) If present, must be CryptFilter for a crypt filter dictionary.
            /// </summary>
            [KeyInfo(KeyType.Name | KeyType.Optional)]
            public const string Type = "/Type";

            /// <summary>
            /// (Optional) The method used, if any, by the consumer application to decrypt data.
            /// The following values are supported:
            ///  None  (PDF 1.1) The application does not decrypt data but directs the input stream to the security
            ///                  handler for decryption.
            ///  V2    (PDF 1.4) The application asks the security handler for the encryption key and implicitly
            ///                  decrypts data with Algorithm 3.1, using the RC4 algorithm.
            ///  AESV2 (PDF 1.6) The application asks the security handler for the encryption key and implicitly
            ///                  decrypts data with Algorithm 3.1, using the AES algorithm in Cipher Block Chaining
            ///                  mode (CBC) with a 16-byte block size and an initialization vector that is randomly
            ///                  generated and placed as the first 16 bytes in the stream or string.
            ///  When the value is V2 or AESV2, the application may ask once for this encryption key and cache the
            ///  key for subsequent use for streams that use the same crypt filter.Therefore, there must be a
            ///  one-to-one relationship between a crypt filter name and the corresponding encryption key.
            ///  Only the values listed here are supported.
            ///  Applications that encounter other values should report that the file is encrypted with
            ///  an unsupported algorithm.
            /// </summary>
            [KeyInfo(KeyType.Name | KeyType.Optional)]
            public const string CFM = "/CFM";

            /// <summary>
            /// (Optional but strongly recommended) A code specifying the algorithm to be used in encrypting
            /// and decrypting the document:
            /// 0 An algorithm that is undocumented and no longer supported, and whose use is strongly discouraged.
            /// 1 Algorithm 3.1, with an encryption key length of 40 bits.
            /// 2 (PDF 1.4) Algorithm 3.1, but permitting encryption key lengths greater than 40 bits.
            /// 3 (PDF 1.4) An unpublished algorithm that permits encryption key lengths ranging from 40 to 128 bits.
            /// 4 (PDF 1.5) The security handler defines the use of encryption and decryption in the document, using
            ///             the rules specified by the CF, StmF, and StrF entries.
            /// The default value if this entry is omitted is 0, but a value of 1 or greater is strongly recommended.
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Optional)]
            public const string V = "/V";

            /// <summary>
            /// (Optional) The event to be used to trigger the authorization that is required to access encryption
            /// keys used by this filter. If authorization fails, the event should fail. Valid values are:
            /// DocOpen  Authorization is required when a document is opened.
            /// EFOpen:  Authorization is required when accessing embedded files.
            /// Default value: DocOpen.
            /// If this filter is used as the value of StrF or StmF in the encryption dictionary,
            /// the application should ignore this key and behave as if the value is DocOpen.
            /// </summary>
            [KeyInfo(KeyType.Name | KeyType.Optional)]
            public const string AuthEvent = "/AuthEvent";

            /// <summary>
            /// (Optional) The bit length of the encryption key. It must be a multiple of 8 in
            /// the range of 40 to 128.
            /// Note: Security handlers can define their own use of the Length entry but are encouraged
            /// to use it to define the bit length of the encryption key.
            /// </summary>
            [KeyInfo(KeyType.Integer | KeyType.Optional)]
            public const string Length = "/Length";

            /// <summary>
            /// (Required) If the crypt filter is referenced from StmF or StrF in the encryption dictionary,
            /// this entry is an array of byte strings, where each string is a binary-encoded PKCS#7 object
            /// listing recipients that have been granted equal access rights to the document.
            /// The enveloped data contained in the PKCS#7 object includes both a 20-byte seed value used to
            /// compute the encryption key followed by 4 bytes of permissions settings that apply to the
            /// recipient list.
            /// There should be only one object per unique set of access permissions. If a recipient appears
            /// in more than one list, the permissions used are those in the first matching list.
            /// If the crypt filter is referenced from a Crypt filter decode parameter dictionary, this entry
            /// is a string that is a binary-encoded PKCS#7 object containing a list of all recipients who are
            /// permitted to access the corresponding encrypted stream. The enveloped data contained in the
            /// PKCS#7 object is a 20-byte seed value used to create the encryption key that is used by
            /// Algorithm 3.1.
            /// </summary>
            [KeyInfo(KeyType.ArrayOrString | KeyType.Optional)]
            public const string Recipients = "/Recipients";

            /// <summary>
            /// (Optional; used only by crypt filters that are referenced from StmF in an encryption dictionary)
            /// Indicates whether the document-level metadata stream is to be encrypted.
            /// PDF consumer applications should respect this value when determining whether metadata should be
            /// encrypted.
            /// Default value: true.
            /// </summary>
            [KeyInfo(KeyType.Boolean | KeyType.Optional)]
            public const string EncryptMetadata = "/EncryptMetadata";
        }
    }
}
