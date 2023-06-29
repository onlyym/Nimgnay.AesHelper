using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using static System.Net.Mime.MediaTypeNames;

namespace Nimgnay.AesHelper
{
    /// <summary>
    /// AES 加解密
    /// </summary>
    public class AESHelper
    {
        /// <summary>
        /// 加密操作的模式
        /// </summary>
        private readonly CipherMode _mode;
        /// <summary>
        /// 加密过程中使用的填充方式
        /// </summary>
        private readonly PaddingMode _padding;
        /// <summary>
        /// 加密和解密的密钥的大小
        /// </summary>
        private readonly int _keySize;
        /// <summary>
        /// 加密操作中使用的块的大小
        /// </summary>
        private readonly int _blockSize;

        private RijndaelManaged _aes;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Mode">加密操作的模式</param>
        /// <param name="Padding">加密过程中使用的填充方式</param>
        /// <param name="KeySize">加密和解密的密钥的大小</param>
        /// <param name="BlockSize">加密操作中使用的块的大小</param>
        public AESHelper(CipherMode Mode = CipherMode.ECB, PaddingMode Padding = PaddingMode.PKCS7, int KeySize = 128, int BlockSize = 128)
        {
            _mode = Mode;
            _padding = Padding;
            _keySize = KeySize;
            _blockSize = BlockSize;
            //初始化
            InitAes();
        }

        public void InitAes()
        {

            _aes = new RijndaelManaged();
            _aes.Mode = _mode;
            _aes.Padding = _padding;
            _aes.KeySize = _keySize;
            _aes.BlockSize = _blockSize;

        }






        /// <summary>AES加密 返回加密后base64字符串</summary>  
        /// <param name="text">明文</param>  
        /// <param name="key">密钥,长度为16的字符串</param>  
        /// <param name="iv">偏移量,长度为16的字符串</param>
        /// <param name="encoding">编码</param>  
        /// <returns>密文</returns>  
        public string AesEncode(string str, string key, string iv, Encoding encoding)
        {
            try
            {
                if (string.IsNullOrEmpty(str)) return null;

                byte[] keyBytes = encoding.GetBytes(key); ;
                _aes.Key = keyBytes;
                if (!string.IsNullOrWhiteSpace(iv))
                {
                    _aes.IV = encoding.GetBytes(iv);
                }
                else
                {
                    _aes.IV = new byte[16];
                }
                ICryptoTransform transform = _aes.CreateEncryptor();
                byte[] plainText = Encoding.UTF8.GetBytes(str);
                byte[] cipherBytes = transform.TransformFinalBlock(plainText, 0, plainText.Length);
                var res = Convert.ToBase64String(cipherBytes);
                return res;
            }
            catch (Exception e)
            {
                return string.Empty;
            }

        }

        /// <summary>AES解密</summary>  
        /// <param name="str">密文 base64编码</param>  
        /// <param name="key">密钥,长度为16的字符串</param>  
        /// <param name="iv">偏移量,长度为16的字符串</param>
        /// <param name="encoding">编码</param>    
        /// <returns>明文</returns>  
        public string AesDecode(string str, string key, string iv, Encoding encoding)
        {
            try
            {
                byte[] encryptedData = Convert.FromBase64String(str);
                byte[] keyBytes = encoding.GetBytes(key);
                _aes.Key = keyBytes;
                if (!string.IsNullOrWhiteSpace(iv))
                {
                    _aes.IV = encoding.GetBytes(iv);
                }
                else
                {
                    _aes.IV = new byte[16];
                }
                ICryptoTransform transform = _aes.CreateDecryptor();
                byte[] plainText = transform.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                var res = encoding.GetString(plainText);
                return res;
            }
            catch (Exception e)
            {
                return string.Empty;


            }

        }





        #region 对接java使用ECB 根据种子key生成伪随机密钥
        /// <summary>
        ///  AES 加密 根据种子key生成伪随机密钥进行加密,默认不偏移  JAVA默认使用的ECB 
        /// </summary>
        /// <param name="str">待加密字符串</param>  
        /// <param name="key">随机种子，根据种子生成秘钥</param>  
        /// <param name="iv">偏移量,长度为16的字符串</param>
        /// <param name="encoding">编码</param>    
        /// <returns></returns>
        public string AesEncrypt_SeedKey(string str, string key, string iv, Encoding encoding)
        {

            try
            {

                if (string.IsNullOrEmpty(str)) return string.Empty;

                var byKeyArray = GetKeyBySeed(key, encoding);
                byte[] biv = new byte[16];
                if (!string.IsNullOrWhiteSpace(iv))
                {
                    biv = encoding.GetBytes(iv);
                }
                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.KeySize = _keySize;
                    aesAlg.BlockSize = _blockSize;
                    aesAlg.Mode = _mode;
                    aesAlg.Padding = _padding;
                    ICryptoTransform encryptor = aesAlg.CreateEncryptor(byKeyArray, biv);
                    byte[] data = encoding.GetBytes(str);
                    byte[] encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
                    var res = BitConverter.ToString(encryptedData).Replace("-", "").ToUpper();
                    return res;
                }
            }
            catch (Exception e)
            {
                return string.Empty;

            }
        }

        /// <summary>
        ///  AES 解密 根据种子key生成伪随机密钥进行解密，默认不偏移 JAVA默认使用的ECB 
        /// </summary>
        /// <param name="str">待解密字符串</param>
        /// <param name="key">随机种子，根据种子生成秘钥</param>  
        /// <param name="iv">偏移量,长度为16的字符串</param>
        /// <param name="encoding">编码</param>    
        /// <returns>普通字符串</returns>
        public string AesDecrypt_SeedKey(string str, string key, string iv, Encoding encoding)
        {

            try
            {

                if (string.IsNullOrEmpty(str)) return string.Empty;


                var byteKey = GetKeyBySeed(key, encoding);

                byte[] byCon = new byte[str.Length / 2];

                for (int i = 0; i < str.Length; i += 2)
                {
                    byCon[i / 2] = Convert.ToByte(str.Substring(i, 2), 16);
                }

                if (!string.IsNullOrWhiteSpace(iv))
                {
                    _aes.IV = encoding.GetBytes(iv);
                }

                _aes.Key = byteKey;
                _aes.Padding = _padding;

                ICryptoTransform cTransform = _aes.CreateDecryptor();
                byte[] resultArray = cTransform.TransformFinalBlock(byCon, 0, byCon.Length); //获得解密后的byte[]
                string normalString = encoding.GetString(resultArray); // 将字节数组转换为普通字符串

                return normalString;
            }
            catch (Exception e)
            {
                return "";
            }
        }


        /// <summary>
        /// 用种子获取密钥字节
        /// </summary>
        /// <param name="strKey">密钥种子</param>
        /// <param name="encoding">编码格式</param>
        /// <param name="nLen">密钥长度（一般为16，不清楚时不要随意动）</param>
        /// <returns></returns>
        public static byte[] GetKeyBySeed(string strKey, Encoding encoding, int nLen = 16)
        {
            byte[] bySeed = encoding.GetBytes(strKey);
            byte[] byKeyArray = null;
            using (var st = new SHA1CryptoServiceProvider())
            {
                using (var nd = new SHA1CryptoServiceProvider())
                {
                    var rd = nd.ComputeHash(st.ComputeHash(bySeed));
                    byKeyArray = rd.Take(nLen).ToArray();
                }
            }
            return byKeyArray;
        }
        #endregion






    }
}
