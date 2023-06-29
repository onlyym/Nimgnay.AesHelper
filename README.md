




## **--说明--**
~~~~
 		   //实例化对象 默认构造函数 
            //加密模式：ECB  填充方式 PKCS7 密钥大小 128  块大小 128
            //支持自定义，传入不同的加密方式和填充方式，加解密结果不同
            AESHelper aesHelper = new AESHelper();


            var res1 = aesHelper.AesEncode("2321321", "QQWWEE123456789", null, new UTF8Encoding());
            var dres1 = aesHelper.AesDecode(res1, "QQWWEE123456789", null, new UTF8Encoding());

            //此处的key为随机种子，和java做对接，由种子生成最终的秘钥
            var res = aesHelper.AesEncrypt_SeedKey("zzzzzzzzccccccccbbbbbbbwwww123","SUNING123456789", null, new UTF8Encoding());
            var dres =  aesHelper.AesDecrypt_SeedKey(res,  "QQWWEE123456789", null, new UTF8Encoding());
 ~~~~
 
