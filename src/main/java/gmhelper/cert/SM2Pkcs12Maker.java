package gmhelper.cert;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * @author Lijun Liao https:/github.com/xipki
 */
public class SM2Pkcs12Maker {

    /**
     * @param privKey 用户私钥
     * @param chain   X509证书数组，
     *                第一个（index 0）为privKey对应的证书，index i+1 是index i的CA证书
     * @param passwd  口令
     * @return the PKCS#12 keystore
     * @throws NoSuchProviderException 
     * @throws KeyStoreException 
     * @throws CertificateException 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public KeyStore makePkcs12(PrivateKey privKey, X509Certificate[] chain, char[] passwd)
        throws KeyStoreException, NoSuchProviderException,
        NoSuchAlgorithmException, CertificateException, IOException {

        // 获取P12实例，指定工厂为BC
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

        // 设置保护口令
        ks.load(null, passwd);

        //设置KeyEntry，第一个参数是别名
        ks.setKeyEntry("User Key", privKey, passwd, chain);  // 设置内容，私钥、公钥证书
        return ks;
    }

    /**
     * @param privKey 用户私钥
     * @param cert    X509证书
     * @param passwd  口令
     * @return the PKCS12 keystore
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyStoreException
     */
    public KeyStore makePkcs12(PrivateKey privKey, X509Certificate cert, char[] passwd)
        throws KeyStoreException, NoSuchProviderException,
        NoSuchAlgorithmException, CertificateException, IOException {
      return makePkcs12(privKey, new X509Certificate[] {cert}, passwd);
    }
}
