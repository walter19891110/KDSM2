import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Pattern;

import gmhelper.BCECUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import gmhelper.SM2Util;
import gmhelper.cert.CertSNAllocator;
import gmhelper.cert.CommonUtil;
import gmhelper.cert.RandomSNAllocator;
import gmhelper.cert.SM2CertUtil;
import gmhelper.cert.SM2Pkcs12Maker;
import gmhelper.cert.SM2PublicKey;
import gmhelper.cert.SM2X509CertMaker;
import gmhelper.cert.exception.InvalidX500NameException;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import sun.misc.BASE64Decoder;

import javax.xml.bind.DatatypeConverter;

public class SM {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    //生成根p12文件，包含跟CA
    public static void produceRootPkcs12File(String p12ProducePath, String password) {
        try {
            KeyPair rootKP = SM2Util.generateKeyPair();  // CA的密钥对
            X500Name rootDN = buildRootCADN();  // CA主题名
            long certExpire = 20L * 365 * 24 * 60 * 60 * 1000;  // 证书有效期20年
            CertSNAllocator snAllocator = new RandomSNAllocator();

            SM2X509CertMaker rootCertMaker = new SM2X509CertMaker(rootKP, certExpire, rootDN, snAllocator);
            SM2PublicKey rootPub = new SM2PublicKey(rootKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) rootKP.getPublic());  // 生成SM2公钥
            PrivateKey priKey = rootKP.getPrivate();  // 获取私钥

            // 生成SM2证书请求，主题、公钥、私钥、签名算法
            byte[] rootCSR = CommonUtil.createCSR(rootDN, rootPub, priKey,
                    SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            // 生成CA证书
            X509Certificate rootCACert = rootCertMaker.makeCertificate(true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment
                            | KeyUsage.keyCertSign | KeyUsage.cRLSign), rootCSR);

            // 生成P12，写入私钥、公钥证书和保护口令
            SM2Pkcs12Maker pkcs12Maker = new SM2Pkcs12Maker();
            KeyStore pkcs12 = pkcs12Maker.makePkcs12(priKey, rootCACert, password.toCharArray());
            try (OutputStream os = Files.newOutputStream(Paths.get(p12ProducePath),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                pkcs12.store(os, password.toCharArray());  // 保存P12，会生成一个P12文件
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    //生成 p12 文件
    public static void producePkcs12File(String p12ProducePath, String password) {
        try {
            KeyPair subKP = SM2Util.generateKeyPair();  // 生成SM2密钥对
            X500Name subDN = buildSubjectDN();  // 生成证书主题证名称, X500Name格式
            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) subKP.getPublic());  // 生成SM2公钥
            PrivateKey priKey = subKP.getPrivate();  // 获取私钥

            // 生成SM2证书请求，主题、公钥、私钥、签名算法
            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, priKey,
                    SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            // 生成X509证书，用途为签名和加密
            SM2X509CertMaker certMaker = buildCertMaker();  //创建证书签发者，自带CA
            X509Certificate cert = certMaker.makeCertificate(false,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment), csr);

            // 生成P12，写入私钥、公钥证书和保护口令
            SM2Pkcs12Maker pkcs12Maker = new SM2Pkcs12Maker();
            KeyStore pkcs12 = pkcs12Maker.makePkcs12(priKey, cert, password.toCharArray());
            try (OutputStream os = Files.newOutputStream(Paths.get(p12ProducePath),
                    StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                pkcs12.store(os, password.toCharArray());  // 保存P12，会生成一个P12文件
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    //获取 p12文件 公钥证书
    /**
     * 获取 p12文件 公钥证书
     * 因此，如果文件内有多个别名，一定是存的私钥+证书
     * @param p12FilePath
     * @param password
     * @return
     */
    public static X509Certificate p12ToX509(String p12FilePath, char[] password) {
        X509Certificate cert = null;
        File file = new File(p12FilePath);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            KeyStore keyStore = KeyStore.getInstance("PKCS12","BC");
            keyStore.load(fis, password);
            Enumeration en = keyStore.aliases();
            if (en.hasMoreElements()) {
                String alias = en.nextElement().toString();
                cert = (X509Certificate) keyStore.getCertificate(alias);
            }

//            System.out.println("版本号 " + cert.getVersion());
//            System.out.println("序列号 " + cert.getSerialNumber().toString(16));
//            System.out.println("签名算法 " + cert.getSigAlgName());
//            System.out.println("签发者全名 " + cert.getIssuerDN());
//            System.out.println("有效期起始日 " + cert.getNotBefore());
//            System.out.println("有效期截至日 " + cert.getNotAfter());
//            System.out.println("主体全名 " + cert.getSubjectDN());
            //System.out.println("公钥长度" + cert.getPublicKey().getEncoded().length);
            //System.out.println("公钥" + DatatypeConverter.printHexBinary(cert.getPublicKey().getEncoded()));
            //System.out.println("签名长度" + cert.getSignature().length);
            //System.out.println("签名" + DatatypeConverter.printHexBinary(cert.getSignature()));
        } catch (Exception ex) {
            ex.printStackTrace();
            cert = null;
        }
        finally{
            if (fis != null) {
                try {
                    fis.close();
                }
                catch (IOException ex) {
                }
                fis = null;
            }
        }
        return cert;
    }

    //获取 p12文件 DER公钥证书
    public static boolean getX509DERCertFromP12 (String p12FilePath, char[] password, String certFile) {
        BufferedOutputStream outStream = null;
        try{
            X509Certificate sm2Cert = p12ToX509(p12FilePath, password);

            //生成.cer
            outStream = new BufferedOutputStream(new FileOutputStream(new File(certFile)));
            outStream.write(sm2Cert.getEncoded());
            outStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            if (outStream != null) {
                try {
                    outStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return true;
    }

    //获取 p12文件 PEM公钥证书
    public static boolean getX509PEMCertFromP12 (String p12FilePath, char[] password, String certFile) {

        BufferedOutputStream outStream = null;
        try{
            X509Certificate sm2Cert = p12ToX509(p12FilePath, password);

            //生成.cer
            outStream = new BufferedOutputStream(new FileOutputStream(new File(certFile)));
            outStream.write(BCECUtil.convertECPublicKeyX509ToPEM(sm2Cert.getEncoded()).getBytes());
            outStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            if (outStream != null) {
                try {
                    outStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return true;
    }

    //p12 文件提取私钥
    public static PrivateKey getPrivateKey(String fileName, char[] password) {
        PrivateKey privateKey = null;
        File file = new File(fileName);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
            keyStore.load(fis, password);
            Enumeration en = keyStore.aliases();
            if (en.hasMoreElements()) {
                String alias = en.nextElement().toString();
                privateKey = (PrivateKey) keyStore.getKey(alias, password);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            privateKey = null;
        }
        finally{
            if (fis != null) {
                try {
                    fis.close();
                }
                catch (IOException ex) {
                }
                fis = null;
            }
        }
        return privateKey;
    }

    //获取 证书公钥
    public static BCECPublicKey getBCECPublicKey(X509Certificate sm2Cert) {
        return SM2CertUtil.getBCECPublicKey(sm2Cert);
    }

    //根据证书路径获取证书对象
    public static X509Certificate getX509Certificate(String certFilePath) throws Exception {

        X509Certificate cert = SM2CertUtil.getX509Certificate(certFilePath);

//        System.out.println("版本号 " + cert.getVersion());
//        System.out.println("序列号 " + cert.getSerialNumber().toString(16));
//        System.out.println("签名算法 " + cert.getSigAlgName());
//        System.out.println("签发者全名 " + cert.getIssuerDN());
//        System.out.println("有效期起始日 " + cert.getNotBefore());
//        System.out.println("有效期截至日 " + cert.getNotAfter());
//        System.out.println("主体全名 " + cert.getSubjectDN());
//        System.out.println("公钥长度" + cert.getPublicKey().getEncoded().length);
//        System.out.println("公钥" + DatatypeConverter.printHexBinary(cert.getPublicKey().getEncoded()));
//        System.out.println("签名长度" + cert.getSignature().length);
//        System.out.println("签名" + DatatypeConverter.printHexBinary(cert.getSignature()));

        return cert;

    }

    //加密
    public static byte[] encrypt(BCECPublicKey pubKey, byte[] srcData) throws Exception {
        return SM2Util.encrypt(pubKey, srcData);
    }

    //解密
    public static byte[] decrypt(BCECPrivateKey priKey, byte[] sm2Cipher) throws Exception {
        return SM2Util.decrypt(priKey, sm2Cipher);
    }

    //签名
    public static byte[] sign(BCECPrivateKey priKey, byte[] srcData) throws Exception{
        return SM2Util.sign(priKey, srcData);
    }

    //验签
    public static boolean verify(BCECPublicKey pubKey, byte[] srcData, byte[] sign) {
        return SM2Util.verify(pubKey, srcData, sign);
    }

    // 生成CA证书
    public static X509Certificate buildCACert(){
        X509Certificate rootCACert = null;
        try{
            KeyPair rootKP = SM2Util.generateKeyPair();  // CA的密钥对
            X500Name rootDN = buildRootCADN();  // CA主题名
            long certExpire = 20L * 365 * 24 * 60 * 60 * 1000;  // 证书有效期20年
            CertSNAllocator snAllocator = new RandomSNAllocator();

            SM2X509CertMaker rootCertMaker = new SM2X509CertMaker(rootKP, certExpire, rootDN, snAllocator);
            SM2PublicKey rootPub = new SM2PublicKey(rootKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) rootKP.getPublic());  // 生成SM2公钥
            PrivateKey priKey = rootKP.getPrivate();  // 获取私钥

            // 生成SM2证书请求，主题、公钥、私钥、签名算法
            byte[] rootCSR = CommonUtil.createCSR(rootDN, rootPub, priKey,
                    SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            // 生成CA证书
            rootCACert = rootCertMaker.makeCertificate(true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.dataEncipherment
                            | KeyUsage.keyCertSign | KeyUsage.cRLSign), rootCSR);


        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return rootCACert;
    }

    // 生成自签名证书，CA是自己
    public static boolean createUserCert(String certFile){
        BufferedOutputStream outStream = null;
        X509Certificate sm2Cert = buildCACert();
        try{
            //生成.cer
            outStream = new BufferedOutputStream(new FileOutputStream(new File(certFile)));
            outStream.write(BCECUtil.convertECPublicKeyX509ToPEM(sm2Cert.getEncoded()).getBytes());
            outStream.flush();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        } finally {
            if (outStream != null) {
                try {
                    outStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return true;
    }

    public static SM2X509CertMaker buildCertMaker() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidX500NameException {
        X500Name issuerName = buildRootCADN();  // CA主题名
        KeyPair issKP = SM2Util.generateKeyPair();  // CA的密钥对
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000; // 证书有效期20年
        CertSNAllocator snAllocator = new RandomSNAllocator();
        return new SM2X509CertMaker(issKP, certExpire, issuerName, snAllocator);
    }

    public static X500Name buildSubjectDN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "zz");
        return builder.build();
    }

    public static X500Name buildRootCADN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "ZZ Root CA");
        return builder.build();
    }

    public static void test_prikey(BCECPublicKey publicKey, BCECPrivateKey privateKey) throws Exception{

        println("测试PrivateKey<->PKCS8<->PEM，对比该PEM是否与openssl解析的一致");
        ECPublicKeyParameters pubKeyParameters = BCECUtil.convertPublicKeyToParameters(publicKey);
        ECPrivateKeyParameters priKeyParameters = BCECUtil.convertPrivateKeyToParameters(privateKey);

        byte[] a = BCECUtil.convertECPrivateKeyToPKCS8(priKeyParameters, pubKeyParameters);
        String b = BCECUtil.convertECPrivateKeyPKCS8ToPEM(a);
        println("JAVA_PrivateKey_PEM :"+b);

        //openssl读取到的私钥
        String C_PrivateKey_PEM = getPEMStr("key/C_SM2_PriKey.pem");;
        println("C_PrivateKey_PEM:"+C_PrivateKey_PEM);

        println("测试PEM<->PKCS8<->PEMPrivateKey，对比是否能从openssl生成的私钥证书中正确恢复为BCECPrivateKey格式的私钥");
        byte[] C_PrivateKey_PEM_bytes = Base64.getDecoder().decode(C_PrivateKey_PEM);//获取PKCS8字节流
//        println(DatatypeConverter.printHexBinary(C_PEM_PrivateKey_bytes));
        BCECPrivateKey C_priKey = BCECUtil.convertPKCS8ToECPrivateKey(C_PrivateKey_PEM_bytes);//转换为私钥
        println("C_priKey:"+DatatypeConverter.printHexBinary(privateKey.getD().toByteArray()));

        println("测试从C中解析的私钥是否能与Java公钥匹配上");
        String text = "SM2公私钥匹配成功!";
        byte[] signMsg = sign(privateKey, text.getBytes());
        if(verify(publicKey, text.getBytes(), signMsg)) {
            System.out.println(text);
        }
    }

    public static void test_pubkey(X509Certificate cert, BCECPrivateKey privateKey){
        try{
            String cert_PEM = BCECUtil.convertECPublicKeyX509ToPEM(cert.getEncoded());
//            println("Java_CERT:"+DatatypeConverter.printHexBinary(cert.getEncoded()));
            println("Java CERT_PEM:"+cert_PEM);

//            String C_CERT_PEM = getPEMStr("key/C_SM2_PubKey.cer");
//            println("C CERT_PEM:"+C_CERT_PEM);
//
//            byte[] C_PublicKey_PEM_bytes = Base64.getDecoder().decode(C_CERT_PEM);//获取证书字节流
//            X509Certificate x509 = SM2CertUtil.getX509Certificate(C_PublicKey_PEM_bytes);//转换为X509格式
//            BCECPublicKey c_pubkey = getBCECPublicKey(x509);//提取公钥

            X509Certificate x509 = SM2CertUtil.getX509Certificate("key/C_SM2_PubKey.pem");//读取X509证书
            BCECPublicKey c_pubkey = getBCECPublicKey(x509);//提取公钥


            println("测试从C中解析的私钥是否能与Java公钥匹配上");
            String text = "SM2公私钥匹配成功!";
            byte[] signMsg = sign(privateKey, text.getBytes());
            if(verify(c_pubkey, text.getBytes(), signMsg)) {
                System.out.println(text);
            }
        } catch (Exception e){
            e.printStackTrace();
        }

    }

    public static void test_java_c(){
        String p12file = "key/SM2.p12";
        String pwd = "12345678";
        String certfile = "key/SM2.cer";

        try {
            X509Certificate sm2Cert = p12ToX509(p12file, pwd.toCharArray());
            PrivateKey key = getPrivateKey(p12file, pwd.toCharArray());

            println("测试私钥，打印出来与C语言解析出来的对比");
            BCECPrivateKey privateKey = (BCECPrivateKey) key;
            println("Java PrivateKey Length:"+SM2Util.getRawPrivateKey(privateKey).length);
//            println(DatatypeConverter.printHexBinary(SM2Util.getRawPrivateKey(privateKey)));
            println(DatatypeConverter.printHexBinary(privateKey.getD().toByteArray()));

            println("测试公钥，打印出来与C语言解析出来的对比");
            BCECPublicKey publicKey = getBCECPublicKey(sm2Cert);
            println("Java PublicKey Lenght:"+publicKey.getQ().getEncoded(false).length);  //打印公钥
            println(DatatypeConverter.printHexBinary(publicKey.getQ().getEncoded(false)));  //打印公钥

            println("测试加解密和签名验签");
            String text = "Java自己的公私钥匹配成功!";
            byte[] arrtemp = encrypt(publicKey, text.getBytes());
            byte[] signMsg = sign(privateKey, arrtemp);
            if(verify(publicKey, arrtemp, signMsg)) {
                arrtemp = decrypt(privateKey, arrtemp);
                System.out.println(new String(arrtemp));
            }
            // 测试PrivateKey<->PKCS8<->PEM，对比该PEM是否与openssl解析的一致
            println("\n测试Java是否能解析openssl生成的私钥");
            test_prikey(publicKey, privateKey);

            println("\n测试Java是否能解析openssl生成的公钥证书");
            test_pubkey(sm2Cert, privateKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static void println(Object object){
        System.out.println(object);
    }

    /**
     * 读取PEM证书内容
     * @param pemFile PEM证书
     * @return
     * @throws IOException
     */
    public static String getPEMStr(String pemFile) throws IOException{
        List<String> list = new ArrayList<>();
        String reg="-----*";
        Pattern p= Pattern.compile(reg);
        Files.lines(Paths.get(pemFile)).forEach(line -> {
            //不要第一行和最后一行
            if(!p.matcher(line).find()){
                list.add(line);
            }
        });

        return String.join("",list);
    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub
        Security.addProvider(new BouncyCastleProvider());
        String p12file = "key/SM2.p12";
        String pwd = "12345678";
//        String certfile = "key/server.cer";
        String certfile = "key/SM2.cer";
        try {
//            producePkcs12File(p12file, pwd);
//            getX509DERCertFromP12(p12file, pwd.toCharArray(), certfile);
//            getX509PEMCertFromP12(p12file, pwd.toCharArray(), certfile);
//            X509Certificate sm2Cert = getX509Certificate("/Users/walter/Downloads/SM2.cer");

//            String pemStr = getPEMStr("key/C_SM2_PriKey.cer");
//            println(pemStr);
            test_java_c();
            //测试证书自验
//            X509Certificate CACert = buildCACert();
//            BCECPublicKey CAPubkey = getBCECPublicKey(CACert);
//            boolean res = SM2CertUtil.verifyCertificate(CAPubkey, CACert);
//            System.out.println("验证结果:"+res);
        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
