import ocsp.*;
import ocsp.MainTest;
import ocsp.builder.Properties;
import org.apache.axis.components.logger.LogFactory;
import org.apache.axis.components.net.BooleanHolder;
import org.apache.axis.components.net.SecureSocketFactory;
import org.apache.axis.components.net.TransportClientProperties;
import org.apache.axis.components.net.TransportClientPropertiesFactory;
import org.apache.axis.utils.Messages;
import org.apache.axis.utils.StringUtils;
import org.apache.axis.utils.XMLUtils;
import org.apache.commons.logging.Log;
import sun.security.provider.certpath.OCSP;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.Socket;
import javax.net.ssl.*;
import java.net.URI;
import java.security.*;
import java.security.cert.*;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

public class MyFakeTrustSocketFactory implements SecureSocketFactory {
    String ts = "D:\\spidr1.truststore";
    String ksf = "D:\\chap8.secure.keystore";
    //   String keyStoreFilePath = "C:\\Program Files\\Java\\jdk1.8.0_144\\jre\\lib\\security\\cacerts";
    String keyStoreFilePassword = "changeit";


    protected static Log log = LogFactory.getLog(MyFakeTrustSocketFactory.class.getName());
    public MyFakeTrustSocketFactory(Hashtable attributes) {

    }


    protected SSLSocketFactory sslFactory = null;
    protected void initFactory() throws IOException {
        sslFactory = (SSLSocketFactory)SSLSocketFactory.getDefault();
    }
    /**
     * Create a socket
     */
    public Socket create(String host, int port, StringBuffer otherHeaders, BooleanHolder useFullURL) throws Exception {
        SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("TLS","BCJSSE");

        File keystoreFile = new File(ts);
        if(!keystoreFile.exists() || keystoreFile.isDirectory()) {
            return null;
        }

        KeyStore trustStore = KeyStore.getInstance("JKS", "SUN");
        FileInputStream fin = new FileInputStream(ts);
        trustStore.load(fin, keyStoreFilePassword.toCharArray());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        X509Certificate[] certs = new MyFakeX509TrustManager((X509TrustManager) tmf.getTrustManagers()[0]).getAcceptedIssuers();
        String ersin = certs[2].getIssuerDN().getName();

        Enumeration en = trustStore.aliases();
        X509Certificate signingcert = null;

        while (en.hasMoreElements())
        {
            X509Certificate storecert = null;
            String ali = (String)en.nextElement() ;
            if(trustStore.isCertificateEntry(ali))
            {
                storecert = (X509Certificate)trustStore.getCertificate(ali);
                if( (storecert.getIssuerDN().getName()).equals(ersin))
                {
                    try{
                        System.out.println("Found matching issuer DN cert in keystore:\r\nChecking signature on cert ...") ;
                        System.out.println("Root Public Key : " + storecert.getPublicKey().hashCode());
                        System.out.println("Signature verified on certificate") ;
                        signingcert = storecert;
                        break;
                    }
                    catch(Exception exc){
                        System.out.println("Failed to verify signature on certificate with matching cert DN");
                    }
                }
            }
            else
            if(trustStore.isKeyEntry(ali))
                System.out.println(ali + "   **** key entry ****");
        }


//        System.out.println("SIZE TEST : " + trustStore.size());

//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        PKIXParameters params;
//        CertPath certPath;
//        CertPathValidator certPathValidator;
//        Boolean valid = Boolean.FALSE;
//
//        params = new PKIXParameters(trustStore);
//        params.setRevocationEnabled(true);
//        Security.setProperty("ocsp.enable", "true");
//
//        certPath = cf.generateCertPath(fin);

//        List<Certificate> certs = (List<Certificate>) certPath.getCertificates();
//        for (Certificate cert : certs) {
//            System.out.println("TEST TEST " + cert);
//        }


//        certPathValidator = CertPathValidator.getInstance("PKIX");
//
//        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
//                certPathValidator.validate(certPath, params);
//
//        if(null != result) {
//            valid = Boolean.TRUE;
//            System.out.println("Result is TRUE");
//        }

        KeyStore keyStore2 = KeyStore.getInstance("JKS");
        FileInputStream inputStream2 = new FileInputStream(ksf);
        keyStore2.load(inputStream2, "mDPxad08l36nYHPFgrwHJM6gcOcfUc5u".toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("Sunx509");
        keyManagerFactory.init(keyStore2, "mDPxad08l36nYHPFgrwHJM6gcOcfUc5u".toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();


//        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
//        X509Certificate[] certs = defaultTrustManager.getAcceptedIssuers();
//        for (X509Certificate cert:certs) {
//            System.out.println(cert.getIssuerDN());
//        }

        // to use just server auth, keep first param null, not keyManagers
        sslContext.init(keyManagers,
                // new MyFakeX509TrustManager[]{new MyFakeX509TrustManager((X509TrustManager) tmf.getTrustManagers()[0])},
                new TrustManager[]{new MyFakeX509TrustManager((X509TrustManager) tmf.getTrustManagers()[0])},
                new java.security.SecureRandom() );
        sslFactory = sslContext.getSocketFactory();


        if (port == -1) {
            port = 443;
        }

        TransportClientProperties tcp = TransportClientPropertiesFactory.create("https");

        //boolean hostInNonProxyList = isHostInNonProxyList(host, tcp.getNonProxyHosts());
        boolean hostInNonProxyList = false;
        Socket sslSocket = null;
        if (tcp.getProxyHost().length() == 0 || hostInNonProxyList) {
            // direct SSL connection
            sslSocket = sslFactory.createSocket(host, port);
        }
        else {

            // Default proxy port is 80, even for https
            int tunnelPort = (tcp.getProxyPort().length() != 0)
                    ? Integer.parseInt(tcp.getProxyPort())
                    : 80;
            if (tunnelPort < 0)
                tunnelPort = 80;

            // Create the regular socket connection to the proxy
            Socket tunnel = new Socket(tcp.getProxyHost(), tunnelPort);

            // The tunnel handshake method (condensed and made reflexive)
            OutputStream tunnelOutputStream = tunnel.getOutputStream();
            PrintWriter out = new PrintWriter(
                    new BufferedWriter(new OutputStreamWriter(tunnelOutputStream)));

            out.print("CONNECT " + host + ":" + port + " HTTP/1.0\r\n"
                    + "User-Agent: AxisClient");
            if (tcp.getProxyUser().length() != 0 &&
                    tcp.getProxyPassword().length() != 0) {

                // add basic authentication header for the proxy
                String encodedPassword = XMLUtils.base64encode((tcp.getProxyUser()
                        + ":"
                        + tcp.getProxyPassword()).getBytes());

                out.print("\nProxy-Authorization: Basic " + encodedPassword);
            }
            out.print("\nContent-Length: 0");
            out.print("\nPragma: no-cache");
            out.print("\r\n\r\n");
            out.flush();
            InputStream tunnelInputStream = tunnel.getInputStream();

            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("isNull00", "tunnelInputStream",
                        "" + (tunnelInputStream
                                == null)));
            }
            String replyStr = "";

            // Make sure to read all the response from the proxy to prevent SSL negotiation failure
            // Response message terminated by two sequential newlines
            int newlinesSeen = 0;
            boolean headerDone = false;    /* Done on first newline */

            while (newlinesSeen < 2) {
                int i = tunnelInputStream.read();

                if (i < 0) {
                    throw new IOException("Unexpected EOF from proxy");
                }
                if (i == '\n') {
                    headerDone = true;
                    ++newlinesSeen;
                } else if (i != '\r') {
                    newlinesSeen = 0;
                    if (!headerDone) {
                        replyStr += String.valueOf((char) i);
                    }
                }
            }
            if (StringUtils.startsWithIgnoreWhitespaces("HTTP/1.0 200", replyStr) &&
                    StringUtils.startsWithIgnoreWhitespaces("HTTP/1.1 200", replyStr)) {
                throw new IOException(Messages.getMessage("cantTunnel00",
                        new String[]{
                                tcp.getProxyHost(),
                                "" + tunnelPort,
                                replyStr}));
            }

            // End of condensed reflective tunnel handshake method
            sslSocket = sslFactory.createSocket(tunnel, host, port, true);
            if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("setupTunnel00",
                        tcp.getProxyHost(),
                        "" + tunnelPort));
            }
        }

        ((SSLSocket) sslSocket).startHandshake();
//        String[] cipherSuites = ((SSLSocket) sslSocket).getSupportedCipherSuites();
//        String[] cipherSuites1 =((SSLSocket) sslSocket).getEnabledCipherSuites();
//        for (int i = 0; i < cipherSuites.length ; i++) {
//            System.out.println("Supported Chipher " + i + " : " + cipherSuites[i].toString());
//
//        }
//
//        for (int i = 0; i < cipherSuites1.length ; i++) {
//            System.out.println("Enabled Chipher " + i + " : " + cipherSuites1[i].toString());
//        }

       /** Koray GÜNEY **/
        SSLSession sslSession = ((SSLSocket) sslSocket).getSession();
        //System.out.println("TLS VERSION : " + sslSession.getProtocol());
        //System.out.println("SSL Context Provider : " + sslContext.getProvider());

        /*for (int i = 0; i < ((SSLSocket) sslSocket).getSupportedProtocols().length ; i++) {
            System.out.println("SUPPORTED PROTOCOLS : " + (((SSLSocket) sslSocket).getSupportedProtocols())[i]);
        }*/
//        javax.security.cert.X509Certificate[] certificates = sslSession.getPeerCertificateChain();
//        X509Certificate certUser = convert(certificates[1]);
//        X509Certificate certRoot = convert(certificates[2]);

//        for (javax.security.cert.X509Certificate cert: certificates) {
//            System.out.println(cert.getSubjectDN());
//        }

        // Create OCSP Client using builder.
//        OcspClient client = OcspClient.builder()
//                .set(OcspClient.EXCEPTION_ON_UNKNOWN, false) // Remove to trigger exception on 'UNKNOWN'.
//                .set(OcspClient.EXCEPTION_ON_REVOKED, false) // Remove to trigger exception on 'REVOKED'.
//                .build();

         // Verify certificate (issuer certificate required).
//         CertificateResult response = client.verify(certUser, certRoot);


        // Prints 'GOOD', 'REVOKED' or 'UNKNOWN'.
//        Properties properties = null;
//        URI uri = new MainTest().ocspURI(certUser);
//        System.out.println(uri.toString());
//
//         System.out.println(response.getStatus());
        /** Koray GÜNEY **/

        if (log.isDebugEnabled()) {
            log.debug(Messages.getMessage("createdSSL00"));
        }
        return sslSocket;
    }

    /**
     * Class FakeX509TrustManager
     */
    public static class MyFakeX509TrustManager implements X509TrustManager {

        X509TrustManager myTrustManager;

        public MyFakeX509TrustManager(X509TrustManager myTrustManager)
        {
            this.myTrustManager=myTrustManager;
        }

        /** Field log           */
        protected static Log log =
                LogFactory.getLog(MyFakeTrustSocketFactory.MyFakeX509TrustManager.class.getName());

        //TODO :
        public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            return;
        }
        //TODO :
        public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
            //X509Certificate[] testcert = getAcceptedIssuers();
            //System.out.println("Serial number : " + testcert[1].getSerialNumber());
            try {
                OCSP.RevocationStatus ocspStatus = OCSP.check(x509Certificates[0], x509Certificates[1]);
                System.out.println("TEST :" + ocspStatus.getCertStatus().toString());
                System.out.println("SONUC:  "+x509Certificates[1].getIssuerDN());
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CertPathValidatorException e) {
                e.printStackTrace();
            }

            try {
                myTrustManager.checkServerTrusted(x509Certificates,s);
            } catch (CertificateException e) {
                e.printStackTrace();
            }

            /* Create OCSP Client using builder.
            OcspClient client = OcspClient.builder()
                    //.set(OcspClient.EXCEPTION_ON_UNKNOWN, false) // Remove to trigger exception on 'UNKNOWN'.
                    //.set(OcspClient.EXCEPTION_ON_REVOKED, false) // Remove to trigger exception on 'REVOKED'.
                    .build();
            // Verify certificate (issuer certificate required).
            CertificateResult response = null;

            int certificateChainSize= x509Certificates.length;
            System.out.println("Total cert in the chain : " + certificateChainSize);

            try {
                for (int i = 0; i < certificateChainSize-1 ; i++) {
                    response = client.verify(x509Certificates[i], x509Certificates[i+1]);
                    System.out.println("Validated cert no: " + x509Certificates[i].getSerialNumber());
                }
            } catch (OcspException e) {
                e.printStackTrace();
            }

            // Prints 'GOOD', 'REVOKED' or 'UNKNOWN'.
            Properties properties = null;
            URI uri = null;
            try {
                uri = new AbstractOcspClient(properties).detectOcspUri(x509Certificates[0]);
            } catch (OcspException e) {
                e.printStackTrace();
            }
            System.out.println(uri.toString());
            System.out.println(response.getStatus()); */
        }

        /**
         * Method getAcceptedIssuers
         *
         * @return
         */
        public X509Certificate[] getAcceptedIssuers() {

           /* if (log.isDebugEnabled()) {
                log.debug(Messages.getMessage("My Fake Trust manager get accepted issuers"));
            }
            return null;*/

             return myTrustManager.getAcceptedIssuers();
            // return new X509Certificate[0];


        }
    }

    public static java.security.cert.X509Certificate convert(javax.security.cert.X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
            java.security.cert.CertificateFactory cf
                    = java.security.cert.CertificateFactory.getInstance("X.509");
            return (java.security.cert.X509Certificate)cf.generateCertificate(bis);
        } catch (java.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateEncodingException e) {
        } catch (java.security.cert.CertificateException e) {
        }
        return null;
    }

//    public List<X509Certificate> parse(FileInputStream fis) throws CertificateException {
//        /*
//         * Generate a X509 Certificate initialized with the data read from the inputstream.
//         * NOTE: Generation fails when using BufferedInputStream on PKCS7 certificates.
//         */
//        System.out.println("In the parse method");
//        List<X509Certificate> certificates = null;
//
//        certificates = (List<X509Certificate>) certificateFactory().generateCertificates(fis);
//        // System.out.println("Certificates size : " + certificates.get(0).getSerialNumber());
//        return certificates;
//    }

//    public static final CertificateFactory certificateFactory () throws CertificateException {
//        CertificateFactory cf = CertificateFactory.getInstance("X.509");
//        return cf;
//    }

//    private Boolean validateChain(List<X509Certificate> certificates) throws NoSuchAlgorithmException, CertPathValidatorException, InvalidAlgorithmParameterException {
//        PKIXParameters params;
//        CertPath certPath;
//        CertPathValidator certPathValidator;
//        Boolean valid = Boolean.FALSE;
//
//        params = new PKIXParameters();
//        params.setRevocationEnabled(false);
//
//        certPath = cf.generateCertPath(certificates);
//        certPathValidator = CertPathValidator.getInstance("PKIX");
//
//        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult)
//                certPathValidator.validate(certPath, params);
//
//        if(null != result) {
//            valid = Boolean.TRUE;
//        }
//        return valid;
//    }

}
