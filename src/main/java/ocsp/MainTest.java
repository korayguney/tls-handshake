    package ocsp;

    import ocsp.builder.Properties;

    import java.io.*;
    import java.net.URI;
    import java.security.KeyStore;
    import java.security.KeyStoreException;
    import java.security.NoSuchAlgorithmException;
    import java.security.NoSuchProviderException;
    import java.security.cert.*;
    import java.util.Arrays;
    import java.util.Enumeration;
    import java.util.List;

    public class MainTest {

        public static String serverCert= "certs/spidrserver.pem";
        public static String intCert= "certs/spidrinter.pem";
        public static String rootCert= "certs/spidrroot.pem";

        public static String a2serverCert= "certs/a2user.pem";
        public static String a2intCert= "certs/a2intermediate.pem";

        public static String httpserverCert= "certs/httpdiruser.pem";
        public static String httpintCert= "certs/httpdirintermediate.pem";

        public static String revokedcert= "certs/revoked.crt";
        public static String revokedcert2= "certs/revoked2.crt";

        public static String lab9user= "certs/lab9user.crt";
        public static String lab9root= "certs/lab9root.crt";

        public static String web1= "certs/web1.crt";
        public static String web2= "certs/web3.crt";

//        static File certFile = new File(serverCert);
//
//        public static void isFileExist(){
//            if (certFile.exists()){
//                System.out.println("Certificate founded!");
//            }else {
//                System.out.println("Certificate NOT FOUND!");
//            }
//        }

        public static void main(String[] args) throws IOException, CertificateException, OcspException, NoSuchProviderException, KeyStoreException, NoSuchAlgorithmException {
//            isFileExist();

            String ts = "D:\\spidr1.truststore";
            String keyStoreFilePassword = "changeit";

            KeyStore trustStore = KeyStore.getInstance("JKS", "SUN");
            FileInputStream fin = new FileInputStream(ts);
            trustStore.load(fin, keyStoreFilePassword.toCharArray());


//            Enumeration en = trustStore.aliases();
//            System.out.println(en.nextElement().toString());

//            String alias = (String)en.nextElement() ;
            // X509Certificate certs = (X509Certificate) trustStore.getCertificate(alias);
            //System.out.println("Domain Name of cert with "+ alias + " is :" +certs.getIssuerDN());

            X509Certificate certificate = createCert(serverCert);
            X509Certificate issuer = createCert(intCert);


            // Create OCSP Client using builder.
            OcspClient client = OcspClient.builder()
                    .set(OcspClient.EXCEPTION_ON_UNKNOWN, false) // Remove to trigger exception on 'UNKNOWN'.
                    .set(OcspClient.EXCEPTION_ON_REVOKED, false) // Remove to trigger exception on 'REVOKED'.
                    .build();

            // Verify certificate (issuer certificate required).
            CertificateResult response = client.verify(certificate, issuer);


            // Prints 'GOOD', 'REVOKED' or 'UNKNOWN'.
            Properties properties = null;
            URI uri = new AbstractOcspClient(properties).detectOcspUri(certificate);
            System.out.println(uri.toString());

            System.out.println(response.getStatus());

        }

        public static X509Certificate createCert(String certData) throws IOException, CertificateException {
            InputStream inStream = null;
            try {
                inStream = new FileInputStream(certData);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
                return cert;
            } finally {
                if (inStream != null) {
                    inStream.close();
                }
            }
        }

        public URI ocspURI(X509Certificate certificate) throws IOException, CertificateException, OcspException {

            Properties properties = null;
            URI uri = new AbstractOcspClient(properties).detectOcspUri(certificate);
            return uri;
        }
    }
