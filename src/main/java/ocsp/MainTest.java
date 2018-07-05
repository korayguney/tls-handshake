    package ocsp;

    import ocsp.builder.Properties;

    import java.io.*;
    import java.net.URI;
    import java.security.cert.CertificateException;
    import java.security.cert.CertificateFactory;
    import java.security.cert.X509Certificate;

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

        static File certFile = new File(serverCert);

        public static void isFileExist(){
            if (certFile.exists()){
                System.out.println("Certificate founded!");
            }else {
                System.out.println("Certificate NOT FOUND!");
            }
        }

        public static void main(String[] args) throws IOException, CertificateException, OcspException {
            isFileExist();
            X509Certificate certificate = createCert(serverCert);
            X509Certificate issuer = createCert(rootCert);


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

    }
