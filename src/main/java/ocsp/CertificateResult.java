package ocsp;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.util.Date;

/**
 * @author erlend
 */
public class CertificateResult implements Serializable {

    private static final long serialVersionUID = 1058909599853490115L;

    private CertificateIssuer issuer;

    private URI uri;

    private BigInteger serialNumber;

    private CertificateStatus status;

    private Date thisUpdate;

    private Date nextUpdate;

    protected CertificateResult(CertificateStatus certificateStatus, CertificateIssuer issuer, URI uri,
                                BigInteger serialNumber, Date thisUpdate, Date nextUpdate) {
        this(certificateStatus);
        this.issuer = issuer;
        this.uri = uri;
        this.serialNumber = serialNumber;
        this.thisUpdate = thisUpdate;
        this.nextUpdate = nextUpdate;
    }

    protected CertificateResult(CertificateStatus certificateStatus) {
        this.status = certificateStatus;
    }

    public CertificateStatus getStatus() {
        return status;
    }

    public CertificateIssuer getIssuer() {
        return issuer;
    }

    public URI getUri() {
        return uri;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public Date getThisUpdate() {
        return thisUpdate;
    }

    public Date getNextUpdate() {
        return nextUpdate;
    }

    @Override
    public String toString() {
        return "CertificateResult{" +
                "status=" + status +
                ", thisUpdate=" + thisUpdate +
                ", nextUpdate=" + nextUpdate +
                '}';
    }
}
