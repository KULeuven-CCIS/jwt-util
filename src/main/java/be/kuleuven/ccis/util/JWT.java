package be.kuleuven.ccis.util;

import java.util.Date;
import java.util.Objects;

public class JWT {
    /**
     * The subject of the JWT, usually a username
     */
    private String subject;
    /**
     * The issuer of the JWT token, usually a URL
     */
    private String issuer;
    /**
     * The expiration date of the token
     */
    private Date expirationDate;

    public JWT(String subject, String issuer, Date expirationDate) {
        this.subject = subject;
        this.issuer = issuer;
        this.expirationDate = expirationDate;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JWT jwt = (JWT) o;
        return Objects.equals(subject, jwt.subject) &&
                Objects.equals(issuer, jwt.issuer) &&
                Objects.equals(expirationDate, jwt.expirationDate);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, issuer, expirationDate);
    }

    @Override
    public String toString() {
        return "JWT{" +
                "subject='" + subject + '\'' +
                ", issuer='" + issuer + '\'' +
                ", expirationDate=" + expirationDate +
                '}';
    }
}
