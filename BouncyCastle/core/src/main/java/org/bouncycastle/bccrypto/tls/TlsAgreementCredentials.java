package org.bouncycastle.bccrypto.tls;

import java.io.IOException;

import org.bouncycastle.bccrypto.params.AsymmetricKeyParameter;

/**
 * @deprecated Migrate to the (D)TLS API in org.bouncycastle.tls (bctls jar).
 */
public interface TlsAgreementCredentials
    extends TlsCredentials
{
    byte[] generateAgreement(AsymmetricKeyParameter peerPublicKey)
        throws IOException;
}
