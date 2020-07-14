package com.distrimind.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PublicKey;

import com.distrimind.bouncycastle.tls.SignatureAlgorithm;

public class JcaTlsEd25519Verifier
    extends JcaTlsEdDSAVerifier
{
    public JcaTlsEd25519Verifier(JcaTlsCrypto crypto, PublicKey publicKey)
    {
        super(crypto, publicKey, SignatureAlgorithm.ed25519, "Ed25519");
    }
}
