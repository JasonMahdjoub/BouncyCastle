package com.distrimind.bouncycastle.tls.crypto;

import com.distrimind.bouncycastle.tls.ProtocolVersion;
import com.distrimind.bouncycastle.tls.SecurityParameters;
import com.distrimind.bouncycastle.tls.TlsContext;

/**
 * Carrier class for context-related parameters needed for creating secrets and ciphers.
 */
public class TlsCryptoParameters
{
    private final TlsContext context;

    /**
     * Base constructor.
     *
     * @param context the context for this parameters object.
     */
    public TlsCryptoParameters(TlsContext context)
    {
        this.context = context;
    }

    public SecurityParameters getSecurityParametersConnection()
    {
        return context.getSecurityParametersConnection();
    }

    public SecurityParameters getSecurityParametersHandshake()
    {
        return context.getSecurityParametersHandshake();
    }

    public ProtocolVersion getClientVersion()
    {
        return context.getClientVersion();
    }

    public ProtocolVersion getRSAPreMasterSecretVersion()
    {
        return context.getRSAPreMasterSecretVersion();
    }

    public ProtocolVersion getServerVersion()
    {
        return context.getServerVersion();
    }

    public boolean isServer()
    {
        return context.isServer();
    }

    public TlsNonceGenerator getNonceGenerator()
    {
        return context.getNonceGenerator();
    }
}