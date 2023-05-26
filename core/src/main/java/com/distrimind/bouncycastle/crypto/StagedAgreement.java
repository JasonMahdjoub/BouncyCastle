package com.distrimind.bouncycastle.crypto;

import com.distrimind.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface StagedAgreement
    extends BasicAgreement
{
    AsymmetricKeyParameter calculateStage(CipherParameters pubKey);
}
