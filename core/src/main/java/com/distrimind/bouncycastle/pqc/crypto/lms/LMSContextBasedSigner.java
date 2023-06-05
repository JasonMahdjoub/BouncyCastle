package com.distrimind.bouncycastle.pqc.crypto.lms;

public interface LMSContextBasedSigner
{
    LMSContext generateLMSContext();

    byte[] generateSignature(LMSContext context);

    long getUsagesRemaining();
}