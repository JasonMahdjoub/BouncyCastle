package com.distrimind.bouncycastle.cms.test;

import com.distrimind.bouncycastle.util.encoders.Base64;

public class CMSSampleMessages
{
  static byte[] originatorMessage = Base64.decode(
            "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"
          + "k9HhGwwsgiR+");
    
}
