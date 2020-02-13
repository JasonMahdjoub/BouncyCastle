package org.bouncycastle.bccrypto.params;

import java.security.SecureRandom;

import org.bouncycastle.bccrypto.KeyGenerationParameters;

public class CramerShoupKeyGenerationParameters
	extends KeyGenerationParameters
{

	private CramerShoupParameters params;

	public CramerShoupKeyGenerationParameters(SecureRandom random, CramerShoupParameters params)
	{
		super(random, getStrength(params));

		this.params = params;
	}

	public CramerShoupParameters getParameters()
	{
		return params;
	}

	static int getStrength(CramerShoupParameters params)
	{
		return params.getP().bitLength();
	}
}
