package com.distrimind.bouncycastle.math.ec.endo;

import java.math.BigInteger;

import com.distrimind.bouncycastle.math.ec.ECCurve;
import com.distrimind.bouncycastle.math.ec.ECPointMap;
import com.distrimind.bouncycastle.math.ec.ScaleYNegateXPointMap;

public class GLVTypeAEndomorphism implements GLVEndomorphism
{
    protected final GLVTypeAParameters parameters;
    protected final ECPointMap pointMap;

    public GLVTypeAEndomorphism(ECCurve curve, GLVTypeAParameters parameters)
    {
        /*
         * NOTE: 'curve' MUST only be used to create a suitable ECFieldElement. Due to the way
         * ECCurve configuration works, 'curve' will not be the actual instance of ECCurve that the
         * endomorphism is being used with.
         */

        this.parameters = parameters;
        this.pointMap = new ScaleYNegateXPointMap(curve.fromBigInteger(parameters.getI()));
    }

    public BigInteger[] decomposeScalar(BigInteger k)
    {
        return EndoUtil.decomposeScalar(parameters.getSplitParams(), k);
    }

    public ECPointMap getPointMap()
    {
        return pointMap;
    }

    public boolean hasEfficientPointMap()
    {
        return true;
    }
}
