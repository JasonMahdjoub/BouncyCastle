package com.distrimind.bouncycastle.math.ec.endo;

import com.distrimind.bouncycastle.math.ec.ECPointMap;

public interface ECEndomorphism
{
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}
