package org.bouncycastle.bcmath.ec;

public interface PreCompCallback
{
    PreCompInfo precompute(PreCompInfo existing);
}
