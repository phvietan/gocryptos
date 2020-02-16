# an-crypto

My work at incognito chain requires me to read lots of papers about Cryptography. To understand those thoroughly, I decided to code those algorithm for educational purposes.

If you'd like to use these code, feel free to do it. However, use it with your own risk.

If anyone find a bug, notify me through Issues.

## Package Curve_utilities

Uses Edwards Twisted Curve (Edwards25519). It contains the core operations for Point, Scalar (Add, Subtract, Multiplication, Hashing,...). The core operation is written by [Dero](https://github.com/deroproject/derosuite), so kudos for them.

I created Curve_utilities for me to use their code easily.

## Package Ring-Signature

Contains multiple ring signatures that uses Edwards Curve. (Will suport more curve in the future).

### Multilayer Linkable Spontaneous Anonymous Group (MLSAG) signature

Located inside /ring-signature/mlsag/*

Currently developing
