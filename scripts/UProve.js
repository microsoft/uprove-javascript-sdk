// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

"use strict";

var UProve = UProve || {};

UProve.Uint8ArrayToArray = function (uint8Array) {
    return (uint8Array.length === 1) ? [uint8Array[0]] : Array.apply(null, uint8Array);
}

//
// Hash
//

// Constructs a new Hash object with an underlying SHA256 hash.
// Usage: create the Hash object, call update... methods, and
// call digest to finalize the hash computation.
UProve.Hash = function Hash() {

    // the underlying hash function
    this.sha256 = msrcryptoSha256.sha256;

    // update the hash with one byte
    // b      - byte - the byte value to hash
    this.updateByte = function (b) {
        this.sha256.process([b]);
    }

    // update the hash with the size of an input
    // size - number - the value to hash
    this.updateUint32 = function (size) {
        var buffer = [
            (size >> 24),
            (size >> 16),
            (size >> 8),
            size
        ];
        this.sha256.process(buffer);
    }

    // update the hash with a byte array
    // bytes      - UintArray - the bytes to hash
    this.updateBytes = function (bytes) {
        this.updateUint32(bytes.length);
        this.sha256.process(UProve.Uint8ArrayToArray(bytes));
    }

    // update the hash with a byte array directly without using U-Prove formatting
    // bytes      - UintArray - the bytes to hash
    this.updateRawBytes = function (bytes) {
        this.sha256.process(UProve.Uint8ArrayToArray(bytes));
    }

    // update the hash with a null value
    this.updateNull = function () {
        this.updateUint32(0);
    }

    // update the hash with a list of bytes
    this.updateListOfBytes = function (list) {
        this.updateUint32(list.length);
        for (var i = 0; i < list.length; i++) {
            this.updateByte(list[i]);
        }
    }

    // update the hash with a list of byte arrays
    this.updateListOfByteArrays = function (list) {
        this.updateUint32(list.length);
        for (var i = 0; i < list.length; i++) {
            this.updateBytes(list[i]);
        }
    }

    // update the hash with a list of indices
    this.updateListOfIndices = function (list) {
        this.updateUint32(list.length);
        for (var i = 0; i < list.length; i++) {
            this.updateUint32(list[i]);
        }
    }

    // update the hash with a list of integer
    this.updateListOfIntegers = function (list) {
        this.updateUint32(list.length);
        for (var i = 0; i < list.length; i++) {
            this.updateBytes(list[i].toByteArrayUnsigned());
        }
    }

    // update the hash with an elliptic curve point
    this.updatePoint = function (point) {
        this.updateBytes(cryptoECC.sec1EncodingFp().encodePoint(point));
    }

    // returns the hash digest
    this.digest = function () {
        return new Uint8Array(this.sha256.finish());
    }
}

//
// Helpers
//

UProve.uint8ArrayToBase64 = function (bytes) {
    return btoa(String.fromCharCode.apply(null, bytes));
}

UProve.base64ToArray = function (b64String) {
    return atob(b64String).split("").map(function (c) { return c.charCodeAt(0); });
}

UProve.base64ToUint8Array = function (b64String) {
    return new Uint8Array(UProve.base64ToArray(b64String));
}

// Computes a*b+c mod q
UProve.ATimesBPlusCModQ = function ATimesBPlusCModQ(Zq, a, b, c) {
    var result = Zq.createElementFromInteger(0);
    Zq.multiply(a, b, result);
    Zq.add(result, c, result);
    return result;
}

UProve.multiModExp = function (Gq, bases, exponents) {
    if (bases.length != exponents.length) {
        throw "bases and exponents have different lengths";
    }
    var result = Gq.getIdentityElement();
    var temp = Gq.getIdentityElement();
    for (var i = 0; i < bases.length; i++) {
        Gq.modexp(bases[i], exponents[i], temp);
        Gq.multiply(result, temp, result);
    }

    return result;
}

UProve.computeX = function (Zq, A, e) {
    var x;
    if (e === 1) {
        if (A === null) {
            x = 0;
        } else {
            var H = new UProve.Hash();
            H.updateBytes(A);
            x = Zq.createModElementFromBytes(H.digest());
        }
    } else if (e === 0) {
        x = Zq.createModElementFromBytes(A);
    } else {
        throw "invalid e value: " + e;
    }
    return x;
}

UProve.computeXArray = function (Zq, attributes, e) {
    var n = attributes.length;
    if (n != e.length) {
        throw "arguments must have the same length";
    }
    var x = new Array(n);
    for (var i = 0; i < n; i++) {
        x[i] = UProve.computeX(Zq, attributes[i], e[i]);
    }
    return x;
}

UProve.computeXt = function (Zq, ip, ti) {
    var P = ip.computeDigest();
    var H = new UProve.Hash();
    H.updateByte(1);
    H.updateBytes(P);
    H.updateBytes(ti);
    return Zq.createModElementFromBytes(H.digest());
}

UProve.computeTokenId = function (token) {
    var hash = new UProve.Hash();
    hash.updateBytes(token.h.toByteArrayUnsigned());
    hash.updateBytes(token.szp.toByteArrayUnsigned());
    hash.updateBytes(token.scp.toByteArrayUnsigned());
    hash.updateBytes(token.srp.toByteArrayUnsigned());
    return hash.digest();
}

UProve.computeSigmaCPrime = function (Zq, h, pi, sigmaZPrime, sigmaAPrime, sigmaBPrime) {
    var hash = new UProve.Hash();
    hash.updateBytes(h.toByteArrayUnsigned());
    hash.updateBytes(pi);
    hash.updateBytes(sigmaZPrime.toByteArrayUnsigned());
    hash.updateBytes(sigmaAPrime.toByteArrayUnsigned());
    hash.updateBytes(sigmaBPrime.toByteArrayUnsigned());
    return Zq.createModElementFromBytes(hash.digest());
}

UProve.generateChallenge = function (Zq, issuerParam, token, a, D, disclosedX, C, tildeC, tildeA, p, ap, Ps, m, md) {
    // cp = H(uidt, a, <D>, <{xi}_in D>, C, <{tildeCi}_in C>, <{tildeAi}_in C>, p', ap, Ps, m)
    var uidt = UProve.computeTokenId(token);
    var hash = new UProve.Hash();
    hash.updateBytes(uidt);
    hash.updateBytes(a);
    hash.updateListOfIndices(D);
    hash.updateListOfIntegers(disclosedX);
    C ? hash.updateListOfIndices(C) : hash.updateNull();
    tildeC ? hash.updateListOfIntegers(tildeC) : hash.updateNull();
    tildeA ? hash.updateListOfByteArrays(tildeA) : hash.updateNull();
    hash.updateUint32(p); // p'
    ap ? hash.updateBytes(ap) : hash.updateNull();
    Ps ? hash.updateBytes(Ps.toByteArrayUnsigned()) : hash.updateNull();
    hash.updateBytes(m);
    var cp = hash.digest();

    // c = H(<cp, md>) --> Zq
    hash = new UProve.Hash();
    hash.updateUint32(2);
    hash.updateBytes(cp);
    md ? hash.updateBytes(md) : hash.updateNull();
    return Zq.createModElementFromBytes(hash.digest());
}

UProve.generateIdEscrowChallenge = function (Zq, UIDp, UIDt, H, CbBytes, E1, E2, CbPrime, E1Prime, E2Prime, additionalInfo) {
    // H(UID_p, UID_t, H, Cxb, E1, E2, Cxb', E1', E2', additionalInfo)
    var hash = new UProve.Hash();
    hash.updateBytes(UIDp);
    hash.updateBytes(UIDt);
    hash.updateBytes(H.toByteArrayUnsigned());
    hash.updateBytes(CbBytes);
    hash.updateBytes(E1.toByteArrayUnsigned());
    hash.updateBytes(E2.toByteArrayUnsigned());
    hash.updateBytes(CbPrime.toByteArrayUnsigned());
    hash.updateBytes(E1Prime.toByteArrayUnsigned());
    hash.updateBytes(E2Prime.toByteArrayUnsigned());
    hash.updateBytes(additionalInfo);
    return Zq.createModElementFromBytes(hash.digest());
}

UProve.IssuerParams = function IssuerParams(uidp, descGq, g, e, s) {
    this.uidp = uidp;
    this.descGq = descGq;
    this.g = g;
    this.e = e;
    this.s = s;

    UProve.IssuerParams.prototype.isValid = function () {
        // verify that g0 is a group element, all other params are fixed
        return true;
    }

    UProve.IssuerParams.prototype.computeDigest = function () {
        if (this.P === undefined) {
            var H = new UProve.Hash();
            H.updateBytes(this.uidp);
            this.descGq.updateHash(H);
            H.updateListOfIntegers(this.g);
            H.updateListOfBytes(this.e);
            H.updateBytes(this.s);
            this.P = H.digest();
        }
        return this.P;
    }

    UProve.IssuerParams.prototype.ParseFirstMessage = function (fmObj) {
        try {
            if (!fmObj.sz || !fmObj.sa || !fmObj.sb || fmObj.sa.length != fmObj.sb.length) {
                throw "invalid serialization";
            }

            var firstMsg = {};
            var Gq = this.descGq.getGq();

            firstMsg.sz = Gq.createElementFromBytes(UProve.base64ToUint8Array(fmObj.sz));
            var numberOfTokens = fmObj.sa.length;
            firstMsg.sa = new Array(numberOfTokens);
            firstMsg.sb = new Array(numberOfTokens);
            for (var i = 0; i < numberOfTokens; i++) {
                firstMsg.sa[i] = Gq.createElementFromBytes(UProve.base64ToUint8Array(fmObj.sa[i]));
                firstMsg.sb[i] = Gq.createElementFromBytes(UProve.base64ToUint8Array(fmObj.sb[i]));
            }
        } catch (e) {
            throw new "can't parse first message: " + e;
        }
        return firstMsg;
    }

    UProve.IssuerParams.prototype.ParseThirdMessage = function (tmObj) {
        try {
            if (!tmObj.sr) {
                throw "invalid serialization";
            }

            var thirdMsg = {};
            var Zq = this.descGq.getZq();

            var numberOfTokens = tmObj.sr.length;
            thirdMsg.sr = new Array(numberOfTokens);
            for (var i = 0; i < numberOfTokens; i++) {
                thirdMsg.sr[i] = Zq.createElementFromBytes(UProve.base64ToUint8Array(tmObj.sr[i]));
            }
        } catch (e) {
            throw new "can't parse third message: " + e;
        }
        return thirdMsg;
    }

    UProve.IssuerParams.prototype.ParseKeyAndToken = function (ukatObj) {
        var keyAndToken = {};
        var Gq = this.descGq.getGq();
        var Zq = this.descGq.getZq();
        try {
            if (!ukatObj.token || !ukatObj.key || !ukatObj.token.uidp || !ukatObj.token.h || !ukatObj.token.szp || !ukatObj.token.scp || !ukatObj.token.srp) {
                throw "invalid serialization";
            }
            
            keyAndToken.token = {
                "uidp": UProve.base64ToUint8Array(ukatObj.token.uidp),
                "h": Gq.createElementFromBytes(UProve.base64ToUint8Array(ukatObj.token.h)),
                "ti": ukatObj.token.ti ? UProve.base64ToUint8Array(ukatObj.token.ti) : null,
                "pi": ukatObj.token.pi ? UProve.base64ToUint8Array(ukatObj.token.pi) : null,
                "szp": Gq.createElementFromBytes(UProve.base64ToUint8Array(ukatObj.token.szp)),
                "scp": Zq.createElementFromBytes(UProve.base64ToUint8Array(ukatObj.token.scp)),
                "srp": Zq.createElementFromBytes(UProve.base64ToUint8Array(ukatObj.token.srp)),
                "d": false
            }
            keyAndToken.key = Zq.createElementFromBytes(UProve.base64ToUint8Array(ukatObj.key));
        } catch (e) {
            throw new "can't parse key and token: " + e;
        }
        return keyAndToken;
    }


    UProve.ParseIDEscrowParams = function (ieParamsObj) {
        var obj = {}
        try {
            if (!ieParamsObj.uidp || !ieParamsObj.ge) {
                throw "missing field";
            }
            obj.uipd = UProve.base64ToUint8Array(ieParamsObj.uidp);
            obj.ge = this.descGq.getGq().createElementFromBytes(UProve.base64ToUint8Array(ieParamsObj.ge));
            } catch (e) {
                throw "can't parse id escrow params: " + e;
            }
        return obj;
    }

    UProve.ParseIDEscrowPublicKey = function (iePubKeyObj) {
        var obj = {}
        try {
            if (!iePubKeyObj.H) {
                throw "missing field";
            }
            obj.H = this.descGq.getGq().createElementFromBytes(UProve.base64ToUint8Array(iePubKeyObj.H));
        } catch (e) {
            throw "can't parse id escrow params: " + e;
        }
        return obj;
    }
}

UProve.ParseIssuerParams = function (ipObj) {
    try {
        if (!ipObj.uidp || !ipObj.descGq || !ipObj.e || !ipObj.g || !ipObj.s) {
            throw "missing field";
        }

        var uidp = UProve.base64ToUint8Array(ipObj.uidp);
        var descGq;
        if (ipObj.descGq.name == UProve.L2048N256.OID) {
            descGq = new UProve.L2048N256();
        } else if (ipObj.descGq.name == UProve.ECP256.OID) {
            descGq = new UProve.ECP256();
        } else {
            throw "unknown group: " + ipObj.descGq.name;
        }
        var e = UProve.base64ToArray(ipObj.e);
        var numAttribs = e.length;
        var g = descGq.getPreGenGenerators(numAttribs);
        g[0] = descGq.getGq().createElementFromBytes(UProve.base64ToUint8Array(ipObj.g[0]));
        var s = UProve.base64ToUint8Array(ipObj.s);
    } catch (e) {
        throw "can't parse issuer parameters: " + e;
    }
    return new UProve.IssuerParams(uidp, descGq, g, e, s);
}

UProve.Prover = function Prover(rng, ip) {
    this.rng = rng;
    this.ip = ip;
    this.Gq = this.ip.descGq.getGq();
    this.Zq = this.ip.descGq.getZq();

    UProve.Prover.prototype.generateSecondMessage = function (numberOfTokens, attributes, ti, pi, externalGamma, firstMsg, skipTokenValidation) {

        var validateToken = skipTokenValidation ? false : true;
        this.ti = ti;
        this.pi = pi;
        var generator = this.ip.descGq.getGenerator();

        this.numberOfTokens = numberOfTokens;
        this.secondMsg = { "sc" : [] } 
        this.h = new Array(this.numberOfTokens);
        this.alphaInverse = new Array(this.numberOfTokens);
        this.beta2 = new Array(this.numberOfTokens);
        this.sigmaZPrime = new Array(this.numberOfTokens);
        this.sigmaCPrime = new Array(this.numberOfTokens);
        if (validateToken) {
            this.tokenValidationValue = new Array(this.numberOfTokens);
        }

        // Prover input
        var gamma;
        if (!externalGamma) {
            var x = UProve.computeXArray(this.Zq, attributes, this.ip.e);
            x.unshift(this.Zq.createElementFromInteger(1)); // exponent 1 for g0
            x.push(UProve.computeXt(this.Zq, this.ip, ti));
            // compute gamma = g0 * g1^x1 * ... * gn^xn * gt^xt
            gamma = UProve.multiModExp(this.Gq, this.ip.g, x);
        } else {
            gamma = this.Gq.createElementFromBytes(externalGamma);
        }
        var sigmaZ = firstMsg.sz;
        for (var i = 0; i < this.numberOfTokens; i++) {
            // Prover precomputation
            var alpha = this.rng.getRandomZqElement();
            var beta1 = this.rng.getRandomZqElement();
            this.beta2[i] = this.rng.getRandomZqElement();

            // compute h = gamma^alpha
            this.h[i] = this.Gq.getIdentityElement();
            this.Gq.modexp(gamma, alpha, this.h[i]);
            // compute alpha^-1
            this.alphaInverse[i] = this.Zq.createElementFromInteger(0);
            this.Zq.inverse(alpha, this.alphaInverse[i]);

            var sigmaA = firstMsg.sa[i];
            var sigmaB = firstMsg.sb[i];

            // compute sigmaZPrime = sigmaZ ^ alpha
            this.sigmaZPrime[i] = this.Gq.getIdentityElement();
            this.Gq.modexp(sigmaZ, alpha, this.sigmaZPrime[i]);

            // compute sigmaAPrime = g0^beta1 * g^beta2 * sigmaA
            var bases = new Array(this.ip.g[0], generator);
            var exponents = new Array(beta1, this.beta2[i]);
            var sigmaAPrime = UProve.multiModExp(this.Gq, bases, exponents);
            this.Gq.multiply(sigmaAPrime, sigmaA, sigmaAPrime);

            // compute sigmaBPrime = sigmaZPrime^beta1 * h^beta2 * sigmaB^alpha
            bases = new Array(this.sigmaZPrime[i], this.h[i], sigmaB);
            exponents = new Array(beta1, this.beta2[i], alpha);
            var sigmaBPrime = UProve.multiModExp(this.Gq, bases, exponents);

            // compute sigmaCPrime = H(h, PI, sigmaZPrime, sigmaAPrime, sigmaBPrime) mod q
            this.sigmaCPrime[i] = UProve.computeSigmaCPrime(this.Zq, this.h[i], pi, this.sigmaZPrime[i], sigmaAPrime, sigmaBPrime);

            // compute sigmaC = sigmaCPrime + beta1
            var sigmaC = this.Zq.createElementFromInteger(0);
            this.Zq.add(this.sigmaCPrime[i], beta1, sigmaC);

            this.secondMsg.sc[i] = UProve.uint8ArrayToBase64(sigmaC.toByteArrayUnsigned());
            if (validateToken) {
                // value = sigmaA' . sigmaB' . (g0 . sigmaZ')^sigmaC'
                var value = this.Gq.getIdentityElement();
                var temp = this.Gq.getIdentityElement();
                this.Gq.multiply(sigmaAPrime, sigmaBPrime, value);
                this.Gq.multiply(this.ip.g[0], this.sigmaZPrime[i], temp);
                this.Gq.modexp(temp, this.sigmaCPrime[i], temp);
                this.Gq.multiply(value, temp, value);
                this.tokenValidationValue[i] = value;
            }
        }

        return this.secondMsg;
    }

    UProve.Prover.prototype.getIssuanceState = function () {
        var state = {};
        state.h = new Array(this.numberOfTokens);
        state.alphaInverse = new Array(this.numberOfTokens);
        state.beta2 = new Array(this.numberOfTokens);
        state.sigmaZPrime = new Array(this.numberOfTokens);
        state.sigmaCPrime = new Array(this.numberOfTokens);
        if (this.tokenValidationValue) {
            state.tokenValidationValue = new Array(this.numberOfTokens);
        }
        for (var i = 0; i < this.numberOfTokens; i++) {
            state.h[i] = UProve.uint8ArrayToBase64(this.h[i].toByteArrayUnsigned());
            state.alphaInverse[i] = UProve.uint8ArrayToBase64(this.alphaInverse[i].toByteArrayUnsigned());
            state.beta2[i] = UProve.uint8ArrayToBase64(this.beta2[i].toByteArrayUnsigned());
            state.sigmaZPrime[i] = UProve.uint8ArrayToBase64(this.sigmaZPrime[i].toByteArrayUnsigned());
            state.sigmaCPrime[i] = UProve.uint8ArrayToBase64(this.sigmaCPrime[i].toByteArrayUnsigned());
            if (this.tokenValidationValue) {
                state.tokenValidationValue[i] = UProve.uint8ArrayToBase64(this.tokenValidationValue[i].toByteArrayUnsigned());
            }
        }
        return state;
    }

    UProve.Prover.prototype.setIssuanceState = function (state) {
        if (!state || !state.h || !state.alphaInverse || !state.beta2 || !state.sigmaZPrime || !state.sigmaCPrime) {
            throw "invalid state";
        }
        this.numberOfTokens = state.h.length;
        this.h = new Array(this.numberOfTokens);
        this.alphaInverse = new Array(this.numberOfTokens);
        this.beta2 = new Array(this.numberOfTokens);
        this.sigmaZPrime = new Array(this.numberOfTokens);
        this.sigmaCPrime = new Array(this.numberOfTokens);
        if (state.tokenValidationValue) {
            this.tokenValidationValue = new Array(this.numberOfTokens);
        }
        for (var i = 0; i < this.numberOfTokens; i++) {
            this.h[i] = this.Gq.createElementFromBytes(UProve.base64ToUint8Array(state.h[i]));
            this.alphaInverse[i] = this.Zq.createElementFromBytes(UProve.base64ToUint8Array(state.alphaInverse[i]));
            this.beta2[i] = this.Zq.createElementFromBytes(UProve.base64ToUint8Array(state.beta2[i]));
            this.sigmaZPrime[i] = this.Gq.createElementFromBytes(UProve.base64ToUint8Array(state.sigmaZPrime[i]));
            this.sigmaCPrime[i] = this.Zq.createElementFromBytes(UProve.base64ToUint8Array(state.sigmaCPrime[i]));
            if (state.tokenValidationValue) {
                this.tokenValidationValue[i] = this.Gq.createElementFromBytes(UProve.base64ToUint8Array(state.tokenValidationValue[i]));
            }
        }
    }

    UProve.Prover.prototype.generateTokens = function (thirdMsg) {
        if (this.numberOfTokens != thirdMsg.sr.length) {
            throw "invalid length for message";
        }
        var keyAndTokens = new Array(this.numberOfTokens);
        for (var i = 0; i < this.numberOfTokens; i++) {

            var sigmaR = thirdMsg.sr[i];
            var sigmaRPrime = this.Zq.createElementFromInteger(0);
            this.Zq.add(sigmaR, this.beta2[i], sigmaRPrime);

            // validate the token
            if (this.tokenValidationValue) {
                var temp = this.Gq.getIdentityElement();
                this.Gq.multiply(this.ip.descGq.getGenerator(), this.h[i], temp);
                this.Gq.modexp(temp, sigmaRPrime, temp);
                if (!this.tokenValidationValue[i].equals(temp)) {
                    throw "invalid signature for token " + i;
                }
            }

            keyAndTokens[i] = {
                token: {
                    "h": UProve.uint8ArrayToBase64(this.h[i].toByteArrayUnsigned()),
                    "szp": UProve.uint8ArrayToBase64(this.sigmaZPrime[i].toByteArrayUnsigned()),
                    "scp": UProve.uint8ArrayToBase64(this.sigmaCPrime[i].toByteArrayUnsigned()),
                    "srp": UProve.uint8ArrayToBase64(sigmaRPrime.toByteArrayUnsigned()),
                },
                key: UProve.uint8ArrayToBase64(this.alphaInverse[i].toByteArrayUnsigned())
            }
        }
        return keyAndTokens;
    }

    UProve.Prover.prototype.generateProof = function (keyAndToken, D, C, m, md, attributes, scopeData, commitmentPrivateValues) {

        if (!keyAndToken || !keyAndToken.key || !keyAndToken.token) {
            throw "invalid key and token";
        }
        var n = ip.e.length;
        var t = n + 1;
        if (n != attributes.length) {
            throw "wrong number of attributes";
        }
        if (scopeData) {
            if (!scopeData.p || scopeData.p <= 0 || scopeData.p >= n) {
                throw "invalid pseudonym index: " + scopeData.p;
            }
            if (!scopeData.s && !scopeData.gs) {
                throw "either scopeData.s or scopeData.gs must be set";
            }
        }

        var token = keyAndToken.token;

        // make sure D and C arrays is sorted
        D.sort(function (a, b) { return a - b; } ); // from Crockford's "JavaScript: the good parts"
        if (C) {
            C.sort(function (a, b) { return a - b; } ); // from Crockford's "JavaScript: the good parts"
        }
        var x = new Array(n + 2);
        var size = 1 + (n - D.length);
        var disclosedA = new Array(D.length);
        var disclosedX = new Array(D.length);
        var w = new Array(size);
        var bases = new Array(size);
        w[0] = this.rng.getRandomZqElement();
        bases[0] = token.h;
        var uIndex = 1;
        var dIndex = 0;
        var cIndex = 0;
        var wpIndex = 0;
        var commitmentData = {};
        if (C) {
            commitmentData.tildeC = new Array(C.length);
            commitmentData.tildeA = new Array(C.length);
            commitmentData.tildeO = new Array(C.length);
            commitmentData.tildeW = new Array(C.length);
        }
        for (var i = 1; i <= n; i++) {
            x[i] = UProve.computeX(this.Zq, attributes[i - 1], this.ip.e[i - 1]);
            if (i == D[dIndex]) {
                // xi is disclosed
                disclosedX[dIndex] = x[i];
                disclosedA[dIndex] = UProve.uint8ArrayToBase64(attributes[i - 1]);
                dIndex++;
            } else {
                // xi is undisclosed
                w[uIndex] = this.rng.getRandomZqElement();
                bases[uIndex] = this.ip.g[i];
                if (scopeData && scopeData.p == i) {
                    wpIndex = uIndex;
                }

                if (C && C.lastIndexOf(i.toString()) >= 0) {
                    // xi is committed
                    commitmentData.tildeO[cIndex] = this.rng.getRandomZqElement();
                    commitmentData.tildeW[cIndex] = this.rng.getRandomZqElement();
                    var cBases = [this.ip.descGq.getGenerator(), this.ip.g[1]];
                    commitmentData.tildeC[cIndex] = UProve.multiModExp(this.Gq, cBases, [x[i], commitmentData.tildeO[cIndex]]);
                    var tildeAInput = UProve.multiModExp(this.Gq, cBases, [w[uIndex], commitmentData.tildeW[cIndex]]);
                    var hash = new UProve.Hash();
                    hash.updateBytes(tildeAInput.toByteArrayUnsigned());
                    commitmentData.tildeA[cIndex] = hash.digest();
                    cIndex++;
                }

                uIndex++;
            }
        }
        x[t] = UProve.computeXt(this.Zq, this.ip, token.ti); // xt
        var aInput = UProve.multiModExp(this.Gq, bases, w);
        var hash = new UProve.Hash();
        hash.updateBytes(aInput.toByteArrayUnsigned());
        var a = hash.digest();
        var ap = null;
        var Ps = null;
        if (scopeData) {
            var gs;
            if (scopeData.gs) {
                gs = this.Gq.createElementFromBytes(scopeData.gs);
            } else {
                gs = this.ip.descGq.generateScopeElement(scopeData.s);
            }
            var apInput = this.Gq.getIdentityElement();
            this.Gq.modexp(gs, w[wpIndex], apInput);
            var hash = new UProve.Hash();
            hash.updateBytes(apInput.toByteArrayUnsigned());
            ap = hash.digest();
            Ps = this.Gq.getIdentityElement();
            this.Gq.modexp(gs, x[scopeData.p], Ps);
        }

            /* FIXME: delete
                   if (C) {
            commitmentData.tildeC = new Array(C.length);
            commitmentData.tildeA = new Array(C.length);
            commitmentData.tildeO = new Array(C.length);
            commitmentData.tildeW = new Array(C.length);
            for (var i = 0; i < C.length; i++) {
                commitmentData.tildeO[i] = this.rng.getRandomZqElement();
                commitmentData.tildeW[i] = this.rng.getRandomZqElement();
                var bases = new Array(this.ip.descGq.getGenerator(), this.ip.g[1]);
                var exponents = new Array(x[C[i]], commitmentData.tildeO[i]);
                commitmentData.tildeC[i] = UProve.multiModExp(this.Gq, bases, exponents);
                exponents = new Array(w[i+1], commitmentData.tildeW[i]);
                var tildeAInput = UProve.multiModExp(this.Gq, bases, exponents);
                var hash = new UProve.Hash();
                hash.updateBytes(tildeAInput.toByteArrayUnsigned());
                commitmentData.tildeA[i] = hash.digest();
            }
            */

        var c = UProve.generateChallenge(this.Zq, this.ip, token, a, D, disclosedX, C, commitmentData.tildeC, commitmentData.tildeA, scopeData ? scopeData.p : 0, ap, Ps, m, md);
        var cNegate = this.Zq.createElementFromInteger(0);
        this.Zq.subtract(this.Zq.createElementFromInteger(0), c, cNegate);

        var r = new Array(size);
        r[0] = UProve.uint8ArrayToBase64(UProve.ATimesBPlusCModQ(this.Zq, c, keyAndToken.key, w[0]).toByteArrayUnsigned());
        dIndex = 0;
        uIndex = 1;
        for (var i = 1; i <= n; i++) {
            if (i == D[dIndex]) {
                // xi is disclosed
                dIndex++;
            } else {
                // xi is undisclosed, compute a response
                r[uIndex] = UProve.uint8ArrayToBase64(UProve.ATimesBPlusCModQ(this.Zq, cNegate, x[i], w[uIndex]).toByteArrayUnsigned());
                uIndex++;
            }
        }
        if (C) {
            commitmentData.tildeR = new Array(C.length);
            for (var i = 0; i < C.length; i++) {
                commitmentData.tildeR[i] = UProve.uint8ArrayToBase64(
                    UProve.ATimesBPlusCModQ(this.Zq, cNegate,
                    commitmentData.tildeO[i], commitmentData.tildeW[i]).toByteArrayUnsigned());
                commitmentData.tildeC[i] = UProve.uint8ArrayToBase64(commitmentData.tildeC[i].toByteArrayUnsigned());
                commitmentData.tildeA[i] = UProve.uint8ArrayToBase64(commitmentData.tildeA[i]);
            }
        }

        var proof = {
            "D": disclosedA,
            "a": UProve.uint8ArrayToBase64(a),
            "r": r
        }
        if (scopeData) {
            proof.ap = UProve.uint8ArrayToBase64(ap);
            proof.Ps = UProve.uint8ArrayToBase64(Ps.toByteArrayUnsigned());
        }
        if (C) {
            proof.tc = commitmentData.tildeC;
            proof.ta = commitmentData.tildeA;
            proof.tr = commitmentData.tildeR;
        }
        if (commitmentPrivateValues && commitmentData.tildeO) {
            commitmentPrivateValues.tildeO = commitmentData.tildeO;
        }
        return proof;
    }

    UProve.Prover.prototype.verifiableEncrypt = function (escrowParams, escrowPublicKey, token, additionalInfo, proof, commitmentPrivateValue, commitmentBytes, idAttribIndex, attribute) {

        var temp = this.Gq.getIdentityElement();
        var generator = this.ip.descGq.getGenerator();

        var r = this.rng.getRandomZqElement();

        var E1 = this.Gq.getIdentityElement();
        this.Gq.modexp(generator, r, E1); // E1 = g^r

        var xb = UProve.computeX(this.Zq, attribute, this.ip.e[idAttribIndex - 1]);
        var E2 = this.Gq.getIdentityElement();
        this.Gq.modexp(generator, xb, E2); // E2 = g^xb
        this.Gq.modexp(escrowPublicKey.H, r, temp); // temp = H^r
        this.Gq.multiply(E2, temp, E2); // E2 = g^xb H^r

        var xbPrime = this.rng.getRandomZqElement();
        var obPrime = this.rng.getRandomZqElement();
        var CbPrime = this.Gq.getIdentityElement();
        this.Gq.modexp(generator, xbPrime, CbPrime); // C'b = g^xb'
        this.Gq.modexp(this.ip.g[1], obPrime, temp); // temp = g1^ob'
        this.Gq.multiply(CbPrime, temp, CbPrime); // C'b = g^xb' g1^ob'

        var rPrime = this.rng.getRandomZqElement();
        var E1Prime = this.Gq.getIdentityElement();
        this.Gq.modexp(generator, rPrime, E1Prime); // E1' = g^r'

        var E2Prime = this.Gq.getIdentityElement();
        this.Gq.modexp(generator, xbPrime, E2Prime); // E2' = g^xb'
        this.Gq.modexp(escrowPublicKey.H, rPrime, temp); // temp = H^r'
        this.Gq.multiply(E2Prime, temp, E2Prime); // E2' = g^xb' H^r'

        var c = UProve.generateIdEscrowChallenge(
            this.Zq, this.ip.uidp, UProve.computeTokenId(token), escrowPublicKey.H, commitmentBytes, E1, E2, CbPrime, E1Prime, E2Prime, additionalInfo);
        var cNegate = this.Zq.createElementFromInteger(0);
        this.Zq.subtract(this.Zq.createElementFromInteger(0), c, cNegate);

        var rxb = UProve.ATimesBPlusCModQ(this.Zq, cNegate, xb, xbPrime); // rXb = xb' - c.xb
        var rr = UProve.ATimesBPlusCModQ(this.Zq, cNegate, r, rPrime); // rr = r' - c.r
        var rob = UProve.ATimesBPlusCModQ(this.Zq, cNegate, commitmentPrivateValue, obPrime); // ro = ob' - c.ob

        var ieProof = {
            "E1": UProve.uint8ArrayToBase64(E1.toByteArrayUnsigned()),
            "E2": UProve.uint8ArrayToBase64(E2.toByteArrayUnsigned()),
            "info": UProve.uint8ArrayToBase64(additionalInfo),
            "ieproof": {
                "c": UProve.uint8ArrayToBase64(c.toByteArrayUnsigned()),
                "rXb": UProve.uint8ArrayToBase64(rxb.toByteArrayUnsigned()),
                "rR": UProve.uint8ArrayToBase64(rr.toByteArrayUnsigned()),
                "rOb": UProve.uint8ArrayToBase64(rob.toByteArrayUnsigned())
            }
        }

        return ieProof;
    }
}
