// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// cryptoECC.js ==================================================================================
/// Implementation of Elliptic Curve math routines for cryptographic applications.

/// #region JSCop/JsHint
/* global createProperty */
/* global cryptoMath */
/* jshint -W016 */ /* allows bitwise operators */
/* jshint -W052 */ /* allows not operator */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="random.js" />

/// <dictionary>alg,bitmasks,coord,De-montgomeryized,digitbits,digitmask,divrem,dont,Elt,endian-ness,endian,gcd,goto,gotta,Int,Jacobi,Jacobian,Legendre,mlen,Modm,modpow,montgomerized,montgomeryize,montgomeryized,montmul,mul,param,Pomerance,povar,precompute,Pseudocode,Tolga,typeof,Uint,unrollsentinel,wil,Xout,Xout-t,Yout,Zout</dictionary>
/// <dictionary>aequals,Eshift,idx,Lsbit,Minust,mult,myelement,myresult,naf,Neg,Nist,numcopy,Obj,onemontgomery,Precomputation,Res,swaptmp,Tmp,xbytes,ybytes</dictionary>

/// #endregion JSCop/JsHint

function MsrcryptoECC() {
    /// <summary>Elliptic Curve Cryptography (ECC) funcions.</summary>

    // Create an array, mimics the constructors for typed arrays.
    function createArray(/*@dynamic*/parameter) {
        var i, array = null;
        if (!arguments.length || typeof arguments[0] === "number") {
            // A number.
            array = [];
            for (i = 0; i < parameter; i += 1) {
                array[i] = 0;
            }
        } else if (typeof arguments[0] === "object") {
            // An array or other index-able object
            array = [];
            for (i = 0; i < parameter.length; i += 1) {
                array[i] = parameter[i];
            }
        }
        return array;
    }

    var btd = cryptoMath.bytesToDigits;
    var utils = msrcryptoUtilities;

    var EllipticCurveFp = function (p1, a1, b1, order, gx, gy) {
        /// <param name="p1" type="Digits"/>
        /// <param name="a1" type="Digits"/>
        /// <param name="b1" type="Digits"/>
        /// <param name="order" type="Digits"/>
        /// <param name="gx" type="Digits"/>
        /// <param name="gy" type="Digits"/>
        /// <returns type="EllipticCurveFp"/>

        var fieldStorageBitLength = p1.length;

        var generator = EllipticCurvePointFp(this, false, gx, gy, null, false);

        return {
            p: p1,                  // field prime
            a: a1,                  // Weierstrass coefficient a
            b: b1,                  // Weierstrass coefficient b
            order: order,           // EC group order
            generator: generator,   // EC group generator
            allocatePointStorage: function () {
                return EllipticCurvePointFp(
                    this,
                    false,
                    cryptoMath.intToDigits(0, fieldStorageBitLength),
                    cryptoMath.intToDigits(0, fieldStorageBitLength)
                    );
            },
            createPointAtInfinity: function () {
                return EllipticCurvePointFp(
                    this,
                    true,
                    cryptoMath.intToDigits(0, fieldStorageBitLength),
                    cryptoMath.intToDigits(0, fieldStorageBitLength)
                    );
            }
        };
    };
    var createANeg3Curve = function (p, b, order, gx, gy) {
        /// <param name="p" type="Digits"/>
        /// <param name="b" type="Digits"/>
        /// <param name="order" type="Digits"/>
        /// <param name="gx" type="Digits"/>
        /// <param name="gy" type="Digits"/>

        var a = cryptoMath.intToDigits(3, p.length);
        cryptoMath.subtract(p, a, a);
        var curve = EllipticCurveFp(p, a, b, order, gx, gy);
        curve.generator.curve = curve;
        return curve;
    };

    var curvesData = {
        "256": { size: 32, data: "/////wAAAAEAAAAAAAAAAAAAAAD///////////////9axjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgS/////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q=="},
        "384": { size: 48, data: "//////////////////////////////////////////7/////AAAAAAAAAAD/////szEvp+I+5+SYjgVr4/gtGRgdnG7+gUESAxQIj1ATh1rGVjmNii7RnSqFyO3T7Crv////////////////////////////////x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSlzqofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f"},
        "521": { size: 32, data: "Af//////////////////////////////////////////////////////////////////////////////////////UZU+uWGOHJofkpohoLaFQO6i2nJbmbMV87i0iZGO8QnhVhk5Uex+k3sWUsC9O7G/BzVz34g9LDTx70Uf1GtQPwAB///////////////////////////////////////////6UYaHg78vlmt/zAFI9wml0Du1ybiJnEeuu2+3HpE4ZAnGhY4GtwQE6c2ePstmI5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQmQMVQuQE/rQdhNTxwhqJywkCIvpR2n9FmUA==" }
    };

    var createP256 = function () {
        return createPCurve("256");
    };

    var createP384 = function () {
        return createPCurve("384");
    };

    var createP521 = function () {
        return createPCurve("521");
    };

    var createPCurve = function (curveSize) {

        var cd = utils.unpackData(curvesData[curveSize].data, curvesData[curveSize].size);

        var newCurve = createANeg3Curve(
            btd(cd[0]), // P
            btd(cd[1]), // B
            btd(cd[2]), // Order
            btd(cd[3]), // gX
            btd(cd[4])  // gy
        );

        newCurve.name = "P-" + curveSize;

        return newCurve;

    };

    var createBN254 = function () {

        return EllipticCurveFp(
            cryptoMath.stringToDigits("16798108731015832284940804142231733909889187121439069848933715426072753864723", 10), // 'p'
            cryptoMath.intToDigits(0, 16), // 'a'
            cryptoMath.intToDigits(2, 16), // 'b'
            cryptoMath.stringToDigits("16798108731015832284940804142231733909759579603404752749028378864165570215949", 10), // 'order'
            cryptoMath.stringToDigits("16798108731015832284940804142231733909889187121439069848933715426072753864722", 10), // 'gx = -1'
            cryptoMath.intToDigits(1, 16) // 'gy = 1'
            );
    };
    var EllipticCurvePointFp = function (curve, isInfinity, x, y, z, isInMontgomeryForm) {
        /// <param name="curve" type="EllipticCurveFp"/>
        /// <param name="isInfinity" type="Boolean"/>
        /// <param name="x" type="Digits"/>
        /// <param name="y" type="Digits"/>
        /// <param name="z" type="Digits" optional="true"/>
        /// <param name="isInMontgomeryForm" type="Boolean" optional="true"/>
        /// <returns type="EllipticCurvePointFp"/>

        var returnObj;

        // 'optional' parameters
        if (typeof z === "undefined") {
            z = null;
        }

        if (typeof isInMontgomeryForm === "undefined") {
            isInMontgomeryForm = false;
        }

        function equals(/*@type(EllipticCurvePointFp)*/ellipticCurvePointFp) {
            /// <param name="ellipticCurvePointFp" type="EllipticCurvePointFp"/>

            // If null
            if (!ellipticCurvePointFp) {
                return false;
            }

            // Infinity == infinity
            if (returnObj.isInfinity && ellipticCurvePointFp.isInfinity) {
                return true;
            }

            // Otherwise its member-wise comparison

            if (returnObj.z === null && ellipticCurvePointFp.z !== null) {
                return false;
            }

            if (returnObj.z !== null && ellipticCurvePointFp.z === null) {
                return false;
            }

            if (returnObj.z === null) {
                return (cryptoMath.sequenceEqual(returnObj.x, ellipticCurvePointFp.x) &&
                         cryptoMath.sequenceEqual(returnObj.y, ellipticCurvePointFp.y) &&
                         returnObj.isInMontgomeryForm === ellipticCurvePointFp.isInMontgomeryForm);
            }

            return (cryptoMath.sequenceEqual(returnObj.x, ellipticCurvePointFp.x) &&
                    cryptoMath.sequenceEqual(returnObj.y, ellipticCurvePointFp.y) &&
                    cryptoMath.sequenceEqual(returnObj.z, ellipticCurvePointFp.z) &&
                    returnObj.isInMontgomeryForm === ellipticCurvePointFp.isInMontgomeryForm);
        }

        function copyTo(/*@type(EllipticCurvePointFp)*/ source, /*@type(EllipticCurvePointFp)*/ destination) {
            /// <param name="source" type="EllipticCurvePointFp"/>
            /// <param name="destination" type="EllipticCurvePointFp"/>

            destination.curve = source.curve;
            destination.x = source.x.slice();
            destination.y = source.y.slice();

            if (source.z !== null) {
                destination.z = source.z.slice();
            } else {
                destination.z = null;
            }

            setterSupport || (destination.isAffine = source.isAffine);
            destination.isInMontgomeryForm = source.isInMontgomeryForm;
            destination.isInfinity = source.isInfinity;

            if (!destination.equals(source)) {
                throw new Error("Instances should be equal.");
            }

        }

        function clone() {
            if (returnObj.z === null) {  // isAffine

                return EllipticCurvePointFp(
                    returnObj.curve,
                    returnObj.isInfinity,
                    createArray(returnObj.x),
                    createArray(returnObj.y),
                    null,
                    returnObj.isInMontgomeryForm);
            } else {

                return EllipticCurvePointFp(
                    returnObj.curve,
                    returnObj.isInfinity,
                    createArray(returnObj.x),
                    createArray(returnObj.y),
                    createArray(returnObj.z),
                    returnObj.isInMontgomeryForm);
            }
        }

        returnObj = /*@static_cast(EllipticCurvePointFp)*/ {
            equals: function (ellipticCurvePointFp) {
                return equals(ellipticCurvePointFp);
            },
            copy: function (destination) {
                copyTo(this, destination);
                return;
            },
            clone: function () {
                return clone();
            },
            toByteArrayUnsigned: function () { // NOTE: added for U-Prove
                return cryptoECC.sec1EncodingFp().encodePoint(this);
            }

        };

        createProperty(returnObj, "curve", curve, function () { return curve; }, function (val) { curve = val; });

        createProperty(returnObj, "x", x, function () { return x; }, function (val) { x = val; });
        createProperty(returnObj, "y", y, function () { return y; }, function (val) { y = val; });
        createProperty(returnObj, "z", z, function () { return z; }, function (val) { z = val; });

        createProperty(returnObj, "isInMontgomeryForm", isInMontgomeryForm, function () { return isInMontgomeryForm; }, function (val) { isInMontgomeryForm = val; });
        createProperty(returnObj, "isInfinity", isInfinity, function () { return isInfinity; }, function (val) { isInfinity = val; });
        createProperty(returnObj, "isAffine", (z === null), function () { return (z === null); });

        return returnObj;
    };
    var EllipticCurveOperatorFp = function (/*@type(EllipticCurveFp)*/curve) {
        /// <param name="curve" type="EllipticCurveFp"/>

        // Store a reference to the curve.
        var m_curve = curve;

        var fieldElementWidth = curve.p.length;

        var montgomeryMultiplier = cryptoMath.MontgomeryMultiplier(curve.p);

        // Pre-compute and store the montgomeryized form of A, and set our
        // zero flag to determine whether or not we should use implementations
        // optimized for A = 0.
        var montgomerizedA = curve.a.slice();
        montgomeryMultiplier.convertToMontgomeryForm(montgomerizedA);

        var aequalsZero = cryptoMath.isZero(curve.a);

        var one = cryptoMath.One;

        var onemontgomery = createArray(fieldElementWidth);
        onemontgomery[0] = 1;
        montgomeryMultiplier.convertToMontgomeryForm(onemontgomery);

        var group = cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(montgomeryMultiplier.m), true);

        // Setup temp storage.
        var temp0 = createArray(fieldElementWidth);
        var temp1 = createArray(fieldElementWidth);
        var temp2 = createArray(fieldElementWidth);
        var temp3 = createArray(fieldElementWidth);
        var temp4 = createArray(fieldElementWidth);
        var temp5 = createArray(fieldElementWidth);
        var temp6 = createArray(fieldElementWidth);
        var temp7 = createArray(fieldElementWidth);
        var swap0 = createArray(fieldElementWidth);

        // Some additional temp storage used in point conversion routines.
        var conversionTemp0 = createArray(fieldElementWidth);
        var conversionTemp1 = createArray(fieldElementWidth);
        var conversionTemp2 = createArray(fieldElementWidth);

        function modSub(left, right, result) {
            var resultElement = group.createElementFromInteger(0);
            resultElement.m_digits = result;
            group.subtract(
                group.createElementFromDigits(left),
                group.createElementFromDigits(right),
                resultElement);
        }

        function modAdd(left, right, result) {
            var resultElement = group.createElementFromInteger(0);
            resultElement.m_digits = result;
            group.add(
                group.createElementFromDigits(left),
                group.createElementFromDigits(right),
                resultElement);
        }

        function modInv(number, result) {
            cryptoMath.modInv(number, m_curve.p, result);
        }

        function modDivByTwo( /*@type(Digits)*/ dividend,  /*@type(Digits)*/ result) {

            var s = dividend.length;

            var modulus = curve.p;

            // If dividend is odd, add modulus
            if ((dividend[0] & 0x1) === 0x1) {
                var carry = 0;

                for (var i = 0; i < s; i += 1) {
                    carry += dividend[i] + modulus[i];
                    result[i] = carry & cryptoMath.DIGIT_MASK;
                    carry = (carry >>> cryptoMath.DIGIT_BITS);
                }

                // Put carry bit into position for masking in
                carry = carry << (cryptoMath.DIGIT_BITS - 1);

                // Bit shift
                cryptoMath.shiftRight(result, result);

                // Mask in the carry bit
                result[s - 1] |= carry;
            } else {
                // Shift directly into result
                cryptoMath.shiftRight(dividend, result);
            }

        }

        function montgomeryMultiply(left, right, result) {
            montgomeryMultiplier.montgomeryMultiply(
                left,
                right,
                result);
        }

        function montgomerySquare(left, result) {
            montgomeryMultiplier.montgomeryMultiply(
                left,
                left,
                result);
        }

        function correctInversion(digits) {
            /// <param name="digits" type="Digits"/>
            var results = createArray(digits.length);
            montgomeryMultiply(digits, montgomeryMultiplier.rCubedModm, results);
            for (var i = 0; i < results.length; i += 1) {
                digits[i] = results[i];
            }
        }

        function doubleAequalsNeg3(point, outputPoint) {
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            // If point = infinity then outputPoint := infinity.
            if (point.isInfinity) {
                outputPoint.isInfinity = true;
                return;
            }

            // 't4:=Z1^2;'
            montgomerySquare(point.z, temp4);

            // 't3:=Y1^2;'
            montgomerySquare(point.y, temp3);

            // 't1:=X1+t4;'
            modAdd(point.x, temp4, temp1);

            // 't4:=X1-t4;'
            modSub(point.x, temp4, temp4);

            // 't0:=3*t4;'
            modAdd(temp4, temp4, temp0);
            modAdd(temp0, temp4, temp0);

            // 't5:=X1*t3;'
            montgomeryMultiply(point.x, temp3, temp5);

            // 't4:=t1*t0;'
            montgomeryMultiply(temp1, temp0, temp4);

            // 't0:=t3^2;'
            montgomerySquare(temp3, temp0);

            // 't1:=t4/2'
            modDivByTwo(temp4, temp1);

            // 't3:=t1^2;'
            montgomerySquare(temp1, temp3);

            // 'Z_out:=Y1*Z1;'
            montgomeryMultiply(point.y, point.z, swap0);
            for (var i = 0; i < swap0.length; i += 1) {
                outputPoint.z[i] = swap0[i];
            }

            // 'X_out:=t3-2*t5;'
            modSub(temp3, temp5, outputPoint.x);
            modSub(outputPoint.x, temp5, outputPoint.x);

            // 't3:=t5-X_out;'
            modSub(temp5, outputPoint.x, temp3);

            // 't5:=t1*t3'
            montgomeryMultiply(temp1, temp3, temp5);

            // 'Y_out:=t5-t0;'
            modSub(temp5, temp0, outputPoint.y);

            // Finalize the flags on the output point.
            outputPoint.isInfinity = false;
            outputPoint.isInMontgomeryForm = true;
        }

        function doubleAequals0(point, outputPoint) {
            /// <param name="point" type="EllipticCurvePointFp"/>
            /// <param name="outputPoint" type="EllipticCurvePointFp"/>

            // If point = infinity then outputPoint := infinity.
            if (point.isInfinity) {
                outputPoint.isInfinity = true;
                return;
            }

            // 't3:=Y1^2;'
            montgomerySquare(point.y, temp3);

            // 't4:=X1^2;'
            montgomerySquare(point.x, temp4);

            // 't4:=3*t4;'
            modAdd(temp4, temp4, temp0);
            modAdd(temp0, temp4, temp4);

            // 't5:=X1*t3;'
            montgomeryMultiply(point.x, temp3, temp5);

            // 't0:=t3^2;'
            montgomerySquare(temp3, temp0);

            // 't1:=t4/2;'
            modDivByTwo(temp4, temp1);

            // 't3:=t1^2;'
            montgomerySquare(temp1, temp3);

            // 'Z_out:=Y1*Z1;'
            montgomeryMultiply(point.y, point.z, swap0);
            for (var i = 0; i < swap0.length; i += 1) {
                outputPoint.z[i] = swap0[i];
            }

            // 'X_out:=t3-2*t5;'
            modSub(temp3, temp5, outputPoint.x);
            modSub(outputPoint.x, temp5, outputPoint.x);

            // 't4:=t5-X_out;'
            modSub(temp5, outputPoint.x, temp4);

            // 't2:=t1*t4;'
            montgomeryMultiply(temp1, temp4, temp2);

            // 'Y_out:=t2-t0;'
            modSub(temp2, temp0, outputPoint.y);

            // Finalize the flags on the output point.
            outputPoint.isInfinity = false;
            outputPoint.isInMontgomeryForm = true;
        }

        function generatePrecomputationTable(w, generatorPoint) {

            if (w < 4) {
                throw new Error("This pre-computation algorithm assumes w >= 4");
            }

            if (!generatorPoint.isInMontgomeryForm) {
                throw new Error("Generator point must be in montgomery form");
            }

            if (!generatorPoint.isAffine) {
                throw new Error("Generator point must be in affine form");
            }

            // Currently we support only two curve types, those with A=-3, and
            // those with A=0. In the future we will implement general support.
            // For now we switch here, assuming that the curve was validated in
            // the constructor.
            if (aequalsZero) {
                return generatePrecomputationTableAequals0(w, generatorPoint);
            } else {
                return generatePrecomputationTableAequalsNeg3(w, generatorPoint);
            }
        }

        // Given a point P on an elliptic curve, return a table of 
        // size 2^(w-2) filled with pre-computed values for 
        // P, 3P, 5P, ... Etc.

        function generatePrecomputationTableAequalsNeg3(w, generatorPoint) {
            /// <param name="w" type="Number">The "width" of the table to use. The should match the width used to generate the NAF.</param>
            /// <param name="generatorPoint">The point P in affine, montgomery form.</param>
            /// <returns>A table of size 2^(w-2) filled with pre-computed values for P, 3P, 5P, ... Etc in De-montgomeryized Affine Form.</returns>

            // Width of our field elements.
            var s = curve.p.length;

            // Initialize table
            // The first element is set to our generator povar initially.
            // The rest are dummy points to be filled in by the pre-computation
            // algorithm.
            var tableSize = (1 << (w - 2)); // 2^(w-2)
            var t = []; // Of EllipticCurvePointFp
            var i;
            t[0] = generatorPoint.clone();

            for (i = 1; i < tableSize; i += 1) {
                var newPoint = EllipticCurvePointFp(
                    curve,
                    false,
                    createArray(s),
                    createArray(s),
                    createArray(s),
                    true
                );
                t[i] = newPoint;
            }

            // Initialize temp tables for povar recovery.
            var d = [];
            var e = [];

            for (i = 0; i < tableSize - 2; i += 1) {
                d[i] = createArray(s);
                e[i] = createArray(s);
            }

            // Alias temp7 to Z for readability.
            var z = temp7;

            // Pseudocode Note:
            // Arrays of points use element 1 for X, element 2 for Y
            // so e.g. T[0][1] === T[0].x.

            // SETUP -----------------------------------------------------------

            // Compute T[0] = 2*P and T[1] = P such that both are in Jacobian 
            // form with the same Z. These values are then used to compute 
            // T[0] = 3P, T[1] = 5P, ..., T[n] = (3 + 2*n) * P.

            // 't1 := T[0].x^2;  '
            montgomerySquare(t[0].x, temp1);

            // 't3 := T[0].y^2;'
            montgomerySquare(t[0].y, temp3);

            // 't1 := (3*t1 + A)/2;'
            modAdd(temp1, temp1, temp2);
            modAdd(temp2, temp1, temp1);
            modAdd(temp1, montgomerizedA, temp1);
            modDivByTwo(temp1, temp1);

            // 'T[2].x := t3 * T[0].x;'
            montgomeryMultiply(temp3, t[0].x, t[2].x);

            // 'T[2].y := t3^2;'
            montgomerySquare(temp3, t[2].y);

            // 'Z := T[0].y;'
            for (i = 0; i < s; i += 1) {
                z[i] = t[0].y[i];
            }

            // 'T[1].x := t1^2;'
            montgomerySquare(temp1, t[1].x);

            // 'T[1].x := T[1].x - 2 * T[2].x;'
            // PERF: Implementing DBLSUB here (and everywhere where we compute A - 2*B) 
            // may possibly result in some performance gain.
            modSub(t[1].x, t[2].x, t[1].x);
            modSub(t[1].x, t[2].x, t[1].x);

            // 't2 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp2);

            // 't1 := t1 * t2;'
            // NOTE: Using temp0 as target since montmul is destructive.
            montgomeryMultiply(temp1, temp2, temp0);

            // 'T[1].y := t1 - T[2].y;'
            modSub(temp0, t[2].y, t[1].y);

            // First iteration ------------------------------------------------

            // 't1 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp1);

            // 't2 := T[2].y - T[1].y;'
            modSub(t[2].y, t[1].y, temp2);

            // 'Z := Z * t1;'
            montgomeryMultiply(z, temp1, temp0);
            var idx;
            for (idx = 0; idx < s; idx++) {
                z[idx] = temp0[idx];
            }

            // 'd[0] := t1^2;'
            montgomerySquare(temp1, d[0]);

            // 't3 := t2^2;'
            montgomerySquare(temp2, temp3);

            // 'T[2].x := d[0] * T[1].x;'
            montgomeryMultiply(d[0], t[1].x, t[2].x);

            // 't3 := t3 - 2 * T[2].x;'
            modSub(temp3, t[2].x, temp3);
            modSub(temp3, t[2].x, temp3);

            // 'd[0] := d[0] * t1;'
            montgomeryMultiply(d[0], temp1, temp0);

            for (idx = 0; idx < s; idx++) {
                d[0][idx] = temp0[idx];
            }

            // 'T[1].x := t3 - d[0];'
            modSub(temp3, d[0], t[1].x);

            // 't1 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp1);

            // 't1 := t1 * t2;'
            // NOTE: Using t0 as target due to destructive multiply.
            montgomeryMultiply(temp1, temp2, temp0);

            // 'T[2].y := T[1].y*d[0];'
            montgomeryMultiply(t[1].y, d[0], t[2].y);

            // 'T[1].y := t1 - T[2].y;'
            // NOTE: Reusing t0 result from above.
            modSub(temp0, t[2].y, t[1].y);

            // INNER ITERATIONS ------------------------------------------------
            var j, k, l;

            for (i = 0; i < tableSize - 3; i += 1) {
                j = i + 1;
                k = i + 2;
                l = i + 3;

                // 't1 := T[j].x - T[k].x;'
                modSub(t[j].x, t[k].x, temp1);

                // 't2 := T[j].y - T[k].y;'
                modSub(t[j].y, t[k].y, temp2);

                // 'Z := Z * t1;'
                // NOTE: Using temp0 as target since multiply is destructive.
                montgomeryMultiply(z, temp1, temp0);

                for (idx = 0; idx < s; idx++) {
                    z[idx] = temp0[idx];
                }

                // 'd[i] := t1^2;'
                montgomerySquare(temp1, d[i]);

                // 't3 := t2^2;'
                montgomerySquare(temp2, temp3);

                // 'T[l].x := d[i] * T[k].x;'
                montgomeryMultiply(d[i], t[k].x, t[l].x);

                // 't3 := t3 - 2 * T[l].x;'
                modSub(temp3, t[l].x, temp3);
                modSub(temp3, t[l].x, temp3);

                // 'e[i] := d[i] * t1;'
                montgomeryMultiply(d[i], temp1, e[i]);

                // 'T[k].x := t3 - e[i];'
                modSub(temp3, e[i], t[k].x);

                // 't1 := T[l].x - T[k].x;'
                // NOTE: Using temp0 as target so we can multiply into temp1 below.
                modSub(t[l].x, t[k].x, temp0);

                // 't1 := t1 * t2;'
                // NOTE: Using temp0 result from above.
                montgomeryMultiply(temp0, temp2, temp1);

                // 'T[l].y := T[k].y*e[i];'
                montgomeryMultiply(t[k].y, e[i], t[l].y);

                // 'T[k].y := t1 - T[l].y;'
                modSub(temp1, t[l].y, t[k].y);
            }

            // FINAL ITERATION -------------------------------------------------
            // {
            i = tableSize - 3;
            j = i + 1;
            k = i + 2; // 't1 := T[j].x - T[k].x;'
            modSub(t[j].x, t[k].x, temp1);

            // 't2 := T[j].y - T[k].y;'
            modSub(t[j].y, t[k].y, temp2);

            // 'Z := Z * t1;'
            montgomeryMultiply(z, temp1, temp0);

            for (idx = 0; idx < s; idx++) {
                z[idx] = temp0[idx];
            }

            // 'd[i] := t1^2;'
            montgomerySquare(temp1, d[i]);

            // 't3 := t2^2;'
            montgomerySquare(temp2, temp3);

            // 'e[i] := d[i] * t1;'
            montgomeryMultiply(d[i], temp1, e[i]);

            // 't1 := d[i] * T[k].x;'
            montgomeryMultiply(d[i], t[k].x, temp1);

            // 't3 := t3 - 2 * t1;'
            modSub(temp3, temp1, temp3);
            modSub(temp3, temp1, temp3);

            // 'T[k].x := t3 - e[i];'
            modSub(temp3, e[i], t[k].x);

            // 't1 := t1 - T[k].x;'
            // NOTE: Using temp0 as target so we can multiply into temp1 below.
            modSub(temp1, t[k].x, temp0);

            // 't1 := t1 * t2;'
            // NOTE: Reusing temp0 to multiply into temp1.
            montgomeryMultiply(temp0, temp2, temp1);

            // 'T[k].y := T[k].y * e[i];'
            // NOTE: Using temp3 as target due to destructive multiply.
            montgomeryMultiply(t[k].y, e[i], temp3);

            // 'T[k].y := t1 - T[k].y;'
            // NOTE: Using temp3 instead of T[k].y.
            modSub(temp1, temp3, t[k].y);

            // POST ITERATIONS - INVERT Z AND PREPARE TO RECOVER TABLE ENTRIES ---------------

            // 'Z := 1/Z;'
            // NOTE: Z is in montgomery form at this point, i.e. Z*R. After 
            // inversion we will have 1/(Z*R) but we want (1/Z)*R (the 
            // montgomery form of Z inverse) so we use the inversion 
            // correction, which does a montgomery multiplication by R^3
            // yielding the correct result.
            modInv(z, z);
            correctInversion(z);

            // 't1 := Z^2;'
            montgomerySquare(z, temp1);

            // 't2 := t1 * Z;'
            montgomeryMultiply(temp1, z, temp2);

            // 'T[k].x := T[k].x * t1;'
            montgomeryMultiply(t[k].x, temp1, temp0);

            // Copy temp0 to T[k].x.
            for (idx = 0; idx < s; idx++) {
                t[k].x[idx] = temp0[idx];
            }

            // 'T[k].y := T[k].y * t2;'
            montgomeryMultiply(t[k].y, temp2, temp0);

            for (idx = 0; idx < s; idx++) {
                t[k].y[idx] = temp0[idx];
            }
            // } FINAL ITERATION

            // RECOVER POINTS FROM TABLE ---------------------------------------

            // For i in [(2^(w-2)-2)..1 by -1] do
            for (i = tableSize - 3; i >= 0; i--) {
                // 'j := i + 1;'
                j = i + 1; // 't1 := t1 * d[i];'
                montgomeryMultiply(temp1, d[i], temp0);

                for (idx = 0; idx < s; idx++) {
                    temp1[idx] = temp0[idx];
                }

                // 't2 := t2 * e[i];'
                montgomeryMultiply(temp2, e[i], temp0);

                for (idx = 0; idx < s; idx++) {
                    temp2[idx] = temp0[idx];
                }

                // 'T[j].x := T[j].x * t1;'
                montgomeryMultiply(t[j].x, temp1, temp0);

                for (idx = 0; idx < s; idx++) {
                    t[j].x[idx] = temp0[idx];
                }

                // 'T[j].y := T[j].y * t2;'
                montgomeryMultiply(t[j].y, temp2, temp0);

                for (idx = 0; idx < s; idx++) {
                    t[j].y[idx] = temp0[idx];
                }

                // End for;
            }

            // Points are now in affine form, set Z coord to null (== 1).
            for (i = 0; i < t.length; i += 1) {
                t[i].z = null;
                setterSupport || (t[i].isAffine = true);
            }

            for (i = 0; i < t.length; i += 1) {

                if (!t[i].isAffine) {
                    throw new Error("Non-affine povar found in precomputation table");
                }
                if (!t[i].isInMontgomeryForm) {
                    convertToMontgomeryForm(t[i]);
                }
            }

            return t;
        }

        // Given a povar P on an elliptic curve, return a table of 
        // size 2^(w-2) filled with pre-computed values for 
        // P, 3P, 5P, ... Etc.

        function generatePrecomputationTableAequals0(w, generatorPoint) {
            /// <param name="w" type="Number">The "width" of the table to use. The should match
            /// the width used to generate the NAF.</param>
            /// <param name="generatorPoint" type="EllipticCurvePointFp">The povar P in affine, montgomery form.</param>
            /// <returns>A table of 
            /// size 2^(w-2) filled with pre-computed values for 
            /// P, 3P, 5P, ... Etc in De-montgomeryized Affine Form.</returns>

            // Width of our field elements.
            var s = curve.p.length;

            // Initialize table
            // The first element is set to our generator povar initially.
            // The rest are dummy points to be filled in by the pre-computation
            // algorithm.
            var tableSize = (1 << (w - 2)); // '2^(w-2)'
            var t = []; // Of EllipticCurvePointFp
            t[0] = generatorPoint.clone();
            var i;
            for (i = 1; i < tableSize; i += 1) {
                var newPoint = EllipticCurvePointFp(
                    curve,
                    false,
                    createArray(s),
                    createArray(s),
                    createArray(s),
                    true
                );
                t[i] = newPoint;
            }

            // Initialize temp tables for povar recovery.
            var d = [];
            var e = [];

            for (i = 0; i < tableSize - 2; i += 1) {
                d[i] = createArray(s);
                e[i] = createArray(s);
            }

            // Alias temp7 to Z for readability.
            var z = temp7;

            // Pseudocode Note:
            // Arrays of points use element 1 for X, element 2 for Y
            // so e.g. T[0][1] === T[0].x.

            // SETUP -----------------------------------------------------------

            // Compute T[0] = 2*P and T[1] = P such that both are in Jacobian 
            // form with the same Z. These values are then used to compute 
            // T[0] = 3P, T[1] = 5P, ..., T[n] = (3 + 2*n) * P.

            // 't1 := T[0].x^2;  '
            montgomerySquare(t[0].x, temp1);

            // 't3 := T[0].y^2;'
            montgomerySquare(t[0].y, temp3);

            // 't1 := (3*t1)/2;'
            modAdd(temp1, temp1, temp2);
            modAdd(temp2, temp1, temp1);
            modDivByTwo(temp1, temp1);

            // 'T[2].x := t3 * T[0].x;'
            montgomeryMultiply(temp3, t[0].x, t[2].x);

            // 'T[2].y := t3^2;'
            montgomerySquare(temp3, t[2].y);

            // 'Z := T[0].y;'
            for (i = 0; i < s; i += 1) {
                z[i] = t[0].y[i];
            }

            // 'T[1].x := t1^2;'
            montgomerySquare(temp1, t[1].x);

            // 'T[1].x := T[1].x - 2 * T[2].x;'
            // PERF: Implementing DBLSUB here (and everywhere where we compute A - 2*B) 
            // may possibly result in some performance gain.
            modSub(t[1].x, t[2].x, t[1].x);
            modSub(t[1].x, t[2].x, t[1].x);

            // 't2 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp2);

            // 't1 := t1 * t2;'
            // NOTE: Using temp0 as target since montmul is destructive.
            montgomeryMultiply(temp1, temp2, temp0);

            // 'T[1].y := t1 - T[2].y;'
            modSub(temp0, t[2].y, t[1].y);

            // First iteration ------------------------------------------------

            // 't1 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp1);

            // 't2 := T[2].y - T[1].y;'
            modSub(t[2].y, t[1].y, temp2);

            // 'Z := Z * t1;'
            montgomeryMultiply(z, temp1, temp0);
            var idx;
            for (idx = 0; idx < s; idx++) {
                z[idx] = temp0[idx];
            }

            // 'd[0] := t1^2;'
            montgomerySquare(temp1, d[0]);

            // 't3 := t2^2;'
            montgomerySquare(temp2, temp3);

            // 'T[2].x := d[0] * T[1].x;'
            montgomeryMultiply(d[0], t[1].x, t[2].x);

            // 't3 := t3 - 2 * T[2].x;'
            modSub(temp3, t[2].x, temp3);
            modSub(temp3, t[2].x, temp3);

            // 'd[0] := d[0] * t1;'
            montgomeryMultiply(d[0], temp1, temp0);

            for (idx = 0; idx < s; idx++) {
                d[0][idx] = temp0[idx];
            }

            // 'T[1].x := t3 - d[0];'
            modSub(temp3, d[0], t[1].x);

            // 't1 := T[2].x - T[1].x;'
            modSub(t[2].x, t[1].x, temp1);

            // 't1 := t1 * t2;'
            // NOTE: Using t0 as target due to destructive multiply.
            montgomeryMultiply(temp1, temp2, temp0);

            // 'T[2].y := T[1].y*d[0];'
            montgomeryMultiply(t[1].y, d[0], t[2].y);

            // 'T[1].y := t1 - T[2].y;'
            // NOTE: Reusing t0 result from above.
            modSub(temp0, t[2].y, t[1].y);

            var j, k, l;
            // INNER ITERATIONS ------------------------------------------------
            for (i = 0; i < tableSize - 3; i += 1) {
                j = i + 1;
                k = i + 2;
                l = i + 3;

                // 't1 := T[j].x - T[k].x;'
                modSub(t[j].x, t[k].x, temp1);

                // 't2 := T[j].y - T[k].y;'
                modSub(t[j].y, t[k].y, temp2);

                // 'Z := Z * t1;'
                // NOTE: Using temp0 as target since multiply is destructive.
                montgomeryMultiply(z, temp1, temp0);

                for (idx = 0; idx < s; idx++) {
                    z[idx] = temp0[idx];
                }

                // 'd[i] := t1^2;'
                montgomerySquare(temp1, d[i]);

                // 't3 := t2^2;'
                montgomerySquare(temp2, temp3);

                // 'T[l].x := d[i] * T[k].x;'
                montgomeryMultiply(d[i], t[k].x, t[l].x);

                // 't3 := t3 - 2 * T[l].x;'
                modSub(temp3, t[l].x, temp3);
                modSub(temp3, t[l].x, temp3);

                // 'e[i] := d[i] * t1;'
                montgomeryMultiply(d[i], temp1, e[i]);

                // 'T[k].x := t3 - e[i];'
                modSub(temp3, e[i], t[k].x);

                // 't1 := T[l].x - T[k].x;'
                // NOTE: Using temp0 as target so we can multiply into temp1 below.
                modSub(t[l].x, t[k].x, temp0);

                // 't1 := t1 * t2;'
                // NOTE: Using temp0 result from above.
                montgomeryMultiply(temp0, temp2, temp1);

                // 'T[l].y := T[k].y*e[i];'
                montgomeryMultiply(t[k].y, e[i], t[l].y);

                // 'T[k].y := t1 - T[l].y;'
                modSub(temp1, t[l].y, t[k].y);
            }

            // FINAL ITERATION -------------------------------------------------
            // {
            i = tableSize - 3;
            j = i + 1;
            k = i + 2;

            // 't1 := T[j].x - T[k].x;'
            modSub(t[j].x, t[k].x, temp1);

            // 't2 := T[j].y - T[k].y;'
            modSub(t[j].y, t[k].y, temp2);

            // 'Z := Z * t1;'
            montgomeryMultiply(z, temp1, temp0);

            for (idx = 0; idx < s; idx++) {
                z[idx] = temp0[idx];
            }

            // 'd[i] := t1^2;'
            montgomerySquare(temp1, d[i]);

            // 't3 := t2^2;'
            montgomerySquare(temp2, temp3);

            // 'e[i] := d[i] * t1;'
            montgomeryMultiply(d[i], temp1, e[i]);

            // 't1 := d[i] * T[k].x;'
            montgomeryMultiply(d[i], t[k].x, temp1);

            // 't3 := t3 - 2 * t1;'
            modSub(temp3, temp1, temp3);
            modSub(temp3, temp1, temp3);

            // 'T[k].x := t3 - e[i];'
            modSub(temp3, e[i], t[k].x);

            // 't1 := t1 - T[k].x;'
            // NOTE: Using temp0 as target so we can multiply into temp1 below.
            modSub(temp1, t[k].x, temp0);

            // 't1 := t1 * t2;'
            // NOTE: Reusing temp0 to multiply into temp1.
            montgomeryMultiply(temp0, temp2, temp1);

            // 'T[k].y := T[k].y*e[i];'
            // NOTE: Using temp3 as target due to destructive multiply.
            montgomeryMultiply(t[k].y, e[i], temp3);

            // 'T[k].y := t1 - T[k].y;'
            // NOTE: Using temp3 instead of T[k].y.
            modSub(temp1, temp3, t[k].y);

            // POST ITERATIONS - INVERT Z AND PREPARE TO RECOVER TABLE ENTRIES ---------------

            // 'Z := 1/Z;'
            // NOTE: Z is in montgomery form at this point, i.e. Z*R. After 
            // inversion we will have 1/(Z*R) but we want (1/Z)*R (the 
            // montgomery form of Z inverse) so we use the inversion 
            // correction, which does a montgomery multiplication by R^3
            // yielding the correct result.
            modInv(z, z);
            correctInversion(z);

            // 't1 := Z^2;'
            montgomerySquare(z, temp1);

            // 't2 := t1 * Z;'
            montgomeryMultiply(temp1, z, temp2);

            // 'T[k].x := T[k].x * t1;'
            montgomeryMultiply(t[k].x, temp1, temp0);

            // Copy temp0 to T[k].x.
            for (idx = 0; idx < s; idx++) {
                t[k].x[idx] = temp0[idx];
            }

            // 'T[k].y := T[k].y * t2;'
            montgomeryMultiply(t[k].y, temp2, temp0);

            for (idx = 0; idx < s; idx++) {
                t[k].y[idx] = temp0[idx];
            }
            // }

            // RECOVER POINTS FROM TABLE ---------------------------------------

            // For i in [(2^(w-2)-2)..1 by -1] do
            for (i = tableSize - 3; i >= 0; i--) {
                // 'j := i + 1;'
                j = i + 1;

                // 't1 := t1 * d[i];'
                montgomeryMultiply(temp1, d[i], temp0);

                for (idx = 0; idx < s; idx++) {
                    temp1[idx] = temp0[idx];
                }

                // 't2 := t2 * e[i];'
                montgomeryMultiply(temp2, e[i], temp0);

                for (idx = 0; idx < s; idx++) {
                    temp2[idx] = temp0[idx];
                }

                // 'T[j].x := T[j].x * t1;'
                montgomeryMultiply(t[j].x, temp1, temp0);

                for (idx = 0; idx < s; idx++) {
                    t[j].x[idx] = temp0[idx];
                }

                // 'T[j].y := T[j].y * t2;'
                montgomeryMultiply(t[j].y, temp2, temp0);

                for (idx = 0; idx < s; idx++) {
                    t[j].y[idx] = temp0[idx];
                }

                // End for;
            }

            // Points are now in affine form, set Z coord to null (== 1).
            for (i = 0; i < t.length; i += 1) {
                t[i].z = null;
                setterSupport || (t[i].isAffine = true);
            }

            for (i = 0; i < t.length; i += 1) {

                if (!t[i].isAffine) {
                    throw new Error("Non-affine povar found in precomputation table");
                }
                if (!t[i].isInMontgomeryForm) {
                    convertToMontgomeryForm(t[i]);
                }
            }

            return t;
        }

        function convertToMontgomeryForm(point) {
            /// <param name="point" type="EllipticCurvePointFp"/>

            if (point.isInMontgomeryForm) {
                throw new Error("The given point is already in montgomery form.");
            }

            if (!point.isInfinity) {
                montgomeryMultiplier.convertToMontgomeryForm(point.x);
                montgomeryMultiplier.convertToMontgomeryForm(point.y);

                if (point.z !== null) {
                    montgomeryMultiplier.convertToMontgomeryForm(point.z);
                }
            }

            point.isInMontgomeryForm = true;
        }

        return {

            double: function (point, outputPoint) {
                /// <param name="point" type="EllipticCurvePointFp"/>
                /// <param name="outputPoint" type="EllipticCurvePointFp"/>

                if (typeof point === "undefined") {
                    throw new Error("point undefined");
                }
                if (typeof outputPoint === "undefined") {
                    throw new Error("outputPoint undefined");
                }

                //// if (!point.curve.equals(outputPoint.curve)) {
                ////    throw new Error("point and outputPoint must be from the same curve object.");
                //// }

                if (point.isAffine) {
                    throw new Error("Given point was in Affine form. Use convertToJacobian() first.");
                }

                if (!point.isInMontgomeryForm) {
                    throw new Error("Given point must be in montgomery form. Use montgomeryize() first.");
                }

                if (outputPoint.isAffine) {
                    throw new Error("Given output point was in Affine form. Use convertToJacobian() first.");
                }

                // Currently we support only two curve types, those with A=-3, and
                // those with A=0. In the future we will implement general support.
                // For now we switch here, assuming that the curve was validated in
                // the constructor.
                if (aequalsZero) {
                    doubleAequals0(point, outputPoint);
                } else {
                    doubleAequalsNeg3(point, outputPoint);
                }

            },

            mixedDoubleAdd: function (jacobianPoint, affinePoint, outputPoint) {
                /// <param name="jacobianPoint" type="EllipticCurvePointFp"/>
                /// <param name="affinePoint" type="EllipticCurvePointFp"/>
                /// <param name="outputPoint" type="EllipticCurvePointFp"/>

                if (jacobianPoint.isInfinity) {
                    affinePoint.copy(outputPoint);
                    this.convertToJacobianForm(outputPoint);
                    return;
                }

                if (affinePoint.isInfinity) {
                    jacobianPoint.copy(outputPoint);
                    return;
                }

                // Ok then we do the full double and add.

                // Note: in pseudo-code the capital X,Y,Z is Jacobian point, lower 
                // case x, y, z is Affine point.

                // 't5:=Z1^ 2;'
                montgomerySquare(jacobianPoint.z, temp5);

                // 't6:=Z1*t5;'
                montgomeryMultiply(jacobianPoint.z, temp5, temp6);

                // 't4:=x2*t5;'
                montgomeryMultiply(affinePoint.x, temp5, temp4);

                // 't5:=y2*t6;'
                montgomeryMultiply(affinePoint.y, temp6, temp5);

                // 't1:=t4-X1;'
                modSub(temp4, jacobianPoint.x, temp1);

                // 't2:=t5-Y1;'
                modSub(temp5, jacobianPoint.y, temp2);

                // 't4:=t2^2;'
                montgomerySquare(temp2, temp4);

                // 't6:=t1^2;'
                montgomerySquare(temp1, temp6);

                // 't5:=t6*X1;'
                montgomeryMultiply(temp6, jacobianPoint.x, temp5);

                // 't0:=t1*t6;'
                montgomeryMultiply(temp1, temp6, temp0);

                // 't3:=t4-2*t5;'
                modSub(temp4, temp5, temp3);
                modSub(temp3, temp5, temp3);

                // 't4:=Z1*t1;'
                montgomeryMultiply(jacobianPoint.z, temp1, temp4);

                // 't3:=t3-t5;'
                modSub(temp3, temp5, temp3);

                // 't6:=t0*Y1;'
                montgomeryMultiply(temp0, jacobianPoint.y, temp6);

                // 't3:=t3-t0;'
                modSub(temp3, temp0, temp3);

                // 't1:=2*t6;'
                modAdd(temp6, temp6, temp1);

                // 'Zout:=t4*t3;'
                montgomeryMultiply(temp4, temp3, outputPoint.z);

                // 't4:=t2*t3;'
                montgomeryMultiply(temp2, temp3, temp4);

                // 't0:=t3^2;'
                montgomerySquare(temp3, temp0);

                // 't1:=t1+t4;'
                modAdd(temp1, temp4, temp1);

                // 't4:=t0*t5;'
                montgomeryMultiply(temp0, temp5, temp4);

                // 't7:=t1^2;'
                montgomerySquare(temp1, temp7);

                // 't4:=t0*t5;'
                montgomeryMultiply(temp0, temp3, temp5);

                // 'Xout:=t7-2*t4;'
                modSub(temp7, temp4, outputPoint.x);
                modSub(outputPoint.x, temp4, outputPoint.x);

                // 'Xout:=Xout-t5;'
                modSub(outputPoint.x, temp5, outputPoint.x);

                // 't3:=Xout-t4;'
                modSub(outputPoint.x, temp4, temp3);

                // 't0:=t5*t6;'
                montgomeryMultiply(temp5, temp6, temp0);

                // 't4:=t1*t3;'
                montgomeryMultiply(temp1, temp3, temp4);

                // 'Yout:=t4-t0;'
                modSub(temp4, temp0, outputPoint.y);

                outputPoint.isInfinity = false;
                outputPoint.isInMontgomeryForm = true;

            },

            mixedAdd: function (jacobianPoint, affinePoint, outputPoint) {
                /// <param name="jacobianPoint" type="EllipticCurvePointFp"/>
                /// <param name="affinePoint" type="EllipticCurvePointFp"/>
                /// <param name="outputPoint" type="EllipticCurvePointFp"/>

                if (jacobianPoint === null) {
                    throw new Error("jacobianPoint");
                }

                if (affinePoint === null) {
                    throw new Error("affinePoint");
                }

                if (outputPoint === null) {
                    throw new Error("outputPoint");
                }

                if (jacobianPoint.curve !== affinePoint.curve ||
                    jacobianPoint.curve !== outputPoint.curve) {
                    throw new Error("All points must be from the same curve object.");
                }

                if (jacobianPoint.isAffine) {
                    throw new Error(
                        "Given jacobianPoint was in Affine form. Use ConvertToJacobian() before calling DoubleJacobianAddAffinePoints().");
                }

                if (!affinePoint.isAffine) {
                    throw new Error(
                        "Given affinePoint was in Jacobian form. Use ConvertToAffine() before calling DoubleJacobianAddAffinePoints().");
                }

                if (outputPoint.isAffine) {
                    throw new Error(
                        "Given jacobianPoint was in Jacobian form. Use ConvertToJacobian() before calling DoubleJacobianAddAffinePoints().");
                }

                if (!jacobianPoint.isInMontgomeryForm) {
                    throw new Error("Jacobian point must be in Montgomery form");
                }

                if (!affinePoint.isInMontgomeryForm) {
                    throw new Error("Affine point must be in Montgomery form");
                }

                if (jacobianPoint.isInfinity) {
                    affinePoint.copy(outputPoint);
                    this.convertToJacobianForm(outputPoint);
                    return;
                }

                if (affinePoint.isInfinity) {
                    jacobianPoint.copy(outputPoint);
                    return;
                }

                // Ok then we do the full double and add.

                // Note: in pseudo-code the capital X1,Y1,Z1 is Jacobian point, 
                // lower case x2, y2, z2 is Affine point.
                // 't1 := Z1^2;'.
                montgomerySquare(jacobianPoint.z, temp1);

                // 't2 := t1 * Z1;'
                montgomeryMultiply(temp1, jacobianPoint.z, temp2);

                // 't3 := t1 * x2;'
                montgomeryMultiply(temp1, affinePoint.x, temp3);

                // 't4 := t2 * y2;'
                montgomeryMultiply(temp2, affinePoint.y, temp4);

                // 't1 := t3 - X1;'
                modSub(temp3, jacobianPoint.x, temp1);

                // 't2 := t4 - Y1;'
                modSub(temp4, jacobianPoint.y, temp2);

                // If t1 != 0 then
                var i;
                for (i = 0; i < temp1.length; i += 1) {
                    if (temp1[i] !== 0) {

                        // 'Zout := Z1 * t1;'
                        montgomeryMultiply(jacobianPoint.z, temp1, temp0);
                        for (var j = 0; j < fieldElementWidth; j += 1) {
                            outputPoint.z[j] = temp0[j];
                        }

                        // 't3 := t1^2;'
                        montgomerySquare(temp1, temp3);

                        // 't4 := t3 * t1;'
                        montgomeryMultiply(temp3, temp1, temp4);

                        // 't5 := t3 * X1;'
                        montgomeryMultiply(temp3, jacobianPoint.x, temp5);

                        // 't1 := 2 * t5;'
                        modAdd(temp5, temp5, temp1);

                        // 'Xout := t2^2;'
                        montgomerySquare(temp2, outputPoint.x);

                        // 'Xout := Xout - t1;'
                        modSub(outputPoint.x, temp1, outputPoint.x);

                        // 'Xout := Xout - t4;'
                        modSub(outputPoint.x, temp4, outputPoint.x);

                        // 't3 := t5 - Xout;'
                        modSub(temp5, outputPoint.x, temp3);

                        // 't5 := t3*t2;'
                        montgomeryMultiply(temp2, temp3, temp5);

                        // 't6 := t4*Y1;'
                        montgomeryMultiply(jacobianPoint.y, temp4, temp6);

                        // 'Yout := t5-t6;'
                        modSub(temp5, temp6, outputPoint.y);

                        outputPoint.isInfinity = false;
                        outputPoint.isInMontgomeryForm = true;

                        return;
                    }
                }

                // Else if T2 != 0 then
                for (i = 0; i < temp2.length; i += 1) {
                    if (temp2[i] !== 0) {
                        //         Return infinity
                        outputPoint.isInfinity = true;
                        outputPoint.isInMontgomeryForm = true;
                        return;
                    }
                }
                // Else use DBL routine to return 2(x2, y2, 1) 
                affinePoint.copy(outputPoint);
                this.convertToJacobianForm(outputPoint);
                this.double(outputPoint, outputPoint);
                outputPoint.isInMontgomeryForm = true;

            },

            scalarMultiply: function (k, point, outputPoint) {
                /// <param name="k" type="Digits"/>
                /// <param name="point" type="EllipticCurvePointFp"/>
                /// <param name="outputPoint" type="EllipticCurvePointFp"/>

                // Special case for the point at infinity or k == 0
                if (point.isInfinity || cryptoMath.isZero(k)) {
                    outputPoint.isInfinity = true;
                    return;
                }

                // Runtime check for 1 <= k < order to ensure we dont get hit by
                // subgroup attacks. Since k is a FixedWidth it is a positive integer
                // and we already checked for zero above. So it must be >= 1 already.
                if (cryptoMath.compareDigits(k, curve.order) >= 0) {
                    throw new Error("The scalar k must be in the range 1 <= k < order.");
                }

                var digit;

                // Change w based on the size of the digits, 
                // 5 is good for 256 bits, use 6 for bigger sizes.
                var w = (fieldElementWidth <= 8) ? 5 : 6;
                // Generate wNAF representation.
                // Using an Array because we want to allow negative numbers.
                var nafDigits = msrcryptoUtilities.getVector(k.length * cryptoMath.DIGIT_BITS + 1);
                var numNafDigits = cryptoMath.computeNAF(k, w, temp0, nafDigits);

                // Generate pre-computation table.
                var table = generatePrecomputationTable(w, point);

                // Setup output point as Infinity, Jacobian, montgomery.
                outputPoint.isInfinity = true;

                // Main algorithm.
                for (var i1 = numNafDigits - 1; i1 >= 0; i1--) {
                    if (nafDigits[i1] === 0) {
                        this.double(outputPoint, outputPoint);
                    } else if (nafDigits[i1] < 0) {
                        digit = (-nafDigits[i1] >> 1);

                        // Negate Y coord before doing the add.
                        this.negate(table[digit], table[digit]);
                        this.mixedDoubleAdd(outputPoint, table[digit], outputPoint);
                        this.negate(table[digit], table[digit]);
                    } else if (nafDigits[i1] > 0) {
                        digit = (nafDigits[i1] >> 1);
                        this.mixedDoubleAdd(outputPoint, table[digit], outputPoint);
                    }
                }

                return;

            },

            negate: function (point, outputPoint) {
                /// <param name="point" type="EllipticCurvePointFp">Input point to negate.</param>
                /// <param name="outputPoint" type="EllipticCurvePointFp">(x, p - y).</param>

                if (point !== outputPoint) {
                    point.copy(outputPoint);
                }
                cryptoMath.subtract(point.curve.p, point.y, outputPoint.y);
            },

            convertToMontgomeryForm: function (point) {
                /// <param name="point" type="EllipticCurvePointFp"/>

                if (point.isInMontgomeryForm) {
                    throw new Error("The given point is already in montgomery form.");
                }

                if (!point.isInfinity) {
                    montgomeryMultiplier.convertToMontgomeryForm(point.x);
                    montgomeryMultiplier.convertToMontgomeryForm(point.y);

                    if (point.z !== null) {
                        montgomeryMultiplier.convertToMontgomeryForm(point.z);
                    }
                }

                point.isInMontgomeryForm = true;
            },

            convertToStandardForm: function (point) {
                /// <param name="point" type="EllipticCurvePointFp"/>

                if (!point.isInMontgomeryForm) {
                    throw new Error("The given point is not in montgomery form.");
                }

                if (!point.isInfinity) {
                    montgomeryMultiplier.convertToStandardForm(point.x);
                    montgomeryMultiplier.convertToStandardForm(point.y);
                    if (point.z !== null) {
                        montgomeryMultiplier.convertToStandardForm(point.z);
                    }
                }

                point.isInMontgomeryForm = false;

            },

            convertToAffineForm: function (point) {
                /// <param name="point" type="EllipticCurvePointFp"/>

                if (point.isInfinity) {
                    point.z = null;
                    setterSupport || (point.isAffine = true);
                    return;
                }

                // DETERMINE 1/Z IN MONTGOMERY FORM --------------------------------

                // Call out to the basic inversion function, not the one in this class.
                cryptoMath.modInv(point.z, curve.p, conversionTemp2);

                if (point.isInMontgomeryForm) {
                    montgomeryMultiply(conversionTemp2, montgomeryMultiplier.rCubedModm, conversionTemp1);
                    var swap = conversionTemp2;
                    conversionTemp2 = conversionTemp1;
                    conversionTemp1 = swap;
                }

                // CONVERT TO AFFINE COORDS ----------------------------------------

                // 'temp0 <- 1/z^2'
                montgomerySquare(conversionTemp2, conversionTemp0);

                // Compute point.x = x / z^2 mod p
                // NOTE: We cannot output directly to the X digit array since it is 
                // used for input to the multiplication routine, so we output to temp1
                // and copy.
                montgomeryMultiply(point.x, conversionTemp0, conversionTemp1);
                for (var i = 0; i < fieldElementWidth; i += 1) {
                    point.x[i] = conversionTemp1[i];
                }

                // Compute point.y = y / z^3 mod p
                // temp1 <- y * 1/z^2.
                montgomeryMultiply(point.y, conversionTemp0, conversionTemp1);
                // 'y <- temp1 * temp2 (which == 1/z)'
                montgomeryMultiply(conversionTemp1, conversionTemp2, point.y);

                // Finally, point.z = z / z mod p = 1
                // We use z = NULL for this case to make detecting Jacobian form 
                // faster (otherwise we would have to scan the entire Z digit array).
                point.z = null;
                setterSupport || (point.isAffine = true);
            },

            convertToJacobianForm: function (point) {
                /// <param name="point" type="EllipticCurvePointFp"/>

                if (!point.isAffine) {
                    throw new Error("The given point is not in Affine form.");
                }

                setterSupport || (point.isAffine = false);

                var clonedDigits;
                var i;
                if (point.isInMontgomeryForm) {

                    // Z = 1 (montgomery form)
                    clonedDigits = createArray(onemontgomery.length);
                    for (i = 0; i < onemontgomery.length; i += 1) {
                        clonedDigits[i] = onemontgomery[i];
                    }

                    point.z = clonedDigits;
                } else {

                    // Z = 1 (standard form)
                    clonedDigits = createArray(one.length);
                    for (i = 0; i < one.length; i += 1) {
                        clonedDigits[i] = one[i];
                    }

                    point.z = clonedDigits;
                }

            },

            // For tests
            generatePrecomputationTable: function (w, generatorPoint) {
                /// <param name="w" type="Number"/>
                /// <param name="generatorPoint" type="EllipticCurvePointFp"/>

                return generatePrecomputationTable(w, generatorPoint);
            }

        };
    };
    var sec1EncodingFp = function () {
        return {
            encodePoint: function (/*@type(EllipticCurvePointFp)*/ point) {
                /// <summary>Encode an EC point without compression.
                /// This function encodes a given points into a bytes array containing 0x04 | X | Y, where X and Y are big endian bytes of x and y coordinates.</summary>
                /// <param name="point" type="EllipticCurvePointFp">Input EC point to encode.</param>
                /// <returns type="Array">A bytes array containing 0x04 | X | Y, where X and Y are big endian encoded x and y coordinates.</returns>

                if (!point) {
                    throw new Error("point");
                }

                if (!point.isAffine) {
                    throw new Error("Point must be in affine form.");
                }

                if (point.isInMontgomeryForm) {
                    throw new Error("Point must not be in Montgomery form.");
                }

                if (point.isInfinity) {
                    return createArray(1); /* [0] */
                } else {
                    var xOctetString = cryptoMath.digitsToBytes(point.x);
                    var yOctetString = cryptoMath.digitsToBytes(point.y);
                    var pOctetString = cryptoMath.digitsToBytes(point.curve.p);     // just to get byte length of p
                    var mlen = pOctetString.length;
                    if (mlen < xOctetString.length || mlen < yOctetString.length) {
                        throw new Error("Point coordinate(s) are bigger than the field order.");
                    }
                    var output = createArray(2 * mlen + 1);       // for encoded x and y

                    output[0] = 0x04;
                    var offset = mlen - xOctetString.length;
                    for (var i = 0; i < xOctetString.length; i++) {
                        output[i + 1 + offset] = xOctetString[i];
                    }
                    offset = mlen - yOctetString.length;
                    for (i = 0; i < yOctetString.length; i++) {
                        output[mlen + i + 1 + offset] = yOctetString[i];
                    }

                    return output;
                }

            },
            decodePoint: function (encoded, curve) {
                /// <param name="encoded" type="Digits"/>
                /// <param name="curve" type="EllipticCurveFp"/>

                if (encoded.length < 1) {
                    throw new Error("Byte array must have non-zero length");
                }

                var pOctetString = cryptoMath.digitsToBytes(curve.p);
                var mlen = pOctetString.length;

                if (encoded[0] === 0x0 && encoded.length === 1) {
                    return curve.createPointAtInfinity();
                } else if (encoded[0] === 0x04 && encoded.length === 1 + 2 * mlen) {
                    // Standard encoding.
                    // Each point is a big endian string of bytes of length.
                    //      'ceiling(log_2(Q)/8)'
                    // Zero-padded and representing the magnitude of the coordinate.
                    var xbytes = createArray(mlen);
                    var ybytes = createArray(mlen);

                    for (var i = 0; i < mlen; i++) {
                        xbytes[i] = encoded[i + 1];
                        ybytes[i] = encoded[mlen + i + 1];
                    }

                    var x = cryptoMath.bytesToDigits(xbytes);
                    var y = cryptoMath.bytesToDigits(ybytes);

                    return EllipticCurvePointFp(curve, false, x, y);
                } else {
                    // We don't support other encoding features such as compression
                    throw new Error("Unsupported encoding format");
                }
            }
        };
    };
    var ModularSquareRootSolver = function (modulus) {
        /// <param name="modulus" type="Digits"/>

        // The modulus we are going to use.
        var p = modulus;

        // Special-K not just for breakfast anymore! This is k = (p-3)/4 + 1
        // which is used for NIST curves (or any curve of with P= 3 mod 4).
        // This field is null if p is not of the special form, or k if it is.
        var specialK = [];

        if (typeof modulus === "undefined") {
            throw new Error("modulus");
        }

        // Support for odd moduli, only.
        if (cryptoMath.isEven(modulus)) {
            throw new Error("Only odd moduli are supported");
        }

        // A montgomery multiplier object for doing fast squaring.
        var mul = cryptoMath.MontgomeryMultiplier(p);

        // 'p === 3 mod 4' then we can use the special super fast version.
        // Otherwise we must use the slower general case algorithm.
        if (p[0] % 4 === 3) {
            // 'special k = (p + 1) / 4'
            cryptoMath.add(p, cryptoMath.One, specialK);
            cryptoMath.shiftRight(specialK, specialK, 2);
        } else {
            specialK = null;
        }

        // Temp storage
        var temp0 = new Array(p.length);
        var temp1 = new Array(p.length);

        function squareRootNistCurves(a) {
            /// <summary>Given a number a, returns a solution x to x^2 = a (mod p).</summary>
            /// <param name="a" type="Array">An integer a.</param>
            /// <returns type="Array">The square root of the number a modulo p, if it exists,
            /// otherwise null.</returns>

            // beta = a^k mod n where k=(n+1)/4 for n == 3 mod 4, thus a^(1/2) mod n
            var beta = cryptoMath.intToDigits(0, 16);
            mul.modExp(a, specialK, beta);

            // Okay now we gotta double check by squaring.
            var aPrime = [0];
            cryptoMath.modMul(beta, beta, mul.m, aPrime);

            // If a != x^2 then a has no square root
            if (cryptoMath.compareDigits(a, aPrime) !== 0) {
                return null;
            }

            return beta;
        }

        var publicMethods = {

            squareRoot: function (a) {
                if (specialK !== null) {
                    // Use the special case fast code
                    return squareRootNistCurves(a);
                } else {
                    // Use the general case code
                    throw new Error("GeneralCase not supported.");
                }
            },

            // Given an integer a, this routine returns the Jacobi symbol (a/p), 
            // where p is the modulus given in the constructor, which for p an 
            // odd prime is also the Legendre symbol. From "Prime Numbers, A 
            // Computational Perspective" by Crandall and Pomerance, alg. 2.3.5.
            // The Legendre symbol is defined as:
            //   0   if a === 0 mod p.
            //   1   if a is a quadratic residue (mod p).
            //   -1  if a is a quadratic non-reside (mod p).
            jacobiSymbol: function (a) {
                /// <param name="a">An integer a.</param>

                var modEightMask = 0x7,
                    modFourMask = 0x3,
                    aPrime,
                    pPrime;

                // Clone our inputs, we are going to destroy them
                aPrime = a.slice();
                pPrime = p.slice();

                // 'a = a mod p'.
                cryptoMath.reduce(aPrime, pPrime, aPrime, temp0, temp1);

                // 't = 1'
                var t = 1;

                // While (a != 0)
                while (!cryptoMath.isZero(aPrime)) {
                    // While a is even
                    while (cryptoMath.isEven(aPrime)) {
                        // 'a <- a / 2'
                        cryptoMath.shiftRight(aPrime, aPrime);

                        // If (p mod 8 in {3,5}) t = -t;
                        var pMod8 = (pPrime[0] & modEightMask);
                        if (pMod8 === 3 || pMod8 === 5) {
                            t = -t;
                        }
                    }

                    // Swap variables
                    // (a, p) = (p, a).
                    var tmp = aPrime;
                    aPrime = pPrime;
                    pPrime = tmp;

                    // If (a === p === 3 (mod 4)) t = -t;
                    var aMod4 = (aPrime[0] & modFourMask);
                    var pMod4 = (pPrime[0] & modFourMask);
                    if (aMod4 === 3 && pMod4 === 3) {
                        t = -t;
                    }

                    // 'a = a mod p'
                    cryptoMath.reduce(aPrime, pPrime, aPrime, temp0, temp1);
                }

                // If (p == 1) return t else return 0
                if (cryptoMath.compareDigits(pPrime, cryptoMath.One) === 0) {
                    return t;
                } else {
                    return 0;
                }
            }

        };

        return publicMethods;
    };

    return {
        createP256: createP256,
        createP384: createP384,
        createBN254: createBN254,
        createANeg3Curve: createANeg3Curve,
        sec1EncodingFp: sec1EncodingFp,
        EllipticCurvePointFp: EllipticCurvePointFp,
        EllipticCurveOperatorFp: EllipticCurveOperatorFp,
        ModularSquareRootSolver: ModularSquareRootSolver
    };
}

var cryptoECC = cryptoECC || MsrcryptoECC();
