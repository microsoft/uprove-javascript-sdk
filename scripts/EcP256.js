﻿// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// U-Prove ECP256 Recommended Parameters.
// See http://www.microsoft.com/uprove for details.

var UProve = UProve || {};

UProve.ECGroup = function ECGroup(curve) {
    this.curve = curve;
    this.ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);

    // allocates an element to store some computation results
    this.getIdentityElement = function () {
        // return the point at infinity
        return curve.createPointAtInfinity();
    }

    // creates an element from the serialized bytes
    this.createElementFromBytes = function (bytes) {
        return cryptoECC.sec1EncodingFp().decodePoint(bytes, this.curve);
    }

    this.createPoint = function (x, y) {
        return new cryptoECC.EllipticCurvePointFp(
            this.curve,
            false,
            cryptoMath.bytesToDigits(x),
            cryptoMath.bytesToDigits(y)
        );
    }

    // computes result = [scalar] point.
    this.modexp = function (point, scalar, result) {
        // point must be in Affine, Montgomery form
        if (!point.isAffine) this.ecOperator.convertToAffineForm(point);
        if (!point.isInMontgomeryForm) this.ecOperator.convertToMontgomeryForm(point);

        // scalar multiplication
        this.ecOperator.scalarMultiply(scalar.m_digits, point, result);

        // convert everyone back to Affine, Standard form
        if (!point.isAffine) this.ecOperator.convertToAffineForm(point);
        if (point.isInMontgomeryForm) this.ecOperator.convertToStandardForm(point);
        if (!result.isAffine) this.ecOperator.convertToAffineForm(result);
        if (result.isInMontgomeryForm) this.ecOperator.convertToStandardForm(result);
    }

    // computes result = a + b
    this.multiply = function (a, b, result) {
        // result must be in Jacobian, Montgomery form for the mixed add
        var temp = this.curve.allocatePointStorage();
        this.ecOperator.convertToMontgomeryForm(temp);
        this.ecOperator.convertToJacobianForm(temp);

        // "a" must be in Jacobian, Montgomery form 
        if (!a.isInMontgomeryForm) this.ecOperator.convertToMontgomeryForm(a);
        if (a.isAffine) this.ecOperator.convertToJacobianForm(a);

        // "b" must be in Affine, Montgomery form
        if (!b.isAffine) this.ecOperator.convertToAffineForm(b);
        if (!b.isInMontgomeryForm) this.ecOperator.convertToMontgomeryForm(b);

        // perform the mixed add
        this.ecOperator.mixedAdd(a, b, temp);

        // now convert everyone back to Affine, Standard form
        this.ecOperator.convertToAffineForm(a);
        this.ecOperator.convertToStandardForm(a);
        // b already in affine form
        this.ecOperator.convertToStandardForm(b);
        this.ecOperator.convertToAffineForm(temp);
        this.ecOperator.convertToStandardForm(temp);

        temp.copy(result);
    }
}

UProve.ECP256 = function ECP256() {

    // number of pregenerated generators
    this.n = 50;
    // gt index
    this.t = this.n + 1;

    this.generatorsX = [
    cryptoMath.createArray([
    0xf1, 0xb9, 0x86, 0xd5, 0xd1, 0x1f, 0x43, 0x48,
    0x3a, 0xe7, 0x36, 0xe8, 0x86, 0xaf, 0x75, 0x0e,
    0x87, 0x0d, 0x7f, 0x0c, 0x23, 0x12, 0xaa, 0xd8,
    0xdb, 0x5c, 0x8a, 0x3e, 0x34, 0xf5, 0x39, 0x1e
    ]),
    cryptoMath.createArray([
    0x15, 0x54, 0xcf, 0x98, 0x3e, 0x0b, 0x06, 0x0c,
    0x78, 0x70, 0x5e, 0xd7, 0xd1, 0x4a, 0x49, 0x41,
    0xb0, 0x2e, 0x60, 0x8c, 0xdb, 0x78, 0xf6, 0xa7,
    0x5a, 0x52, 0x34, 0x59, 0x78, 0x14, 0x1f, 0xd3
    ]),
    cryptoMath.createArray([
    0x32, 0x79, 0x1a, 0x77, 0x9e, 0x9a, 0xa4, 0x75,
    0xba, 0x26, 0x66, 0xa0, 0xe4, 0x7a, 0x92, 0x8b,
    0x21, 0xab, 0x19, 0x05, 0xfa, 0xaf, 0x48, 0xbb,
    0x80, 0x62, 0xba, 0xe9, 0x00, 0x9e, 0xb2, 0x7d
    ]),
    cryptoMath.createArray([
    0xc0, 0xef, 0xad, 0xb5, 0xc3, 0x01, 0x5e, 0x42,
    0xc1, 0xd7, 0x1a, 0xc3, 0x90, 0xc4, 0xd2, 0x2a,
    0x6f, 0x5d, 0x55, 0x2f, 0x63, 0xbb, 0xcc, 0x59,
    0x19, 0x0a, 0xea, 0x6a, 0xee, 0x16, 0x35, 0x4a
    ]),
    cryptoMath.createArray([
    0xbd, 0x5f, 0x29, 0xdf, 0x66, 0x40, 0x49, 0x3f,
    0xf9, 0x6c, 0x6c, 0xbc, 0x49, 0xcb, 0x8e, 0x5f,
    0x61, 0x46, 0x27, 0x92, 0xdb, 0x75, 0xf2, 0x0e,
    0xf4, 0x9b, 0xf8, 0x6e, 0x26, 0x0d, 0xc9, 0x55
    ]),
    cryptoMath.createArray([
    0xd9, 0x1a, 0xbd, 0xa2, 0x6e, 0xc5, 0xc3, 0x00,
    0x1c, 0xf1, 0xca, 0x2c, 0x09, 0xad, 0x88, 0x66,
    0x25, 0x58, 0x42, 0x6d, 0xc3, 0xb4, 0xd1, 0xb5,
    0x01, 0xe7, 0xab, 0xc2, 0xdb, 0x08, 0x0c, 0xdc
    ]),
    cryptoMath.createArray([
    0x86, 0xeb, 0x2c, 0x94, 0xe2, 0xb6, 0xd6, 0x20,
    0xa3, 0x91, 0xb4, 0x08, 0x0d, 0xfe, 0x2b, 0x37,
    0x7c, 0xc2, 0x0d, 0x98, 0x1b, 0x5b, 0xc0, 0xcc,
    0xa9, 0x4e, 0x86, 0x56, 0x97, 0x95, 0x9e, 0xbe
    ]),
    cryptoMath.createArray([
    0x55, 0x53, 0x14, 0x8e, 0x44, 0x25, 0x26, 0x92,
    0xd9, 0xe7, 0xea, 0x9c, 0x18, 0x94, 0x69, 0xdd,
    0x2c, 0x0e, 0x8b, 0xd4, 0x49, 0x40, 0x5b, 0x6f,
    0x3b, 0x1f, 0x27, 0x92, 0x45, 0xb3, 0x7f, 0x0d
    ]),
    cryptoMath.createArray([
    0x77, 0x66, 0x8d, 0x97, 0xbf, 0xf7, 0xd5, 0xda,
    0x69, 0x5d, 0x6d, 0x72, 0xe4, 0xf8, 0x40, 0x20,
    0x5d, 0xe2, 0x89, 0xce, 0x8f, 0xf1, 0xe9, 0x95,
    0x24, 0x35, 0xb0, 0xb4, 0xdd, 0x4e, 0x22, 0x2e
    ]),
    cryptoMath.createArray([
    0x72, 0x9a, 0x72, 0xbe, 0x83, 0x75, 0x88, 0x8f,
    0x67, 0xdf, 0x96, 0xd2, 0xa5, 0x2e, 0x1b, 0x38,
    0x4a, 0xf1, 0xc6, 0x8f, 0xf8, 0xb7, 0x3c, 0xad,
    0xf6, 0x29, 0x6c, 0x72, 0xc2, 0xc1, 0xfa, 0xb2
    ]),
    cryptoMath.createArray([
    0xcf, 0xba, 0x01, 0x4e, 0xf2, 0x73, 0x4b, 0xb0,
    0xd5, 0x18, 0x63, 0xa1, 0xe6, 0xae, 0x8e, 0xb4,
    0xae, 0x18, 0x9f, 0x8c, 0x19, 0x43, 0x2a, 0xf4,
    0x6d, 0x9f, 0x16, 0xfd, 0xd4, 0x3f, 0xbc, 0x18
    ]),
    cryptoMath.createArray([
    0x6c, 0x14, 0x07, 0xc4, 0x9a, 0x51, 0xf6, 0x76,
    0x25, 0xeb, 0x8b, 0x29, 0x95, 0xac, 0x11, 0x94,
    0x42, 0x88, 0x99, 0x5b, 0x3a, 0x81, 0x78, 0x9a,
    0x5e, 0xb3, 0xe6, 0xbf, 0x4f, 0x2d, 0xed, 0x78
    ]),
    cryptoMath.createArray([
    0xd9, 0x23, 0x1c, 0x31, 0x5b, 0xaf, 0x72, 0x24,
    0x69, 0xf7, 0x4f, 0xba, 0x55, 0xba, 0x66, 0x17,
    0x77, 0xe9, 0x1c, 0xa6, 0x32, 0x0a, 0x88, 0x25,
    0xbd, 0xa1, 0xcb, 0xf0, 0xea, 0x20, 0x60, 0x92
    ]),
    cryptoMath.createArray([
    0x35, 0x35, 0x87, 0x11, 0x38, 0x41, 0x06, 0xb8,
    0x62, 0xa2, 0xcf, 0x0b, 0x40, 0x3e, 0x80, 0x55,
    0x92, 0x0c, 0x75, 0x98, 0xbf, 0xb4, 0x99, 0x87,
    0xa8, 0x9c, 0x35, 0x69, 0xe5, 0xa0, 0x5b, 0x61
    ]),
    cryptoMath.createArray([
    0x25, 0xd0, 0x5c, 0x26, 0x17, 0x72, 0x16, 0x6c,
    0x08, 0x48, 0x3d, 0x00, 0x00, 0x3f, 0x44, 0x35,
    0x20, 0xe9, 0x13, 0x24, 0xcb, 0xe9, 0x18, 0xfc,
    0x34, 0x00, 0x8a, 0x93, 0x27, 0x16, 0xd7, 0xeb
    ]),
    cryptoMath.createArray([
    0xfc, 0x03, 0x5c, 0x85, 0xaa, 0x0e, 0x9c, 0x52,
    0x7e, 0xa7, 0xdc, 0xa2, 0x6a, 0x2d, 0xb7, 0x4d,
    0xc2, 0x50, 0xe8, 0xa5, 0xab, 0xe8, 0x53, 0xbb,
    0xde, 0xd1, 0x59, 0x59, 0xd7, 0x23, 0x0f, 0x43
    ]),
    cryptoMath.createArray([
    0x85, 0xb3, 0x87, 0x3f, 0xd9, 0x11, 0xbf, 0x06,
    0xa9, 0x78, 0xfa, 0x40, 0xe2, 0x61, 0xe1, 0xc8,
    0x56, 0xf6, 0x38, 0xca, 0x9e, 0xc8, 0xcb, 0xe8,
    0x82, 0x6a, 0x60, 0x82, 0xc8, 0x45, 0x2d, 0x0f
    ]),
    cryptoMath.createArray([
    0x45, 0x49, 0xf8, 0xc6, 0x21, 0xea, 0xba, 0x57,
    0xed, 0x23, 0x36, 0xd5, 0x19, 0x20, 0xf6, 0xfc,
    0x4d, 0xc3, 0x4e, 0x04, 0x7d, 0xb1, 0x34, 0xc6,
    0x19, 0x80, 0xe4, 0xe3, 0x58, 0xc5, 0xe3, 0x24
    ]),
    cryptoMath.createArray([
    0xb8, 0xad, 0x38, 0x6b, 0x54, 0xf9, 0x76, 0x6e,
    0x5c, 0xb1, 0xa2, 0xf0, 0x50, 0xcb, 0xca, 0x2a,
    0x22, 0x61, 0x9b, 0xa0, 0x08, 0xfd, 0xf9, 0x49,
    0x6d, 0xf3, 0x8a, 0x6c, 0xea, 0x78, 0x4e, 0xb2
    ]),
    cryptoMath.createArray([
    0x56, 0x62, 0x8c, 0x7d, 0x63, 0x66, 0xe1, 0xc4,
    0xa9, 0x36, 0x1e, 0x5f, 0x7e, 0x49, 0x41, 0x5c,
    0x80, 0xfd, 0xa1, 0x4c, 0x04, 0xf1, 0x06, 0xf0,
    0x63, 0x8e, 0xc8, 0xcf, 0x59, 0xaa, 0x04, 0x85
    ]),
    cryptoMath.createArray([
    0x8f, 0x1f, 0x5a, 0x0e, 0x34, 0x2e, 0x65, 0x57,
    0xb9, 0x55, 0x35, 0x54, 0x38, 0x60, 0x8d, 0xb0,
    0x9e, 0x4d, 0x23, 0x7e, 0xc7, 0x23, 0x0e, 0x2c,
    0x83, 0x6b, 0xd5, 0xf3, 0xe9, 0x1c, 0x6c, 0x12
    ]),
    cryptoMath.createArray([
    0xbe, 0xaf, 0x77, 0x57, 0xa3, 0xce, 0x43, 0xdc,
    0x8d, 0x4a, 0x07, 0x32, 0xe1, 0xe3, 0x18, 0xf4,
    0x97, 0x55, 0xe6, 0x1e, 0x5f, 0x57, 0xa8, 0x5b,
    0xec, 0xcf, 0x21, 0xb7, 0xdc, 0xc8, 0x18, 0xe2
    ]),
    cryptoMath.createArray([
    0xe5, 0x13, 0xc3, 0xe5, 0x0e, 0xfa, 0x44, 0x36,
    0x19, 0x9c, 0x5a, 0x51, 0xfd, 0x69, 0x1e, 0xa4,
    0xdc, 0xab, 0xbc, 0x20, 0x2a, 0x80, 0x29, 0xba,
    0x3d, 0xf0, 0x33, 0x6f, 0x12, 0xd8, 0x26, 0x63
    ]),
    cryptoMath.createArray([
    0xb4, 0x2b, 0x3b, 0x05, 0xbc, 0xaf, 0xbb, 0x72,
    0x80, 0x0e, 0xe2, 0x42, 0xab, 0x4c, 0xb7, 0xab,
    0xd7, 0x7f, 0x1f, 0xce, 0xac, 0x7c, 0xe1, 0xd3,
    0x27, 0xee, 0xc2, 0x5b, 0x3d, 0xe6, 0xc4, 0x3d
    ]),
    cryptoMath.createArray([
    0xc8, 0xa4, 0xa7, 0xdf, 0x6b, 0xef, 0x6c, 0x61,
    0xef, 0x50, 0xbf, 0xfd, 0x9c, 0xfa, 0x7e, 0xfd,
    0xe2, 0x25, 0x30, 0xf0, 0xb2, 0xd0, 0x37, 0x1e,
    0x81, 0x9b, 0x80, 0xe8, 0x85, 0xd5, 0x92, 0xdd
    ]),
    cryptoMath.createArray([
    0xa2, 0x2a, 0xf4, 0x5e, 0x5a, 0x7a, 0x9a, 0x9f,
    0x94, 0x91, 0x0e, 0x8c, 0xdb, 0x5e, 0x64, 0x9e,
    0x83, 0xc3, 0x8f, 0xc1, 0x36, 0x9f, 0x1c, 0xa9,
    0xfa, 0x1d, 0x51, 0x88, 0x7c, 0x38, 0xdd, 0xf1
    ]),
    cryptoMath.createArray([
    0x22, 0xf4, 0x7a, 0x6a, 0xae, 0xc1, 0x42, 0x35,
    0x94, 0x81, 0xee, 0xa4, 0x90, 0x98, 0x88, 0x2b,
    0x3e, 0xca, 0xc4, 0x62, 0x5b, 0x1d, 0x25, 0x62,
    0xb0, 0x27, 0x18, 0x48, 0x76, 0x2c, 0x5d, 0xde
    ]),
    cryptoMath.createArray([
    0xea, 0xe2, 0x4e, 0x9c, 0xbf, 0x4a, 0x8e, 0xb9,
    0x2c, 0x1c, 0xc8, 0x0d, 0x75, 0xdc, 0xf4, 0x4c,
    0x39, 0xdf, 0xe4, 0xed, 0xcf, 0x13, 0xc3, 0xe5,
    0xe4, 0xb7, 0xba, 0x08, 0xc3, 0x29, 0x37, 0x8d
    ]),
    cryptoMath.createArray([
    0xad, 0x92, 0xb0, 0x98, 0x52, 0x8a, 0xe2, 0x08,
    0x57, 0x24, 0x74, 0xe3, 0xca, 0x2b, 0x1f, 0x6f,
    0xbe, 0x13, 0x3c, 0xb4, 0xfa, 0xb5, 0xee, 0xba,
    0x0e, 0x46, 0x10, 0x0c, 0x68, 0x4d, 0x5b, 0xbc
    ]),
    cryptoMath.createArray([
    0xdc, 0x5a, 0xbc, 0x9d, 0x9e, 0x2a, 0x04, 0xa7,
    0xba, 0x38, 0x34, 0x6e, 0x82, 0x71, 0x19, 0xf5,
    0x0f, 0xa3, 0x11, 0xb8, 0xcb, 0x4b, 0x12, 0xcf,
    0x53, 0x60, 0x2f, 0x34, 0x82, 0xa6, 0x09, 0xc0
    ]),
    cryptoMath.createArray([
    0x5d, 0x00, 0x8b, 0x9b, 0xde, 0xbb, 0x38, 0x24,
    0x93, 0x5b, 0xdc, 0x68, 0xa7, 0xac, 0x42, 0x6c,
    0x55, 0x40, 0x58, 0xa9, 0xdc, 0x4e, 0xd8, 0xbe,
    0xa2, 0xea, 0x74, 0xa9, 0x2d, 0xf4, 0x7f, 0xc3
    ]),
    cryptoMath.createArray([
    0x4b, 0xff, 0x16, 0x06, 0x7e, 0x37, 0x79, 0x8f,
    0xf3, 0xe3, 0x24, 0x2b, 0x11, 0xbe, 0x39, 0xf8,
    0x3d, 0xd7, 0x45, 0x1e, 0xbe, 0x11, 0x01, 0xea,
    0xc4, 0x88, 0x7a, 0x6f, 0x93, 0xd5, 0x02, 0x06
    ]),
    cryptoMath.createArray([
    0xae, 0xcb, 0xa7, 0xf0, 0x74, 0x51, 0x23, 0xd9,
    0xc6, 0xa6, 0x0e, 0x9b, 0xd4, 0x61, 0xa8, 0x63,
    0x61, 0x31, 0xb0, 0x95, 0xf5, 0x96, 0x17, 0x84,
    0x9d, 0x33, 0x5d, 0x2a, 0x7d, 0x8b, 0x18, 0x7b
    ]),
    cryptoMath.createArray([
    0xa7, 0x4e, 0xcb, 0x80, 0x73, 0x24, 0x96, 0xe8,
    0xf6, 0xce, 0x72, 0xf4, 0x55, 0x69, 0x37, 0xc2,
    0x37, 0xe1, 0x9e, 0xfa, 0xc7, 0x56, 0x7c, 0x15,
    0x1f, 0x38, 0x6b, 0x65, 0x06, 0x56, 0xa2, 0x26
    ]),
    cryptoMath.createArray([
    0xed, 0x0e, 0x96, 0x56, 0x69, 0x01, 0x7a, 0xa7,
    0x1f, 0x34, 0x2e, 0xc8, 0xa0, 0x99, 0xbb, 0xf0,
    0x1a, 0x0b, 0x9e, 0xab, 0x94, 0xf6, 0x26, 0x23,
    0xec, 0xf9, 0x6b, 0xcc, 0x0e, 0x14, 0xe4, 0xab
    ]),
    cryptoMath.createArray([
    0x06, 0x9b, 0x84, 0x3b, 0xdb, 0xf0, 0x17, 0xd4,
    0x16, 0xa7, 0x67, 0xd1, 0x34, 0xe1, 0xc2, 0xd4,
    0x97, 0xfa, 0xd2, 0xcd, 0xaa, 0xe3, 0x6b, 0x27,
    0x53, 0x70, 0xff, 0x51, 0x2a, 0x34, 0xbf, 0xa7
    ]),
    cryptoMath.createArray([
    0x59, 0x2d, 0x48, 0x15, 0x8a, 0x63, 0x58, 0xa2,
    0x90, 0x0d, 0x45, 0x3d, 0x79, 0xe8, 0x8d, 0x6b,
    0xc2, 0x0b, 0x7f, 0xa8, 0xcb, 0x2b, 0xfc, 0xfc,
    0xdf, 0xd0, 0x82, 0x96, 0x05, 0x25, 0xad, 0x83
    ]),
    cryptoMath.createArray([
    0x18, 0xff, 0xac, 0x75, 0x07, 0xb8, 0xf0, 0x22,
    0xeb, 0xa9, 0x72, 0x2a, 0xea, 0x93, 0xc6, 0xca,
    0x74, 0x70, 0x82, 0x5a, 0x78, 0x7c, 0x1f, 0x98,
    0x2b, 0x08, 0x3d, 0xda, 0x04, 0x90, 0xed, 0x32
    ]),
    cryptoMath.createArray([
    0xdd, 0xe5, 0xdf, 0xc2, 0x86, 0x7a, 0x61, 0xba,
    0x2e, 0x04, 0x6d, 0xd5, 0x25, 0x76, 0xd3, 0xd3,
    0x3a, 0x24, 0x17, 0x3e, 0x32, 0xd7, 0x16, 0xca,
    0xf0, 0xd6, 0xbc, 0x4b, 0xd1, 0x19, 0x43, 0x74
    ]),
    cryptoMath.createArray([
    0xe0, 0xf7, 0x2a, 0x8c, 0x71, 0x39, 0x5e, 0x19,
    0x06, 0x3b, 0x0e, 0x09, 0xf9, 0x47, 0xf8, 0x6c,
    0x06, 0xf4, 0xb3, 0x00, 0xc8, 0x1d, 0x3b, 0xbb,
    0xc4, 0x8d, 0xcb, 0x21, 0x9a, 0xb9, 0x60, 0xaa
    ]),
    cryptoMath.createArray([
    0x38, 0x53, 0x88, 0x07, 0x8e, 0xa2, 0xb4, 0x79,
    0x2d, 0xac, 0x8f, 0xbe, 0x0b, 0x47, 0x48, 0xb9,
    0x98, 0x00, 0xca, 0x08, 0x66, 0x62, 0xfa, 0x8e,
    0xab, 0xd6, 0x25, 0x96, 0xdd, 0x7e, 0x5c, 0x53
    ]),
    cryptoMath.createArray([
    0xb1, 0x08, 0xaa, 0x3e, 0x8b, 0xf1, 0xf7, 0x07,
    0xf6, 0xba, 0x95, 0x56, 0xaa, 0x0f, 0x18, 0x71,
    0x51, 0x97, 0x34, 0xa6, 0x98, 0x20, 0x3f, 0x75,
    0x32, 0x92, 0x54, 0x43, 0xb2, 0x02, 0x0c, 0xbd
    ]),
    cryptoMath.createArray([
    0x06, 0x05, 0xb3, 0x50, 0x5f, 0x77, 0xe7, 0x4b,
    0x22, 0xea, 0x7e, 0x67, 0xc3, 0x33, 0x3f, 0xf3,
    0xb7, 0xb7, 0x71, 0x73, 0x83, 0x89, 0xd3, 0x05,
    0xaa, 0x59, 0x4d, 0x8f, 0x55, 0x02, 0x37, 0xdb
    ]),
    cryptoMath.createArray([
    0xd8, 0x18, 0x83, 0xa9, 0xcf, 0x1d, 0xc3, 0x04,
    0x3c, 0x44, 0xf9, 0xf0, 0xf9, 0xff, 0x50, 0x2c,
    0xd0, 0x45, 0xe4, 0x29, 0x4c, 0x37, 0x5a, 0x30,
    0xa8, 0xa6, 0x5a, 0xbc, 0x0d, 0xd2, 0x82, 0x64
    ]),
    cryptoMath.createArray([
    0x93, 0xec, 0x90, 0x87, 0x9c, 0xd2, 0xd8, 0x6a,
    0x22, 0x76, 0xf4, 0x4b, 0x42, 0xdf, 0x73, 0x62,
    0x83, 0xd2, 0x97, 0x47, 0x07, 0x59, 0xde, 0x0a,
    0xf2, 0xc6, 0xc9, 0x2f, 0x16, 0x84, 0x82, 0xaf
    ]),
    cryptoMath.createArray([
    0x4e, 0x9e, 0x9e, 0xb8, 0xe2, 0x67, 0xc0, 0xd6,
    0x17, 0x60, 0xec, 0xab, 0xc9, 0xac, 0x19, 0xdd,
    0xac, 0x5d, 0xb9, 0x5c, 0x28, 0x33, 0x4e, 0xc9,
    0x9d, 0x49, 0xd7, 0x4d, 0x40, 0xb6, 0x6d, 0xaf
    ]),
    cryptoMath.createArray([
    0xce, 0xb4, 0xca, 0x98, 0xf6, 0x20, 0x19, 0x59,
    0x6b, 0x9b, 0xc6, 0x23, 0x4e, 0xa5, 0xc2, 0x02,
    0x99, 0x90, 0xf0, 0x8d, 0x06, 0x8f, 0x27, 0xee,
    0xf4, 0xfa, 0x7d, 0x98, 0x97, 0xbf, 0xaf, 0x62
    ]),
    cryptoMath.createArray([
    0x80, 0xe8, 0x70, 0x67, 0x09, 0xbd, 0x25, 0xa8,
    0x49, 0x37, 0x41, 0x7e, 0x2d, 0x6a, 0x6d, 0xaf,
    0xa8, 0x3d, 0x37, 0x38, 0xdf, 0xb4, 0x2f, 0x8e,
    0xef, 0xa0, 0xfb, 0x52, 0x47, 0xd6, 0x99, 0x85
    ]),
    cryptoMath.createArray([
    0x13, 0xbd, 0x26, 0x06, 0x06, 0x67, 0xf8, 0xeb,
    0x7e, 0x56, 0xe7, 0x82, 0x85, 0x4a, 0xf3, 0xb3,
    0xe0, 0x10, 0xcf, 0x18, 0x25, 0xa6, 0x84, 0xbc,
    0x72, 0xb2, 0x87, 0xea, 0x7b, 0x2c, 0x23, 0x4c
    ]),
    cryptoMath.createArray([
    0x7d, 0x5e, 0x69, 0xba, 0xce, 0x92, 0x0e, 0x8e,
    0xd2, 0xd0, 0xb4, 0x3a, 0xd1, 0x48, 0x49, 0xd7,
    0x1e, 0x26, 0x72, 0x9c, 0xb3, 0x7f, 0x00, 0x9a,
    0xe1, 0x4e, 0x6d, 0x8a, 0x06, 0x5e, 0x90, 0x79
    ]),
    cryptoMath.createArray([
    0xe2, 0xab, 0x81, 0xde, 0xf5, 0x93, 0xe9, 0x99,
    0xc9, 0x75, 0xa8, 0xa4, 0x86, 0x68, 0xb9, 0xa0,
    0x7e, 0x55, 0x94, 0xcf, 0xd6, 0x8f, 0xac, 0x29,
    0xf1, 0x7a, 0x81, 0x1c, 0xb2, 0x6b, 0x3e, 0x10
    ]),
    cryptoMath.createArray([
    0x4c, 0xa6, 0x25, 0x11, 0x8d, 0x0a, 0x05, 0xd0,
    0x4d, 0x27, 0x5d, 0xae, 0x1f, 0xf0, 0x96, 0x36,
    0x1e, 0xbe, 0xba, 0x34, 0x5c, 0x31, 0x27, 0x09,
    0x82, 0xf7, 0x96, 0x63, 0x9b, 0x1c, 0xa5, 0x74
    ])
    ];

    this.generatorsY = [
    cryptoMath.createArray([
    0x64, 0x34, 0x7b, 0x7f, 0x49, 0x31, 0x87, 0xa5,
    0x3b, 0x37, 0x08, 0x94, 0xb8, 0xf8, 0xe3, 0x8f,
    0xd2, 0x2c, 0xb9, 0x93, 0x02, 0x39, 0x3d, 0x79,
    0xdc, 0xe2, 0x25, 0x91, 0x8e, 0xba, 0x61, 0xee
    ]),
    cryptoMath.createArray([
    0x62, 0x54, 0x0e, 0x69, 0x0c, 0x8f, 0xa9, 0xfe,
    0x10, 0x7e, 0x21, 0x41, 0xdf, 0xc6, 0x90, 0x7f,
    0x74, 0xf5, 0xfe, 0xeb, 0xdf, 0x5b, 0x12, 0xd7,
    0x15, 0x3b, 0x46, 0x35, 0xa2, 0xdf, 0x6a, 0x76
    ]),
    cryptoMath.createArray([
    0x18, 0x74, 0xba, 0x86, 0xea, 0x19, 0x4f, 0xb1,
    0x4d, 0xcc, 0xe9, 0xfa, 0x22, 0x36, 0x6f, 0x47,
    0x35, 0xca, 0xea, 0x21, 0x19, 0xbe, 0xb6, 0x3f,
    0x2b, 0xae, 0xc1, 0x9a, 0x9e, 0x93, 0xa5, 0x45
    ]),
    cryptoMath.createArray([
    0x53, 0xf0, 0x13, 0x3e, 0xa4, 0x4d, 0xa2, 0x0c,
    0x50, 0x9a, 0x4e, 0x5b, 0xe9, 0xb0, 0x27, 0xdb,
    0xe1, 0x3e, 0x3a, 0x60, 0x43, 0x9d, 0xbe, 0x72,
    0x08, 0x4b, 0x0c, 0x75, 0xa0, 0x49, 0x72, 0x3f
    ]),
    cryptoMath.createArray([
    0x20, 0x4c, 0x44, 0x0e, 0xf8, 0xc6, 0xeb, 0x2b,
    0xec, 0x0c, 0x34, 0x3a, 0xce, 0x9c, 0x6d, 0x64,
    0xe1, 0x88, 0xc8, 0xb4, 0xf0, 0x61, 0x3d, 0x64,
    0x84, 0x6a, 0xdb, 0xdc, 0x3d, 0x8f, 0xdf, 0xad
    ]),
    cryptoMath.createArray([
    0x54, 0xeb, 0xb1, 0x7f, 0xed, 0x85, 0x5a, 0x36,
    0xc1, 0xf7, 0x4a, 0xb8, 0x25, 0x62, 0x08, 0xe8,
    0x63, 0x07, 0xa9, 0xf2, 0xb7, 0x56, 0xd7, 0xc8,
    0x4b, 0x4f, 0xb9, 0x48, 0x5e, 0x0f, 0xf5, 0xf5
    ]),
    cryptoMath.createArray([
    0x26, 0xac, 0x15, 0x89, 0xc5, 0x28, 0x80, 0xc3,
    0xb8, 0xf8, 0x1d, 0x2b, 0xf3, 0x29, 0x76, 0x63,
    0x60, 0x19, 0xf1, 0x6d, 0x8e, 0xfa, 0x1f, 0x4d,
    0x20, 0x95, 0x0b, 0x99, 0x08, 0xce, 0xb7, 0xe1
    ]),
    cryptoMath.createArray([
    0x79, 0x0c, 0xa4, 0xce, 0x90, 0xe0, 0x48, 0xa7,
    0x42, 0x5b, 0x66, 0x2a, 0x63, 0x16, 0x12, 0xd0,
    0x22, 0x4f, 0x20, 0x8e, 0x4b, 0xe6, 0xe9, 0x07,
    0xc3, 0xe7, 0xd9, 0x60, 0x7a, 0x99, 0x7f, 0x6d
    ]),
    cryptoMath.createArray([
    0x14, 0x76, 0x06, 0x0b, 0x33, 0xfe, 0x63, 0x6b,
    0xb9, 0xb7, 0x5f, 0x10, 0x78, 0x5d, 0x4b, 0x43,
    0x19, 0x05, 0xcd, 0x00, 0x6f, 0x83, 0x2b, 0xf7,
    0x31, 0x03, 0xb9, 0xf8, 0x80, 0x37, 0x85, 0x56
    ]),
    cryptoMath.createArray([
    0x01, 0x31, 0x20, 0xe6, 0x94, 0x2d, 0x07, 0x40,
    0xa2, 0x5f, 0x8b, 0x87, 0x1e, 0x1f, 0x2f, 0xe9,
    0xa8, 0x60, 0x49, 0x77, 0xd1, 0xda, 0xa1, 0x8a,
    0xf0, 0xe4, 0xfe, 0xd5, 0x70, 0xc6, 0xea, 0x2e
    ]),
    cryptoMath.createArray([
    0x12, 0x56, 0xc7, 0x84, 0xf8, 0x27, 0xc3, 0x1a,
    0xd2, 0x3d, 0x8d, 0x23, 0x36, 0x78, 0xce, 0x2e,
    0xeb, 0xce, 0x34, 0x46, 0x29, 0xe7, 0xa5, 0xf7,
    0xa6, 0xd9, 0x4a, 0xdc, 0x0f, 0xf4, 0x7a, 0x7e
    ]),
    cryptoMath.createArray([
    0x16, 0xd8, 0x72, 0x49, 0x4f, 0xc1, 0x8d, 0x77,
    0x40, 0x4f, 0x90, 0x6e, 0x58, 0x90, 0x21, 0x50,
    0xe1, 0xfc, 0xdd, 0xa0, 0xcf, 0x21, 0x15, 0x16,
    0xf6, 0xf1, 0x94, 0x15, 0xe8, 0x89, 0x2f, 0x26
    ]),
    cryptoMath.createArray([
    0x36, 0xe4, 0xcd, 0x12, 0x88, 0x08, 0x8d, 0xec,
    0xee, 0xa8, 0xe7, 0xb6, 0xd2, 0x2c, 0xfd, 0x97,
    0xb9, 0x9f, 0x87, 0xfa, 0xcc, 0x95, 0xf1, 0x89,
    0x1f, 0xc6, 0xa2, 0x8b, 0xd8, 0x1e, 0x5f, 0x50
    ]),
    cryptoMath.createArray([
    0x18, 0xed, 0xfa, 0x1d, 0xfc, 0x65, 0x3a, 0x05,
    0x74, 0xca, 0x88, 0xfd, 0xaa, 0xec, 0xdf, 0xe9,
    0xeb, 0x75, 0x30, 0x9a, 0xac, 0xbe, 0x92, 0x6c,
    0x21, 0x10, 0xe9, 0x26, 0x78, 0xc8, 0x4e, 0x3d
    ]),
    cryptoMath.createArray([
    0x66, 0x8a, 0x13, 0xc5, 0xd1, 0x63, 0xf6, 0x64,
    0x6b, 0xf2, 0xe8, 0xf4, 0x2d, 0x1f, 0x48, 0xe7,
    0x9a, 0x9e, 0xad, 0x02, 0x09, 0x22, 0xb3, 0x83,
    0x00, 0x6b, 0x67, 0x6d, 0x29, 0xd3, 0x5a, 0x42
    ]),
    cryptoMath.createArray([
    0x65, 0xf0, 0x52, 0xa3, 0x82, 0xb2, 0xc7, 0x8c,
    0xaa, 0x9f, 0xcf, 0xc9, 0x52, 0x09, 0x6f, 0x4c,
    0xcc, 0x47, 0x72, 0x54, 0x6e, 0x57, 0x98, 0x64,
    0x91, 0x23, 0xfe, 0xf9, 0x4e, 0xc9, 0x5a, 0xcc
    ]),
    cryptoMath.createArray([
    0x3c, 0xf0, 0x0d, 0x69, 0x58, 0x6f, 0x56, 0xbe,
    0xd8, 0x49, 0xd5, 0xe9, 0xe2, 0x82, 0x5a, 0x00,
    0x3c, 0xe5, 0x62, 0xaa, 0xb5, 0xf8, 0x1b, 0xd7,
    0x18, 0xa4, 0xe9, 0x41, 0x98, 0x9e, 0x11, 0x01
    ]),
    cryptoMath.createArray([
    0x39, 0xe8, 0xbe, 0x23, 0xf0, 0x40, 0x33, 0xa0,
    0xf8, 0xbc, 0x43, 0xd5, 0xa1, 0x1b, 0x1e, 0x79,
    0x8d, 0x25, 0xb5, 0xc7, 0x5d, 0x74, 0x0e, 0xfd,
    0x30, 0x99, 0x85, 0xed, 0xc5, 0xde, 0xdb, 0x98
    ]),
    cryptoMath.createArray([
    0x5b, 0x33, 0x3a, 0x0c, 0xde, 0x9d, 0xdc, 0x8d,
    0x65, 0x71, 0xb1, 0xca, 0xc4, 0x56, 0xa4, 0x71,
    0x44, 0xc9, 0xc1, 0x6e, 0xce, 0x86, 0x6a, 0x53,
    0x84, 0x94, 0xea, 0x0f, 0xea, 0xee, 0xf0, 0xac
    ]),
    cryptoMath.createArray([
    0x74, 0xfd, 0xc2, 0x60, 0x80, 0x2b, 0x6d, 0xf5,
    0x5a, 0x64, 0x02, 0x33, 0x88, 0x95, 0x35, 0xcd,
    0x04, 0xe0, 0xdf, 0x84, 0xb6, 0x6d, 0x9d, 0xa4,
    0x64, 0x5d, 0xa3, 0x11, 0x93, 0x99, 0x50, 0x46
    ]),
    cryptoMath.createArray([
    0x2c, 0x1a, 0x21, 0x02, 0xa6, 0x9e, 0xf7, 0x4a,
    0x00, 0x63, 0x53, 0xc2, 0xd2, 0xd1, 0xdd, 0x9d,
    0xbd, 0xfa, 0xb0, 0x07, 0xfd, 0x08, 0xe7, 0xc8,
    0x8e, 0xb8, 0x69, 0xa0, 0xa6, 0x69, 0xb1
    ]),
    cryptoMath.createArray([
    0x40, 0xd2, 0x6c, 0x2a, 0xdc, 0x3f, 0x41, 0xd0,
    0x91, 0x56, 0x02, 0x5a, 0x9d, 0xc3, 0x4f, 0xd3,
    0xca, 0x6b, 0x96, 0x80, 0x9d, 0x3d, 0x7c, 0xf5,
    0xf2, 0x8d, 0x00, 0xa1, 0xed, 0xbd, 0x69, 0x95
    ]),
    cryptoMath.createArray([
    0x75, 0xf4, 0x2f, 0x58, 0x48, 0x0d, 0x2c, 0xad,
    0x56, 0x9b, 0x0f, 0x13, 0xcb, 0xf3, 0x76, 0xc3,
    0x91, 0x32, 0x71, 0xd9, 0xf7, 0x84, 0x42, 0x42,
    0xb8, 0x70, 0x51, 0x9d, 0x2b, 0xe8, 0x39, 0x8e
    ]),
    cryptoMath.createArray([
    0x72, 0x5f, 0x5b, 0x3d, 0x0c, 0xdd, 0x1b, 0x86,
    0xbd, 0x7a, 0x8b, 0xd6, 0x35, 0xc1, 0xac, 0xed,
    0xba, 0xc9, 0x1d, 0x6c, 0x35, 0x16, 0x3e, 0xae,
    0x66, 0x81, 0x07, 0x51, 0xf4, 0xd4, 0x62, 0x88
    ]),
    cryptoMath.createArray([
    0x19, 0x6e, 0x7e, 0x0a, 0x81, 0xd0, 0x3b, 0x38,
    0xa8, 0xf9, 0x91, 0x04, 0x81, 0x2f, 0x64, 0x78,
    0x4b, 0x62, 0xd4, 0x19, 0x91, 0xf5, 0x66, 0xde,
    0x27, 0x84, 0x7b, 0x6b, 0xb9, 0xba, 0xa2, 0x51
    ]),
    cryptoMath.createArray([
    0x75, 0x9b, 0xd3, 0x8c, 0x6e, 0x09, 0xfe, 0x2c,
    0xd7, 0x5b, 0x4f, 0x35, 0x5f, 0x44, 0x20, 0xe2,
    0xe7, 0xb2, 0xdf, 0xd9, 0xf7, 0x14, 0x7a, 0xa0,
    0x3d, 0x53, 0x73, 0xb3, 0x61, 0x2b, 0x83, 0x89
    ]),
    cryptoMath.createArray([
    0x3e, 0x0b, 0x7e, 0x0c, 0x51, 0xa0, 0x63, 0x30,
    0x35, 0x80, 0xca, 0x25, 0xe3, 0x26, 0xae, 0x7e,
    0x61, 0x08, 0x6e, 0xa6, 0xe4, 0xc4, 0x95, 0xd2,
    0x51, 0x62, 0x86, 0x70, 0x39, 0xd9, 0xfe, 0x4c
    ]),
    cryptoMath.createArray([
    0x2f, 0x7f, 0xff, 0xfa, 0x43, 0xa2, 0xd0, 0x26,
    0x8c, 0x25, 0xe4, 0xf0, 0x86, 0x63, 0xfe, 0xf2,
    0x6c, 0x57, 0x96, 0x2f, 0xd5, 0xf6, 0x23, 0x29,
    0x2f, 0x06, 0x1e, 0xa1, 0x9c, 0x57, 0x10, 0xa1
    ]),
    cryptoMath.createArray([
    0x47, 0x97, 0x86, 0x85, 0xfa, 0x8f, 0x41, 0xca,
    0x52, 0x46, 0xbd, 0x63, 0x47, 0xba, 0x65, 0xf6,
    0x70, 0xec, 0x65, 0xa1, 0x36, 0x16, 0x6c, 0x75,
    0xe7, 0x93, 0x63, 0x46, 0xe1, 0x6a, 0xd7, 0x90
    ]),
    cryptoMath.createArray([
    0xe9, 0x4f, 0x73, 0xd5, 0xd9, 0x64, 0x19, 0x42,
    0x18, 0x8f, 0xd0, 0xff, 0x64, 0xa7, 0x75, 0x10,
    0x21, 0xfa, 0xf6, 0xcc, 0x9c, 0x4d, 0x2a, 0xa0,
    0x31, 0x8e, 0x94, 0xf0, 0x59, 0x78, 0xbe
    ]),
    cryptoMath.createArray([
    0x18, 0x05, 0xd5, 0xf8, 0xf0, 0x97, 0xea, 0x8b,
    0x3b, 0x86, 0x08, 0xdc, 0x5f, 0x01, 0x6f, 0xd9,
    0x09, 0x78, 0x1b, 0x75, 0x90, 0x0d, 0x53, 0xce,
    0x8b, 0x65, 0x84, 0x65, 0x18, 0xca, 0x0b, 0xda
    ]),
    cryptoMath.createArray([
    0x06, 0x5e, 0x5e, 0x31, 0xe1, 0x50, 0x13, 0x60,
    0x36, 0xe1, 0x92, 0x25, 0x49, 0xb9, 0xfd, 0x9a,
    0x85, 0x59, 0x97, 0x12, 0x9f, 0x45, 0x66, 0xd3,
    0xf5, 0xac, 0xf8, 0xa1, 0xe4, 0xd0, 0xac, 0x83
    ]),
    cryptoMath.createArray([
    0x5f, 0x62, 0xd5, 0xea, 0xf4, 0xa9, 0xa8, 0x92,
    0x48, 0x8c, 0x0d, 0xe9, 0x5d, 0x8d, 0x85, 0xed,
    0xa9, 0x03, 0x5b, 0x65, 0x97, 0xea, 0x26, 0x74,
    0xd7, 0xa7, 0xee, 0x7d, 0x4a, 0x53, 0x5e, 0xbd
    ]),
    cryptoMath.createArray([
    0x04, 0xf6, 0x61, 0x41, 0x53, 0x13, 0x28, 0x4d,
    0x90, 0x44, 0x85, 0xe6, 0xf6, 0xdb, 0x8f, 0xe9,
    0x47, 0x82, 0xb2, 0xba, 0x24, 0xc0, 0xcb, 0xa6,
    0xca, 0x77, 0x55, 0x7e, 0xfc, 0xd8, 0xf0, 0x5e
    ]),
    cryptoMath.createArray([
    0x24, 0x4b, 0xf1, 0x25, 0x52, 0x3e, 0xf2, 0x97,
    0x8d, 0xb0, 0x60, 0x06, 0xcd, 0xa7, 0xcf, 0x3e,
    0x4d, 0x58, 0x39, 0x77, 0x11, 0xd9, 0x28, 0x97,
    0x60, 0x3d, 0xba, 0xe2, 0x9b, 0x82, 0x86, 0x4b
    ]),
    cryptoMath.createArray([
    0x3d, 0x3b, 0xe3, 0xd2, 0xe8, 0x6e, 0xb0, 0x7a,
    0x87, 0x84, 0x9b, 0x2e, 0xf1, 0x6e, 0xe3, 0x03,
    0x10, 0xb8, 0x6e, 0x63, 0xb3, 0x47, 0x81, 0x63,
    0xfd, 0x06, 0xb6, 0x59, 0x2b, 0xbd, 0xe5, 0x45
    ]),
    cryptoMath.createArray([
    0x72, 0x31, 0xc3, 0xd1, 0xf8, 0x6f, 0xcc, 0x1b,
    0x6c, 0x9e, 0x8c, 0x16, 0xae, 0x45, 0xa9, 0x35,
    0x08, 0xc9, 0xc4, 0x9e, 0x8a, 0x74, 0x5e, 0x64,
    0xb0, 0x76, 0x36, 0xfc, 0x6b, 0x03, 0x10, 0x3f
    ]),
    cryptoMath.createArray([
    0x30, 0x4b, 0x83, 0x60, 0x4a, 0x94, 0xff, 0x8a,
    0x27, 0x87, 0xb0, 0x47, 0xe8, 0x23, 0xe5, 0x0a,
    0x64, 0xed, 0xca, 0x0b, 0x1d, 0xcc, 0xb9, 0x38,
    0x11, 0x96, 0x59, 0x7a, 0x1c, 0x63, 0xb3, 0x62
    ]),
    cryptoMath.createArray([
    0x79, 0xb6, 0xe3, 0x0b, 0x18, 0x22, 0xd6, 0x1e,
    0xad, 0xe5, 0x9b, 0x0a, 0xb3, 0xed, 0xbe, 0x8f,
    0x42, 0x91, 0xc8, 0xe0, 0x81, 0xdd, 0xce, 0xde,
    0xff, 0x00, 0xbc, 0x32, 0xeb, 0xfc, 0x1a, 0x93
    ]),
    cryptoMath.createArray([
    0x6f, 0x23, 0x1e, 0x0a, 0x53, 0x8c, 0x8f, 0x54,
    0xc0, 0x66, 0xc9, 0x3e, 0x1a, 0xf8, 0x57, 0xbc,
    0x3b, 0x1c, 0x41, 0x88, 0x02, 0x27, 0x4c, 0xbd,
    0xf5, 0xe3, 0x87, 0xd8, 0x87, 0x36, 0xf5, 0x76
    ]),
    cryptoMath.createArray([
    0x4d, 0x21, 0x12, 0x11, 0x1d, 0x5b, 0xf4, 0x7b,
    0xae, 0xd1, 0xc4, 0xa2, 0x68, 0x8c, 0xfa, 0x61,
    0x6e, 0x7b, 0xbb, 0x64, 0xd4, 0x12, 0xf1, 0x6b,
    0x37, 0x12, 0x88, 0xbf, 0xe9, 0x57, 0xea, 0x61
    ]),
    cryptoMath.createArray([
    0x5a, 0x75, 0xfa, 0xe7, 0xad, 0x0b, 0xe2, 0x35,
    0x20, 0x73, 0x47, 0x79, 0xef, 0x11, 0xf3, 0x25,
    0xdd, 0xe7, 0xa6, 0xed, 0xc6, 0x33, 0x36, 0xef,
    0x9f, 0xb5, 0x86, 0x61, 0xfc, 0xcc, 0x46, 0xa5
    ]),
    cryptoMath.createArray([
    0x74, 0x87, 0xad, 0xb2, 0xe0, 0x7c, 0x3a, 0xb9,
    0x2e, 0x13, 0x86, 0x54, 0x67, 0x90, 0xa0, 0x11,
    0x49, 0x7e, 0xb9, 0xfb, 0x98, 0x46, 0x71, 0x6b,
    0x04, 0x79, 0x3d, 0xce, 0xa4, 0x30, 0xc7, 0xab
    ]),
    cryptoMath.createArray([
    0x1d, 0x75, 0xc9, 0x9e, 0xb4, 0x4e, 0x2d, 0x8b,
    0x43, 0xa5, 0x3f, 0x69, 0xb6, 0x88, 0x1f, 0x96,
    0x92, 0x94, 0x35, 0xe2, 0xb3, 0x85, 0x0a, 0x37,
    0x01, 0xae, 0xd0, 0x26, 0xe8, 0x0a, 0x32, 0x91
    ]),
    cryptoMath.createArray([
    0x1f, 0x45, 0xf4, 0x80, 0xa0, 0xec, 0x76, 0x07,
    0x51, 0x66, 0x79, 0xc2, 0xbb, 0x9f, 0x67, 0x7a,
    0x89, 0xd4, 0x50, 0xec, 0x46, 0x9a, 0xc9, 0x30,
    0xa1, 0x0d, 0x21, 0x3c, 0x1e, 0xb2, 0xa9, 0xcf
    ]),
    cryptoMath.createArray([
    0x5d, 0xd7, 0x1c, 0x92, 0xd3, 0x11, 0xec, 0x15,
    0xd5, 0xe2, 0xe6, 0xd3, 0xb8, 0xd5, 0x13, 0x36,
    0x41, 0x5a, 0x60, 0x8e, 0x14, 0x04, 0x8c, 0x86,
    0xce, 0xec, 0x76, 0x4e, 0x6d, 0xe6, 0xdf, 0x49
    ]),
    cryptoMath.createArray([
    0x41, 0x60, 0xfb, 0xdd, 0xaf, 0x29, 0x86, 0xf3,
    0xa1, 0x1e, 0x29, 0xb5, 0x89, 0xb9, 0xd9, 0x1d,
    0x8b, 0x15, 0xc5, 0xf8, 0xbb, 0xf0, 0x2f, 0x7f,
    0x17, 0x5f, 0x6e, 0xf8, 0xe7, 0xc2, 0xb1, 0xa4
    ]),
    cryptoMath.createArray([
    0x6a, 0x8f, 0x2e, 0xa6, 0xb2, 0x30, 0x1e, 0x3a,
    0xef, 0xbd, 0x82, 0x46, 0xf6, 0xeb, 0x97, 0xea,
    0x0c, 0xe1, 0x15, 0x5c, 0xe0, 0xb7, 0x2c, 0x47,
    0x1d, 0x01, 0xb0, 0xd0, 0xb8, 0x8d, 0xa2, 0xca
    ]),
    cryptoMath.createArray([
    0x18, 0x71, 0xc1, 0x5a, 0xa6, 0xf8, 0xcc, 0x3a,
    0xda, 0x2d, 0x4b, 0xf6, 0xbb, 0x2b, 0xc6, 0x29,
    0x6c, 0xa6, 0x58, 0x7c, 0x12, 0x2d, 0xf3, 0xb4,
    0x7a, 0x9f, 0xaa, 0x30, 0x25, 0x86, 0x3a, 0x8c
    ]),
    cryptoMath.createArray([
    0x13, 0xd6, 0xc8, 0xd6, 0xae, 0x02, 0x73, 0xa1,
    0x89, 0x01, 0x29, 0x77, 0x9f, 0xce, 0x34, 0xf0,
    0xca, 0xf6, 0xf3, 0x53, 0xbf, 0xde, 0x9e, 0xe3,
    0x37, 0x27, 0x86, 0x78, 0xc9, 0xb6, 0xe7, 0x58
    ]),
    cryptoMath.createArray([
    0x75, 0x63, 0x11, 0xf8, 0x96, 0xc5, 0x03, 0xec,
    0xdb, 0x2f, 0x60, 0x8a, 0x1c, 0xcb, 0xfa, 0x37,
    0x8a, 0x95, 0xeb, 0x45, 0x78, 0xe6, 0x5f, 0x19,
    0x0f, 0x1a, 0x8b, 0x54, 0x4d, 0x20, 0xb0, 0x82
    ]),
    cryptoMath.createArray([
    0x14, 0x2d, 0x15, 0x0c, 0x85, 0x5b, 0xa9, 0xaa,
    0x7d, 0xcc, 0x71, 0x82, 0x1a, 0x53, 0x8e, 0xdb,
    0x54, 0x48, 0x36, 0xdf, 0x80, 0x50, 0x91, 0x26,
    0x79, 0xcc, 0xd7, 0x23, 0x3f, 0xbb, 0xa6, 0x36
    ])
    ];

    // P256 curve
    this.p256 = cryptoECC.createP256();

    // recommended parameters

    this.Gq = new UProve.ECGroup(this.p256);
    this.getGq = function () {
        return this.Gq;
    }

    this.Zq = new cryptoMath.IntegerGroup(cryptoMath.createArray(cryptoMath.digitsToBytes(this.p256.order)));
    this.getZq = function () {
        return this.Zq;
    }

    this.getGenerator = function () {
        return this.p256.generator;
    }

    // update the hash with the group values
    // hash   - UProve.Hash          - the hash function to update
    this.updateHash = function (hash) {
        // H(p,a,b,g,q,1)
        hash.updateBytes(cryptoMath.digitsToBytes(this.p256.p));
        hash.updateBytes(cryptoMath.digitsToBytes(this.p256.a));
        hash.updateBytes(cryptoMath.digitsToBytes(this.p256.b));
        hash.updatePoint(this.p256.generator);
        hash.updateBytes(cryptoMath.digitsToBytes(this.p256.order));
        hash.updateBytes([0x01]);
    }

    // returns an array of n + 2 pre-generated generators: 1, g1, ..., gn, gt.
    // The first element (g0) is set to 1 and must be replaced by caller with
    // an Issuer-specific value.
    this.getPreGenGenerators = function (n) {
        var gen = new Array(n + 2);
        gen[0] = this.Gq.getIdentityElement(); // to be replaced by caller
        for (var i = 1; i <= n ; i++) { // g1, ..., gn
            gen[i] = this.Gq.createPoint(this.generatorsX[i - 1], this.generatorsY[i - 1]);
        }
        gen[n + 1] = this.Gq.createPoint(this.generatorsX[this.t - 1], this.generatorsY[this.t - 1]);
        return gen;
    }

    this.getX = function (input, counter) {
        var numIterations = 1; // for P-256/SHA-256, ratio is 1
        var H = new UProve.Hash();
        var zeroByte = 0x30; // ascii value for 0
        H.updateRawBytes(input);
        // Hash([index, count, iteration]). index always 0 for generation scope, iteration always 0 for P-256/SHA-256
        H.updateRawBytes([zeroByte, zeroByte + counter, zeroByte]); 
        var digest = H.digest();
        return this.Gp.createElementFromBytes(digest);
    }

    this.Gp = new cryptoMath.IntegerGroup(cryptoMath.digitsToBytes(this.p256.p), true);
    this.GpZero = this.Gp.createElementFromInteger(0);
    this.generateScopeElement = function (s) {
        if (!s) {
            throw "invalid scope";
        }
        var sqrtSolver = new cryptoMath.ModularSquareRootSolver(this.p256.p /*, rand*/); // no need to set rand when using NIST curves
        var x = null;
        var y = null;
        var count = 0;
        var index = 0;
        while (y === null) {
            var x = this.getX(s, count);
            // z = x^3 + ax + b mod p
            var z = this.Gp.getIdentityElement();
            this.Gp.modmul(x, x, z); // z = x^2 mod p
            var a = this.Gp.createElementFromDigits(this.p256.a);
            this.Gp.add(z, a, z); // z = x^2 + a mod p
            this.Gp.modmul(z, x, z); // z = x^3 + ax mod p
            var b = this.Gp.createElementFromDigits(this.p256.b);
            this.Gp.add(z, b, z); // z = x^3 + ax + b mod p
            if (cryptoMath.compareDigits(z.m_digits, this.GpZero.m_digits)) {
                y = z;
            }
            else {
                // y = Sqrt(z)
                // i.e. y such that y^2 === z mod p
                // or null if no such element exists
                y = sqrtSolver.squareRoot(z.m_digits);
            }
            count++;
        }
        // take the smallest sqrt of y
        var finalY = cryptoMath.intToDigits(0, this.Gp.m_digitWidth);
        cryptoMath.subtract(this.p256.p, y, finalY);
        if (cryptoMath.compareDigits(y, finalY) < 0) {
            finalY = y;
        }

        counter = count - 1;
        return this.Gq.createPoint(x.toByteArrayUnsigned(), cryptoMath.digitsToBytes(finalY));
    }

}

UProve.ECP256.OID = "1.3.6.1.4.1.311.75.1.2.1";
