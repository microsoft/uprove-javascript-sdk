// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

"use strict";

var cryptoUProveTest = cryptoUProveTest || {};

var performanceTimer = (typeof performance === "undefined" ? Date : performance); // performance not supported on Safari

cryptoUProveTest.testVectorDirectory = "TestVectors";

// Read a byte array in comma delimited format into a Uint8Array
cryptoUProveTest.readNumberList = function (string) {
    var elements = string.split(',');
    var array = new Array();

    for (var i = 0; i < elements.length; i++) {
        var number = elements[i].valueOf();
        array[i] = number;
    }

    return array;
};

// Read a hex string into a Uint8Array
cryptoUProveTest.readHexString = function (hexString) {
    var array = new Array();
    var index = 0;
    if ((hexString.length % 2) != 0) {
        // prepend 0
        hexString = "0" + hexString;
    }

    for (var i = 0; i < hexString.length; i += 2) {
        array[index++] = parseInt("0x" + hexString.substr(i, 2), 16);
    }

    var result = new Uint8Array(array);
    return result;
}

cryptoUProveTest.readFileDataInDictionary = function (filename) {
    var request = new XMLHttpRequest();
    request.open("GET", cryptoUProveTest.testVectorDirectory + "/" + filename, false)
    request.send(null);
    var fileData = request.responseText;
    var lines = fileData.split('\r\n');
    var dictionary = {};
    for (var j = 1; j < lines.length; j++) { // skip the file header in line 0
        var lineData = lines[j].split(" = ");
        dictionary[lineData[0]] = lineData[1];
    }
    return dictionary;
}

cryptoUProveTest.readTestVectors = function (filename) {
    var vectorsData = cryptoUProveTest.readFileData(filename);
    // put each test vector variable in a dictionary
    var lines = vectorsData.split('\r\n');
    var vectors = {};
    for (var j = 1; j < lines.length; j++) { // skip the header
        var lineData = lines[j].split(" = ");
        vectors[lineData[0]] = lineData[1];
    }
    return vectors;
}

cryptoUProveTest.readRecommendedParams = function (filename) {
    var paramsData = cryptoUProveTest.readFileData(filename);

    // put each test vector variable in a dictionary
    var lines = paramsData.split('\r\n');
    var vectors = {};
    for (var j = 1; j < lines.length; j++) { // skip the header
        var lineData = lines[j].split(" = ");
        vectors[lineData[0]] = lineData[1];
    }
    return vectors;
}

// Execute the U-Prove hashing tests
cryptoUProveTest.executeHashTests = function (outputDiv) {
    // read recommended parameters
    var vectors = cryptoUProveTest.readFileDataInDictionary("testvectors_hashing.txt");
    cryptoUProveTest.hashUnitTest(vectors, outputDiv);
};

// U-Prove hash unit test
cryptoUProveTest.hashUnitTest = function (vectors, outputDiv) {

    // clear output
    outputDiv.innerHTML = "";

    var t1 = performanceTimer.now();
   
    // hash_byte (0x01) = 4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a
    var testCase = "hash_byte (0x01)";
    var H = new UProve.Hash();
    H.updateByte(0x01);
    if (!cryptoMath.sequenceEqual(H.digest(), cryptoUProveTest.readHexString(vectors[testCase]))) {
        throw "invalid digest for input " + testCase;
    }

    // hash_octectstring (0x0102030405) = 16df7d2d0c3882334fe0457d298a7b2413e1e5b7a880f0b5ec79eeeae7f58dd8
    testCase = "hash_octectstring (0x0102030405)";
    var bytesx0102030405 = cryptoUProveTest.readHexString("0102030405");
    H = new UProve.Hash();
    H.updateBytes(bytesx0102030405);
    if (!cryptoMath.sequenceEqual(H.digest(), cryptoUProveTest.readHexString(vectors[testCase]))) {
        throw "invalid digest for input " + testCase;
    }
    
    // hash_null (null) = df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119
    testCase = "hash_null (null)";
    H = new UProve.Hash();
    H.updateNull();
    if (!cryptoMath.sequenceEqual(H.digest(), cryptoUProveTest.readHexString(vectors[testCase]))) {
        throw "invalid digest for input " + testCase;
    }

    // hash_list [0x01, 0x0102030405, null] = dfd6a31f867566ffeb6c657af1dafb564c3de74485058426633d4b6c8bad6732
    testCase = "hash_list [0x01, 0x0102030405, null]";
    H = new UProve.Hash();
    H.updateUint32(3);
    H.updateByte(0x01);
    H.updateBytes(bytesx0102030405);
    H.updateNull();
    if (!cryptoMath.sequenceEqual(H.digest(), cryptoUProveTest.readHexString(vectors[testCase]))) {
        throw "invalid digest for input " + testCase;
    }

    // hash_group (1.3.6.1.4.1.311.75.1.1.1) = 7b36c8a3cf1552077e1cacb365888d25c9dc54f3faed7aff9b11859aa8e4ba06
    testCase = "hash_group (1.3.6.1.4.1.311.75.1.1.1)";
    H = new UProve.Hash();
    var Gq = new UProve.L2048N256();
    Gq.updateHash(H);
    if (!cryptoMath.sequenceEqual(H.digest(), cryptoUProveTest.readHexString(vectors[testCase]))) {
        throw "invalid digest for input " + testCase;
    }

    // hash_group (1.3.6.1.4.1.311.75.1.2.1) = 02bb879cb2f89c19579105be662247db15ab45875cfc63a58745361d193ba248
    testCase = "hash_group (1.3.6.1.4.1.311.75.1.2.1)";
    H = new UProve.Hash();
    var Gq = new UProve.ECP256();
    Gq.updateHash(H);
    if (!cryptoMath.sequenceEqual(H.digest(), cryptoUProveTest.readHexString(vectors[testCase]))) {
        throw "invalid digest for input " + testCase;
    }

    var time = performanceTimer.now() - t1;
    outputDiv.innerHTML += ("Hash tests: " + time.toFixed(10) + " ms <br/>");
}

// Execute the U-Prove protocol tests
cryptoUProveTest.executeUProveTests = function (outputDiv, lite, ecc) {

    cryptoUProveTest.testLiteMode = lite;
    cryptoUProveTest.testECC = ecc;
    cryptoUProveTest.testVectorFile = "testvectors_" + (cryptoUProveTest.testECC ? "EC" : "SG") + "_D2" + (cryptoUProveTest.testLiteMode ? "_lite" : "") + "_doc.txt";
    cryptoUProveTest.recommendedParamsFile = "UProveRecommendedParams" + (cryptoUProveTest.testECC ? "P256" : "L2048N256") + ".txt";
    cryptoUProveTest.params = cryptoUProveTest.readFileDataInDictionary(cryptoUProveTest.recommendedParamsFile);

    // read recommended parameters
    var vectors = cryptoUProveTest.readFileDataInDictionary(cryptoUProveTest.testVectorFile);
    cryptoUProveTest.proverUnitTest(cryptoUProveTest.params, vectors, outputDiv);
};

// U-Prove Prover unit test
cryptoUProveTest.proverUnitTest = function (params, vectors, outputDiv) {

    var numAttribs = 5;
    var t = numAttribs + 1;

    function readVectorElement(group, vectors, label, isEcGq) {
        if (isEcGq === 'undefined') {
            isEcGq = false;
        }
        if (isEcGq) {
            return group.createPoint(cryptoUProveTest.readHexString(vectors[label + ".x"]), cryptoUProveTest.readHexString(vectors[label + ".y"]));
        } else {
            return group.createElementFromBytes(cryptoUProveTest.readHexString(vectors[label]));
        }
    }

    function verifyComputation(group, v, vName, isEcGq) {
        if (isEcGq === "undefined") {
            isEcGq = false;
        }

        if (!v.equals(readVectorElement(group, vectors, vName, isEcGq))) {
            throw "invalid " + vName;
        }
    }

    function verifyArrayComputation(v, vName) {
        if (!cryptoMath.sequenceEqual(v, cryptoUProveTest.readHexString(vectors[vName]))) {
            throw "invalid " + vName;
        }
    }

    ////////////////////////////////////////////
    // Issuance protocol
    ////////////////////////////////////////////

    var useECC = (params["OID"] === "1.3.6.1.4.1.311.75.1.2.1");

    // clear output
    outputDiv.innerHTML = "";

    // instantiate the group construction
    var Group = null;
    if (useECC) {
        Group = new UProve.ECP256();
    } else {
        Group = new UProve.L2048N256();
    }
    var Gq = Group.getGq();
    var Zq = Group.getZq();

    var uidp = cryptoUProveTest.readHexString(vectors["UIDp"]);
    var g = Group.getPreGenGenerators(numAttribs);
    g[0] = readVectorElement(Gq, vectors, "g0", useECC);
    var e = new Array(numAttribs);
    for (var i = 1; i <= numAttribs; i++) {
        if (!g[i].equals(readVectorElement(Gq, params, "g" + i, useECC))) {
            throw "invalid g" + i;
        }
        e[i - 1] = cryptoUProveTest.readHexString(vectors["e" + i])[0]; // we only keep the first byte of the returned byte array
    }
    var s = cryptoUProveTest.readHexString(vectors["S"]);
    var ip = new UProve.IssuerParams(uidp, Group, g, e, s);
    if (!ip.isValid()) {
        throw "invalid ip";
    }
    // check the ip digest against test vector value
    verifyArrayComputation(ip.computeDigest(), "P");
    
    // this rng will return the test vector values in order in which they are expected
    var testVectorsRNG = {
        values:
            cryptoUProveTest.testLiteMode ?
            [ // lite version
            readVectorElement(Zq, vectors, "alpha"),
            readVectorElement(Zq, vectors, "beta1"),
            readVectorElement(Zq, vectors, "beta2"),
            readVectorElement(Zq, vectors, "w0"),
            readVectorElement(Zq, vectors, "w1"),
            readVectorElement(Zq, vectors, "w3"),
            readVectorElement(Zq, vectors, "w4"),
            ]
            : 
            [ // full version
            readVectorElement(Zq, vectors, "alpha"),
            readVectorElement(Zq, vectors, "beta1"),
            readVectorElement(Zq, vectors, "beta2"),
            readVectorElement(Zq, vectors, "w0"),
            readVectorElement(Zq, vectors, "w1"),
            readVectorElement(Zq, vectors, "tildeO1"),
            readVectorElement(Zq, vectors, "tildeW1"),
            readVectorElement(Zq, vectors, "w3"),
            readVectorElement(Zq, vectors, "w4"),
            readVectorElement(Zq, vectors, "tildeO4"),
            readVectorElement(Zq, vectors, "tildeW4"),
            readVectorElement(Zq, vectors, "ie_r"),
            readVectorElement(Zq, vectors, "ie_xbPrime"),
            readVectorElement(Zq, vectors, "ie_obPrime"),
            readVectorElement(Zq, vectors, "ie_rPrime")
            ],
        index : -1,
        getRandomZqElement: function () { this.index++; return this.values[this.index] }
    };

    var t1 = performanceTimer.now();
    var prover = new UProve.Prover(testVectorsRNG, ip);
    var time = performanceTimer.now() - t1;
    outputDiv.innerHTML += ("Setup (" + (useECC ? "ECC" : "Subgroup") + "): " + time.toFixed(10) + " ms <br/>");
    var totalTime = time;

    //
    // Second message
    //

    var attributes = new Array(numAttribs);
    for (var i = 1; i <= numAttribs; i++) {
        attributes[i - 1] = cryptoUProveTest.readHexString(vectors["A" + i]);
    }
    var ti = cryptoUProveTest.readHexString(vectors["TI"]);
    var pi = cryptoUProveTest.readHexString(vectors["PI"]);
    // verify the computation of the x_i
    var x = UProve.computeXArray(Zq, attributes, e);
    for (var i = 1; i <= numAttribs; i++) {
        verifyComputation(Zq, x[i - 1], "x" + i);
    }
    verifyComputation(Zq, UProve.computeXt(Zq, ip, ti), "xt");

    var firstMsg = {
        "sz": readVectorElement(Gq, vectors, "sigmaZ", useECC),
        "sa": [readVectorElement(Gq, vectors, "sigmaA", useECC)],
        "sb": [readVectorElement(Gq, vectors, "sigmaB", useECC)]
    };
    var gamma = readVectorElement(Gq, vectors, "gamma", useECC).toByteArrayUnsigned();
    t1 = performanceTimer.now();
    var secondMsg = prover.generateSecondMessage(1, attributes, ti, pi, gamma, firstMsg);
    time = performanceTimer.now() - t1;
    outputDiv.innerHTML += ("Second message (with pre-computed gamma): " + time.toFixed(10) + " ms <br/>");
    totalTime += time;
    verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(secondMsg.sc[0])), "sigmaC");

    //
    // Generate token
    //

    var thirdMsg = {
        "sr": [readVectorElement(Zq, vectors, "sigmaR")]
    };
    t1 = performanceTimer.now();
    var keyAndToken = prover.generateTokens(thirdMsg);
    time = performanceTimer.now() - t1;
    totalTime += time;
    outputDiv.innerHTML += ("Generate token: " + time.toFixed(10) + " ms <br/>");
    outputDiv.innerHTML += ("<b>Total issuance: " + totalTime.toFixed(10) + " ms</b> <br/>");
    var token = keyAndToken[0].token;
    verifyComputation(Gq, Gq.createElementFromBytes(UProve.base64ToUint8Array(token.h)), "h", useECC);
    verifyComputation(Gq, Gq.createElementFromBytes(UProve.base64ToUint8Array(token.szp)), "sigmaZPrime", useECC);
    verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(token.scp)), "sigmaCPrime");
    verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(token.srp)), "sigmaRPrime");

    //
    // Generate proof
    //

    var disclosed = cryptoUProveTest.readNumberList(vectors["D"]);
    var committed = cryptoUProveTest.testLiteMode ? null : cryptoUProveTest.readNumberList(vectors["C"]);
    var undisclosed = cryptoUProveTest.readNumberList(vectors["U"]);
    var message = cryptoUProveTest.readHexString(vectors["m"]);
    var messageD = cryptoUProveTest.readHexString(vectors["md"]);
    var scopeData = cryptoUProveTest.testLiteMode ? null : {
        p: vectors["p"],
        gs: readVectorElement(Gq, vectors, "gs", useECC).toByteArrayUnsigned()
    }
    var commitmentPrivateValues = {}
    t1 = performanceTimer.now();
    keyAndToken[0].token.uidp = UProve.uint8ArrayToBase64(ip.uidp);
    keyAndToken[0].token.ti = UProve.uint8ArrayToBase64(ti);
    keyAndToken[0].token.pi = UProve.uint8ArrayToBase64(pi);
    var ukat = ip.ParseKeyAndToken(keyAndToken[0]);
    var proof = prover.generateProof(ukat, disclosed, committed, message, messageD, attributes, scopeData, commitmentPrivateValues);
    time = performanceTimer.now() - t1;
    var dSize = disclosed.length;
    outputDiv.innerHTML += ("<b>Total presentation: " + time.toFixed(10) + " ms</b> <br/>");
    outputDiv.innerHTML += ("( 1 token with " + numAttribs + " attributes, disclosing " + dSize + (cryptoUProveTest.testLiteMode ? "" : ", with a scope-exclusive pseudonym and commitment") + ")<br/>");

    verifyArrayComputation(UProve.base64ToUint8Array(proof.a), "a");
    if (!cryptoUProveTest.testLiteMode) { verifyArrayComputation(UProve.base64ToUint8Array(proof.ap), "ap"); }
    if (!cryptoUProveTest.testLiteMode) { verifyComputation(Gq, Gq.createElementFromBytes(UProve.base64ToUint8Array(proof.Ps)), "Ps", useECC); }
    verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(proof.r[0])), "r0");
    for (var i = 1; i <= undisclosed.length; i++) {
        verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(proof.r[i])), "r" + undisclosed[i - 1]);
    }
    if (!cryptoUProveTest.testLiteMode) {
        for (var i = 0; i < committed.length; i++) {
            verifyComputation(Gq, Gq.createElementFromBytes(UProve.base64ToUint8Array(proof.tc[i])), "tildeC" + committed[i], useECC);
            verifyArrayComputation(UProve.base64ToUint8Array(proof.ta[i]), "tildeA" + committed[i]);
            verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(proof.tr[i])), "tildeR" + committed[i]);
        }

        // generate ID escrow proof
        var ie_escrowParams = {
            "uidp": cryptoUProveTest.readHexString(vectors["UIDp"]),
            "ge": Group.getGenerator().toByteArrayUnsigned()
        }
        var ie_escrowPublicKey = {
            "H": readVectorElement(Gq, vectors, "ie_H", useECC)
        }
        var ie_x = readVectorElement(Zq, vectors, "ie_x");
        var ie_additionalInfo = cryptoUProveTest.readHexString(vectors["ie_additionalInfo"]);
        var ie_idAttribIndex = vectors["ie_b"];
        t1 = performance.now();
        var ie_proof = prover.verifiableEncrypt(ie_escrowParams, ie_escrowPublicKey, ukat.token, ie_additionalInfo, proof, commitmentPrivateValues.tildeO[0], UProve.base64ToUint8Array(proof.tc[0]), ie_idAttribIndex, attributes[ie_idAttribIndex - 1]);
        time = performance.now() - t1;
        outputDiv.innerHTML += ("Verifiable encryption: " + time.toFixed(10) + " ms <br/>");
        verifyComputation(Gq, Gq.createElementFromBytes(UProve.base64ToUint8Array(ie_proof.E1)), "ie_E1", useECC);
        verifyComputation(Gq, Gq.createElementFromBytes(UProve.base64ToUint8Array(ie_proof.E2)), "ie_E2", useECC);
        verifyArrayComputation(UProve.base64ToUint8Array(ie_proof.info), "ie_additionalInfo");
        verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(ie_proof.ieproof.c)), "ie_c");
        verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(ie_proof.ieproof.rXb)), "ie_rxb");
        verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(ie_proof.ieproof.rR)), "ie_rr");
        verifyComputation(Zq, Zq.createModElementFromBytes(UProve.base64ToUint8Array(ie_proof.ieproof.rOb)), "ie_rob");
    }
};

// Execute the modexp speed tests
cryptoUProveTest.executeModexpSpeedTests = function (exponent, outputDiv, ecc) {
    cryptoUProveTest.modexpSpeedTest(exponent, outputDiv, ecc);
};

