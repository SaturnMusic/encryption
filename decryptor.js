const decryptor = require('bindings')('decryptor.node');

exports.getKey = (trackId) => {
    return decryptor.getKey(trackId);
}

exports.decryptFile = (key, inputFilename, outputFilename) => {
    decryptor.decryptFile(key, inputFilename, outputFilename);
    return;
}

exports.decryptBuffer = (key, data) => {
    return decryptor.decryptBuffer(key, data);
}