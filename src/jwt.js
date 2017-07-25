/**
 * module dependencies
 */

var rs = require('jsrsasign');

/**
 * expose object
 */
var jwt = module.exports;

/**
 * Encode JWT
 *
 * @param {Object} payload
 * @param {String} key
 * @param {String} algorithm default 'HS256'
 * @return {String} token
 * @api public
 */
jwt.encode = function jwt_encode( payload, key, algorithm ) {
    algorithm = typeof algorithm !== 'undefined' ? algorithm : 'HS256';
    return rs.jws.JWS.sign(algorithm, JSON.stringify({ alg: algorithm, typ: 'JWT' }), JSON.stringify(payload), key);
}

/**
 * Parse JWT token
 *
 * @param {String} token
 * @param {String} key
 * @return {Object} payload
 * @api public
 */
jwt.decode = function jwt_parseToken( token, key ) {
    var isValid = rs.jws.JWS.verify(token, key);
    if (isValid){
        return rs.jws.JWS.parseJWS;
    } else {
        return null;
    }

}

/**
 * Verify JWT token by specified pass
 *
 * @param {String} token
 * @param {String} pass
 * @return {Boolean} true if the signature is valid otherwise false
 * @api public
 */
jwt.verify = function jwt_verifyToken( token, key ) {
    return rs.jws.JWS.verify(token, key);
}
