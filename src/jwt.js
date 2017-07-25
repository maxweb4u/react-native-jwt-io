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
 * @param {String} pass default none
 * @return {String} token
 * @api public
 */
jwt.encode = function jwt_encode( payload, key, algorithm, pass ) {
    algorithm = typeof algorithm !== 'undefined' ? algorithm : 'HS256';
    pass = typeof pass !== 'undefined' ? pass : '';
    return rs.jws.JWS.sign(algorithm, JSON.stringify({ alg: algorithm, typ: 'JWT' }), JSON.stringify(payload), key, pass);
}

/**
 * Parse JWT token
 *
 * @param {String} token
 * @return {Object} payload
 * @api public
 */
jwt.decode = function jwt_parseToken( token ) {
    return rs.jws.JWS.parseJWS(token);
}

/**
 * Verify JWT token by specified pass
 *
 * @param {String} token
 * @param {String} pass
 * @return {Boolean} true if the signature is valid otherwise false
 * @api public
 */
jwt.verify = function jwt_verifyToken( token, pass ) {
    return rs.jws.JWS.verify(token, pass);
}
