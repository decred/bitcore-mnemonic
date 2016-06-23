'use strict';

var bitcore = require('bitcore-lib');
var BN = bitcore.crypto.BN;
var unorm = require('unorm');
var _ = bitcore.deps._;

var pbkdf2 = require('./pbkdf2');
var errors = require('./errors');

var Hash = bitcore.crypto.Hash;
var Random = bitcore.crypto.Random;

var $ = bitcore.util.preconditions;


/**
 * This is an immutable class that represents a BIP39 Mnemonic code.
 * See BIP39 specification for more info: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * A Mnemonic code is a a group of easy to remember words used for the generation
 * of deterministic wallets. A Mnemonic can be used to generate a seed using
 * an optional passphrase, for later generate a HDPrivateKey.
 *
 * @example
 * // generate a random mnemonic
 * var mnemonic = new Mnemonic();
 * var phrase = mnemonic.phrase;
 *
 * // use a different language
 * var mnemonic = new Mnemonic(Mnemonic.Words.SPANISH);
 * var xprivkey = mnemonic.toHDPrivateKey();
 *
 * @param {*=} data - a seed, phrase, or entropy to initialize (can be skipped)
 * @param {Array=} wordlist - the wordlist to generate mnemonics from
 * @returns {Mnemonic} A new instance of Mnemonic
 * @constructor
 */
var Mnemonic = function(data, wordlist) {
  if (!(this instanceof Mnemonic)) {
    return new Mnemonic(data, wordlist);
  }

  if (_.isArray(data)) {
    wordlist = data;
    data = null;
  }


  // handle data overloading
  var ent, phrase, seed;
  if (Buffer.isBuffer(data)) {
    seed = data;
  } else if (_.isString(data)) {
    phrase = unorm.nfkd(data);
  } else if (_.isNumber(data)) {
    ent = data;
  } else if (data) {
    throw new bitcore.errors.InvalidArgument('data', 'Must be a Buffer, a string or an integer');
  }
  ent = ent || 256;


  // check and detect wordlist
  wordlist = wordlist || Mnemonic._getDictionary(phrase);
  if (phrase && !wordlist) {
    throw new errors.UnknownWordlist(phrase);
  }
  wordlist = wordlist || Mnemonic.Words.ENGLISH;

  if (seed) {
    phrase = Mnemonic._entropy2mnemonic(seed, wordlist);
  }


  // validate phrase and ent
  // 
  if (phrase && !Mnemonic.isValid(phrase, wordlist)) {
    throw new errors.InvalidMnemonic(phrase);
  }
  if (ent % 32 !== 0 || ent < 128) {
    throw new bitcore.errors.InvalidArgument('ENT', 'Values must be ENT > 128 and ENT % 32 == 0');
  }

  phrase = phrase || Mnemonic._mnemonic(ent, wordlist);

  Object.defineProperty(this, 'wordlist', {
    configurable: false,
    value: wordlist
  });

  Object.defineProperty(this, 'phrase', {
    configurable: false,
    value: phrase
  });
};

Mnemonic.Words = require('./words');

/**
 * Will return a boolean if the mnemonic is valid
 *
 * @example
 *
 * var valid = Mnemonic.isValid('lab rescue lunch elbow recall phrase perfect donkey biology guess moment husband');
 * // true
 *
 * @param {String} mnemonic - The mnemonic string
 * @param {String} [wordlist] - The wordlist used
 * @returns {boolean}
 */
Mnemonic.isValid = function(mnemonic, wordlist) {
  mnemonic = unorm.nfkd(mnemonic);
  wordlist = wordlist || Mnemonic._getDictionary(mnemonic);

  if (!wordlist) {
    return false;
  }
  var words = mnemonic.split(' ');
  var bin = '';
  var buf = new Buffer(words.length-1);
  for (var i = 0; i < words.length-1; i++) {
    var ind = wordlist.indexOf(words[i]);
    if (ind < 0) return false;
    ind = ind/2; 
    buf.writeUInt8(Math.floor(ind), i);
  }
  var actual = wordlist.indexOf(words[i]);
  var expected_hash_bits = Mnemonic._entropyChecksum(buf);
  return expected_hash_bits === actual;
};

/**
 * Internal function to check if a mnemonic belongs to a wordlist.
 *
 * @param {String} mnemonic - The mnemonic string
 * @param {String} wordlist - The wordlist
 * @returns {boolean}
 */
Mnemonic._belongsToWordlist = function(mnemonic, wordlist) {
  var words = unorm.nfkd(mnemonic).split(' ');
  for (var i = 0; i < words.length; i++) {
    var ind = wordlist.indexOf(words[i]);
    if (ind < 0) return false;
  }
  return true;
};

/**
 * Internal function to detect the wordlist used to generate the mnemonic.
 *
 * @param {String} mnemonic - The mnemonic string
 * @returns {Array} the wordlist or null
 */
Mnemonic._getDictionary = function(mnemonic) {
  if (!mnemonic) return null;

  var dicts = Object.keys(Mnemonic.Words);
  for (var i = 0; i < dicts.length; i++) {
    var key = dicts[i];
    if (Mnemonic._belongsToWordlist(mnemonic, Mnemonic.Words[key])) {
      return Mnemonic.Words[key];
    }
  }
  return null;
};

/**
 * Will generate a seed based on the mnemonic and optional passphrase.
 *
 * @param {String} [passphrase]
 * @returns {Buffer}
 */
Mnemonic.prototype.toSeed = function(passphrase) {
  passphrase = passphrase || '';
  return pbkdf2(unorm.nfkd(this.phrase), unorm.nfkd('mnemonic' + passphrase), 2048, 64);
};

/**
 * Will generate a Mnemonic object based on a seed.
 *
 * @param {Buffer} [seed]
 * @param {string} [wordlist]
 * @returns {Mnemonic}
 */
Mnemonic.fromSeed = function(seed, wordlist) {
  $.checkArgument(Buffer.isBuffer(seed), 'seed must be a Buffer.');
  $.checkArgument(_.isArray(wordlist) || _.isString(wordlist), 'wordlist must be a string or an array.');
  return new Mnemonic(seed, wordlist);
};

/**
 *
 * Generates a HD Private Key from a Mnemonic.
 * Optionally receive a passphrase and bitcoin network.
 *
 * @param {String=} [passphrase]
 * @param {Network|String|number=} [network] - The network: 'livenet' or 'testnet'
 * @returns {HDPrivateKey}
 */
Mnemonic.prototype.toHDPrivateKey = function(passphrase, network) {
  var words = this.phrase.split(' ');
  var buf = new Buffer(words.length-1);
  for (var i = 0; i < words.length-1; i++) {
    var ind = this.wordlist.indexOf(words[i]);
    if (ind < 0) return false;
    ind = ind/2; 
    buf.writeUInt8(Math.floor(ind), i);
  }
  return bitcore.HDPrivateKey.fromSeed(buf, network);
};

/**
 * Will return a the string representation of the mnemonic
 *
 * @returns {String} Mnemonic
 */
Mnemonic.prototype.toString = function() {
  return this.phrase;
};

/**
 * Will return a string formatted for the console
 *
 * @returns {String} Mnemonic
 */
Mnemonic.prototype.inspect = function() {
  return '<Mnemonic: ' + this.toString() + ' >';
};

/**
 * Internal function to generate a random mnemonic
 *
 * @param {Number} ENT - Entropy size, defaults to 128
 * @param {Array} wordlist - Array of words to generate the mnemonic
 * @returns {String} Mnemonic string
 */
Mnemonic._mnemonic = function(ENT, wordlist) {
  var buf = Random.getRandomBuffer(ENT / 8);
  return Mnemonic._entropy2mnemonic(buf, wordlist);
};

/**
 * Internal function to generate mnemonic based on entropy
 *
 * @param {Number} entropy - Entropy buffer
 * @param {Array} wordlist - Array of words to generate the mnemonic
 * @returns {String} Mnemonic string
 */
Mnemonic._entropy2mnemonic = function(entropy, wordlist) {
  var mnemonic = [];
  for (var i = 0; i < entropy.length; i++) {
    var wi = entropy[i] * 2;
    if (i % 2 !== 0) {
      wi++;
    }
    mnemonic.push(wordlist[wi]);
  }

  mnemonic.push(wordlist[Mnemonic._entropyChecksum(entropy)]);
  var ret;
  ret = mnemonic.join(' ');
  console.log(ret);
  return ret;
};

/**
 * Internal function to create checksum of entropy
 *
 * @param entropy
 * @returns {string} Checksum of entropy length / 32
 * @private
 */
Mnemonic._entropyChecksum = function(entropy, wordlist) {
  var hash = Hash.sha256sha256(entropy);

  var checksum = hash[0] * 2;
  
  if (entropy.length % 2 !== 0) {
	  checksum++;
  }

  return checksum;
};

module.exports = Mnemonic;
