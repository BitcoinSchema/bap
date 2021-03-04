"use strict";var _interopRequireDefault=require("@babel/runtime/helpers/interopRequireDefault");Object.defineProperty(exports,"__esModule",{value:!0}),exports.BAP=void 0;var _regenerator=_interopRequireDefault(require("@babel/runtime/regenerator")),_asyncToGenerator2=_interopRequireDefault(require("@babel/runtime/helpers/asyncToGenerator")),_classCallCheck2=_interopRequireDefault(require("@babel/runtime/helpers/classCallCheck")),_createClass2=_interopRequireDefault(require("@babel/runtime/helpers/createClass")),_classPrivateFieldLooseBase2=_interopRequireDefault(require("@babel/runtime/helpers/classPrivateFieldLooseBase")),_classPrivateFieldLooseKey2=_interopRequireDefault(require("@babel/runtime/helpers/classPrivateFieldLooseKey")),_bsv=_interopRequireDefault(require("bsv")),_message=_interopRequireDefault(require("bsv/message")),_ecies=_interopRequireDefault(require("bsv/ecies"));require("node-fetch");var _HDPrivateKey,_ids,_BAP_SERVER,_BAP_TOKEN,_lastIdPath,_temp,_utils=require("./utils"),_id=require("./id"),_constants=require("./constants"),BAP=(_temp=(_HDPrivateKey=(0,_classPrivateFieldLooseKey2["default"])("HDPrivateKey"),_ids=(0,_classPrivateFieldLooseKey2["default"])("ids"),_BAP_SERVER=(0,_classPrivateFieldLooseKey2["default"])("BAP_SERVER"),_BAP_TOKEN=(0,_classPrivateFieldLooseKey2["default"])("BAP_TOKEN"),_lastIdPath=(0,_classPrivateFieldLooseKey2["default"])("lastIdPath"),function(){function a(b){var c=!!(1<arguments.length&&void 0!==arguments[1])&&arguments[1];if((0,_classCallCheck2["default"])(this,a),Object.defineProperty(this,_HDPrivateKey,{writable:!0,value:null}),Object.defineProperty(this,_ids,{writable:!0,value:{}}),Object.defineProperty(this,_BAP_SERVER,{writable:!0,value:_constants.BAP_SERVER}),Object.defineProperty(this,_BAP_TOKEN,{writable:!0,value:""}),Object.defineProperty(this,_lastIdPath,{writable:!0,value:""}),!b)throw new Error("No HDPrivateKey given");else(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey]=_bsv["default"].HDPrivateKey(b);c&&((0,_classPrivateFieldLooseBase2["default"])(this,_BAP_TOKEN)[_BAP_TOKEN]=c)}return(0,_createClass2["default"])(a,[{key:"getPublicKey",value:function getPublicKey(){var a=!!(0<arguments.length&&void 0!==arguments[0])&&arguments[0];return a?(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].deriveChild(a).publicKey.toString():(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].publicKey.toString()}},{key:"getHdPublicKey",value:function getHdPublicKey(){var a=!!(0<arguments.length&&void 0!==arguments[0])&&arguments[0];return a?(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].deriveChild(a).hdPublicKey.toString():(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].hdPublicKey.toString()}},{key:"BAP_SERVER",get:function get(){return(0,_classPrivateFieldLooseBase2["default"])(this,_BAP_SERVER)[_BAP_SERVER]},set:function set(a){var b=this;(0,_classPrivateFieldLooseBase2["default"])(this,_BAP_SERVER)[_BAP_SERVER]=a,Object.keys((0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids]).forEach(function(c){(0,_classPrivateFieldLooseBase2["default"])(b,_ids)[_ids][c].BAP_SERVER=a})}},{key:"BAP_TOKEN",get:function get(){return(0,_classPrivateFieldLooseBase2["default"])(this,_BAP_TOKEN)[_BAP_TOKEN]},set:function set(a){var b=this;(0,_classPrivateFieldLooseBase2["default"])(this,_BAP_TOKEN)[_BAP_TOKEN]=a,Object.keys((0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids]).forEach(function(c){(0,_classPrivateFieldLooseBase2["default"])(b,_ids)[_ids][c].BAP_TOKEN=a})}},{key:"checkIdBelongs",value:function checkIdBelongs(a){var b=(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].deriveChild(a.rootPath),c=b.publicKey.toAddress().toString();if(c!==a.rootAddress)throw new Error("ID does not belong to this private key");return!0}},{key:"listIds",value:function listIds(){return Object.keys((0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids])}},{key:"newId",value:function newId(){var a=0<arguments.length&&void 0!==arguments[0]?arguments[0]:null,b=1<arguments.length&&void 0!==arguments[1]?arguments[1]:{},c=2<arguments.length&&void 0!==arguments[2]?arguments[2]:"";a||(a=this.getNextValidPath());var d=new _id.BAP_ID((0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey],b,c);d.BAP_SERVER=(0,_classPrivateFieldLooseBase2["default"])(this,_BAP_SERVER)[_BAP_SERVER],d.BAP_TOKEN=(0,_classPrivateFieldLooseBase2["default"])(this,_BAP_TOKEN)[_BAP_TOKEN],d.rootPath=a,d.currentPath=_utils.Utils.getNextPath(a);var e=d.getIdentityKey();return(0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids][e]=d,(0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids][e]}},{key:"getNextValidPath",value:function getNextValidPath(){return(0,_classPrivateFieldLooseBase2["default"])(this,_lastIdPath)[_lastIdPath]?_utils.Utils.getNextPath((0,_classPrivateFieldLooseBase2["default"])(this,_lastIdPath)[_lastIdPath]):"/0'/".concat(Object.keys((0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids]).length,"'/0'")}},{key:"getId",value:function getId(a){return(0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids][a]||null}},{key:"setId",value:function setId(a){if(a instanceof _id.BAP_ID)this.checkIdBelongs(a),(0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids][a.getIdentityKey()]=a;else throw new Error("id is not an instance of BAP_ID")}},{key:"importIds",value:function importIds(a){var b=this,c=!(1<arguments.length&&void 0!==arguments[1])||arguments[1];if(c){var d=(0,_ecies["default"])(),e=(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].deriveChild(_constants.ENCRYPTION_PATH);d.privateKey(e.privateKey);var g=d.decrypt(Buffer.from(a,_utils.Utils.isHex(a)?"hex":"base64")).toString();a=JSON.parse(g)}var f=!1;!a.hasOwnProperty("ids")&&a.hasOwnProperty("lastIdPath")&&(f=!0,a={lastIdPath:"",ids:a}),a.ids.forEach(function(c){if(!c.identityKey||!c.identityAttributes||!c.rootAddress)throw new Error("ID cannot be imported as it is not complete");var d=new _id.BAP_ID((0,_classPrivateFieldLooseBase2["default"])(b,_HDPrivateKey)[_HDPrivateKey],{},c.idSeed);d.BAP_SERVER=(0,_classPrivateFieldLooseBase2["default"])(b,_BAP_SERVER)[_BAP_SERVER],d.BAP_TOKEN=(0,_classPrivateFieldLooseBase2["default"])(b,_BAP_TOKEN)[_BAP_TOKEN],d["import"](c),b.checkIdBelongs(d),(0,_classPrivateFieldLooseBase2["default"])(b,_ids)[_ids][d.getIdentityKey()]=d,f&&(a.lastIdPath=d.currentPath())}),(0,_classPrivateFieldLooseBase2["default"])(this,_lastIdPath)[_lastIdPath]=a.lastIdPath}},{key:"exportIds",value:function exportIds(){var a=this,b=!(0<arguments.length&&void 0!==arguments[0])||arguments[0],c={lastIdPath:(0,_classPrivateFieldLooseBase2["default"])(this,_lastIdPath)[_lastIdPath],ids:[]};if(Object.keys((0,_classPrivateFieldLooseBase2["default"])(this,_ids)[_ids]).forEach(function(b){c.ids.push((0,_classPrivateFieldLooseBase2["default"])(a,_ids)[_ids][b]["export"]())}),b){var d=(0,_ecies["default"])(),e=(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].deriveChild(_constants.ENCRYPTION_PATH);return d.publicKey(e.publicKey),d.encrypt(JSON.stringify(c)).toString("base64")}return c}},{key:"encrypt",value:function encrypt(a){var b=(0,_ecies["default"])(),c=(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].deriveChild(_constants.ENCRYPTION_PATH);return b.publicKey(c.publicKey),b.encrypt(a).toString("base64")}},{key:"decrypt",value:function decrypt(a){var b=(0,_ecies["default"])(),c=(0,_classPrivateFieldLooseBase2["default"])(this,_HDPrivateKey)[_HDPrivateKey].deriveChild(_constants.ENCRYPTION_PATH);return b.privateKey(c.privateKey),b.decrypt(Buffer.from(a,"base64")).toString()}},{key:"signAttestationWithAIP",value:function signAttestationWithAIP(a,b){var c=2<arguments.length&&void 0!==arguments[2]?arguments[2]:0,d=3<arguments.length&&void 0!==arguments[3]?arguments[3]:"",e=this.getId(b);if(!e||!(e instanceof _id.BAP_ID))throw new Error("Could not find identity to attest with");var f=this.getAttestationBuffer(a,c,d),g=e.signMessage(f),h=g.address,i=g.signature;return this.createAttestationTransaction(a,c,h,i,d)}},{key:"verifyAttestationWithAIP",value:function verifyAttestationWithAIP(a){if(!Array.isArray(a)||"0x6a"!==a[0]||a[1]!==_constants.BAP_BITCOM_ADDRESS_HEX)throw new Error("Not a valid BAP transaction");var b="0x44415441"===a[7]?5:0,c={type:_utils.Utils.hexDecode(a[2]),hash:_utils.Utils.hexDecode(a[3]),sequence:_utils.Utils.hexDecode(a[4]),signingProtocol:_utils.Utils.hexDecode(a[7+b]),signingAddress:_utils.Utils.hexDecode(a[8+b]),signature:_utils.Utils.hexDecode(a[9+b],"base64")};b&&a[3]===a[8]&&(c.data=_utils.Utils.hexDecode(a[9]));try{for(var d=[],e=0;e<6+b;e++)d.push(Buffer.from(a[e].replace("0x",""),"hex"));var f=Buffer.concat([].concat(d));c.verified=this.verifySignature(f,c.signingAddress,c.signature)}catch(a){c.verified=!1}return c}},{key:"createAttestationTransaction",value:function createAttestationTransaction(a,b,c,d){var e=4<arguments.length&&void 0!==arguments[4]?arguments[4]:"",f=["0x6a",_utils.Utils.hexEncode(_constants.BAP_BITCOM_ADDRESS)];return f.push(_utils.Utils.hexEncode("ATTEST")),f.push(_utils.Utils.hexEncode(a)),f.push(_utils.Utils.hexEncode("".concat(b))),f.push("0x7c"),e&&"string"==typeof e&&(f.push(_utils.Utils.hexEncode(_constants.BAP_BITCOM_ADDRESS)),f.push(_utils.Utils.hexEncode("DATA")),f.push(_utils.Utils.hexEncode(a)),f.push(_utils.Utils.hexEncode(e)),f.push("0x7c")),f.push(_utils.Utils.hexEncode(_constants.AIP_BITCOM_ADDRESS)),f.push(_utils.Utils.hexEncode("BITCOIN_ECDSA")),f.push(_utils.Utils.hexEncode(c)),f.push("0x"+Buffer.from(d,"base64").toString("hex")),f}},{key:"getAttestationBuffer",value:function getAttestationBuffer(a){var b=1<arguments.length&&void 0!==arguments[1]?arguments[1]:0,c=2<arguments.length&&void 0!==arguments[2]?arguments[2]:"",d=Buffer.from("");return c&&(d=Buffer.concat([Buffer.from(_constants.BAP_BITCOM_ADDRESS),Buffer.from("DATA"),Buffer.from(a),Buffer.from(c),Buffer.from("7c","hex")])),Buffer.concat([Buffer.from("6a","hex"),Buffer.from(_constants.BAP_BITCOM_ADDRESS),Buffer.from("ATTEST"),Buffer.from(a),Buffer.from("".concat(b)),Buffer.from("7c","hex"),d])}},{key:"verifySignature",value:function verifySignature(a,b,c){var d=Buffer.isBuffer(a)?a:Buffer.from(a);return _message["default"].verify(d,b,c)}},{key:"verifyChallengeSignature",value:function(){var a=(0,_asyncToGenerator2["default"])(_regenerator["default"].mark(function a(b,c,d,e){var f;return _regenerator["default"].wrap(function(a){for(;;)switch(a.prev=a.next){case 0:if(!this.verifySignature(d,c,e)){a.next=5;break}return a.next=3,this.getApiData("/attestation/valid",{idKey:b,challenge:d,signature:e});case 3:return f=a.sent,a.abrupt("return",f.data);case 5:return a.abrupt("return",!1);case 6:case"end":return a.stop();}},a,this)}));return function verifyChallengeSignature(){return a.apply(this,arguments)}}()},{key:"isValidAttestationTransaction",value:function(){var a=(0,_asyncToGenerator2["default"])(_regenerator["default"].mark(function a(b){return _regenerator["default"].wrap(function(a){for(;;)switch(a.prev=a.next){case 0:if(!this.verifyAttestationWithAIP(b)){a.next=2;break}return a.abrupt("return",this.getApiData("/attestation/valid",{tx:b}));case 2:return a.abrupt("return",!1);case 3:case"end":return a.stop();}},a,this)}));return function isValidAttestationTransaction(){return a.apply(this,arguments)}}()},{key:"getIdentityFromAddress",value:function(){var a=(0,_asyncToGenerator2["default"])(_regenerator["default"].mark(function a(b){return _regenerator["default"].wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",this.getApiData("/identity/from-address",{address:b}));case 1:case"end":return a.stop();}},a,this)}));return function getIdentityFromAddress(){return a.apply(this,arguments)}}()},{key:"getIdentity",value:function(){var a=(0,_asyncToGenerator2["default"])(_regenerator["default"].mark(function a(b){return _regenerator["default"].wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",this.getApiData("/identity",{idKey:b}));case 1:case"end":return a.stop();}},a,this)}));return function getIdentity(){return a.apply(this,arguments)}}()},{key:"getAttestationsForHash",value:function(){var a=(0,_asyncToGenerator2["default"])(_regenerator["default"].mark(function a(b){return _regenerator["default"].wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return a.abrupt("return",this.getApiData("/attestations",{hash:b}));case 1:case"end":return a.stop();}},a,this)}));return function getAttestationsForHash(){return a.apply(this,arguments)}}()},{key:"getApiData",value:function(){var a=(0,_asyncToGenerator2["default"])(_regenerator["default"].mark(function a(b,c){var d,e;return _regenerator["default"].wrap(function(a){for(;;)switch(a.prev=a.next){case 0:return d="".concat((0,_classPrivateFieldLooseBase2["default"])(this,_BAP_SERVER)[_BAP_SERVER]).concat(b),a.next=3,fetch(d,{method:"post",headers:{"Content-type":"application/json; charset=utf-8",token:(0,_classPrivateFieldLooseBase2["default"])(this,_BAP_TOKEN)[_BAP_TOKEN],format:"json"},body:JSON.stringify(c)});case 3:return e=a.sent,a.abrupt("return",e.json());case 5:case"end":return a.stop();}},a,this)}));return function getApiData(){return a.apply(this,arguments)}}()}]),a}()),_temp);exports.BAP=BAP;