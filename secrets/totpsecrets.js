/**
 * @fileoverview
 * @enhanceable
 * @public
 */
// GENERATED CODE -- DO NOT EDIT!

goog.provide('proto.secrets.TOTPSecrets');

goog.require('jspb.Message');
goog.require('jspb.BinaryReader');
goog.require('jspb.BinaryWriter');
goog.require('proto.secrets.Secret');


/**
 * Generated by JsPbCodeGenerator.
 * @param {Array=} opt_data Optional initial data array, typically from a
 * server response, or constructed directly in Javascript. The array is used
 * in place and becomes part of the constructed object. It is not cloned.
 * If no data is provided, the constructed object will be empty, but still
 * valid.
 * @extends {jspb.Message}
 * @constructor
 */
proto.secrets.TOTPSecrets = function(opt_data) {
  jspb.Message.initialize(this, opt_data, 0, -1, proto.secrets.TOTPSecrets.repeatedFields_, null);
};
goog.inherits(proto.secrets.TOTPSecrets, jspb.Message);
if (goog.DEBUG && !COMPILED) {
  proto.secrets.TOTPSecrets.displayName = 'proto.secrets.TOTPSecrets';
}
/**
 * List of repeated fields within this message type.
 * @private {!Array<number>}
 * @const
 */
proto.secrets.TOTPSecrets.repeatedFields_ = [1];



if (jspb.Message.GENERATE_TO_OBJECT) {
/**
 * Creates an object representation of this proto suitable for use in Soy templates.
 * Field names that are reserved in JavaScript and will be renamed to pb_name.
 * To access a reserved field use, foo.pb_<name>, eg, foo.pb_default.
 * For the list of reserved names please see:
 *     com.google.apps.jspb.JsClassTemplate.JS_RESERVED_WORDS.
 * @param {boolean=} opt_includeInstance Whether to include the JSPB instance
 *     for transitional soy proto support: http://goto/soy-param-migration
 * @return {!Object}
 */
proto.secrets.TOTPSecrets.prototype.toObject = function(opt_includeInstance) {
  return proto.secrets.TOTPSecrets.toObject(opt_includeInstance, this);
};


/**
 * Static version of the {@see toObject} method.
 * @param {boolean|undefined} includeInstance Whether to include the JSPB
 *     instance for transitional soy proto support:
 *     http://goto/soy-param-migration
 * @param {!proto.secrets.TOTPSecrets} msg The msg instance to transform.
 * @return {!Object}
 */
proto.secrets.TOTPSecrets.toObject = function(includeInstance, msg) {
  var f, obj = {
    secretsList: jspb.Message.toObjectList(msg.getSecretsList(),
    proto.secrets.Secret.toObject, includeInstance)
  };

  if (includeInstance) {
    obj.$jspbMessageInstance = msg;
  }
  return obj;
};
}


/**
 * Deserializes binary data (in protobuf wire format).
 * @param {jspb.ByteSource} bytes The bytes to deserialize.
 * @return {!proto.secrets.TOTPSecrets}
 */
proto.secrets.TOTPSecrets.deserializeBinary = function(bytes) {
  var reader = new jspb.BinaryReader(bytes);
  var msg = new proto.secrets.TOTPSecrets;
  return proto.secrets.TOTPSecrets.deserializeBinaryFromReader(msg, reader);
};


/**
 * Deserializes binary data (in protobuf wire format) from the
 * given reader into the given message object.
 * @param {!proto.secrets.TOTPSecrets} msg The message object to deserialize into.
 * @param {!jspb.BinaryReader} reader The BinaryReader to use.
 * @return {!proto.secrets.TOTPSecrets}
 */
proto.secrets.TOTPSecrets.deserializeBinaryFromReader = function(msg, reader) {
  while (reader.nextField()) {
    if (reader.isEndGroup()) {
      break;
    }
    var field = reader.getFieldNumber();
    switch (field) {
    case 1:
      var value = new proto.secrets.Secret;
      reader.readMessage(value,proto.secrets.Secret.deserializeBinaryFromReader);
      msg.addSecrets(value);
      break;
    default:
      reader.skipField();
      break;
    }
  }
  return msg;
};


/**
 * Serializes the message to binary data (in protobuf wire format).
 * @return {!Uint8Array}
 */
proto.secrets.TOTPSecrets.prototype.serializeBinary = function() {
  var writer = new jspb.BinaryWriter();
  proto.secrets.TOTPSecrets.serializeBinaryToWriter(this, writer);
  return writer.getResultBuffer();
};


/**
 * Serializes the given message to binary data (in protobuf wire
 * format), writing to the given BinaryWriter.
 * @param {!proto.secrets.TOTPSecrets} message
 * @param {!jspb.BinaryWriter} writer
 */
proto.secrets.TOTPSecrets.serializeBinaryToWriter = function(message, writer) {
  var f = undefined;
  f = message.getSecretsList();
  if (f.length > 0) {
    writer.writeRepeatedMessage(
      1,
      f,
      proto.secrets.Secret.serializeBinaryToWriter
    );
  }
};


/**
 * repeated Secret secrets = 1;
 * If you change this array by adding, removing or replacing elements, or if you
 * replace the array itself, then you must call the setter to update it.
 * @return {!Array.<!proto.secrets.Secret>}
 */
proto.secrets.TOTPSecrets.prototype.getSecretsList = function() {
  return /** @type{!Array.<!proto.secrets.Secret>} */ (
    jspb.Message.getRepeatedWrapperField(this, proto.secrets.Secret, 1));
};


/** @param {!Array.<!proto.secrets.Secret>} value */
proto.secrets.TOTPSecrets.prototype.setSecretsList = function(value) {
  jspb.Message.setRepeatedWrapperField(this, 1, value);
};


/**
 * @param {!proto.secrets.Secret=} opt_value
 * @param {number=} opt_index
 * @return {!proto.secrets.Secret}
 */
proto.secrets.TOTPSecrets.prototype.addSecrets = function(opt_value, opt_index) {
  return jspb.Message.addToRepeatedWrapperField(this, 1, opt_value, proto.secrets.Secret, opt_index);
};


proto.secrets.TOTPSecrets.prototype.clearSecretsList = function() {
  this.setSecretsList([]);
};


