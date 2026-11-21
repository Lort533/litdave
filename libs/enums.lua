-- See https://github.com/discord/libdave/blob/main/cpp/includes/dave/dave.h for documentation
return {
	codec = {
		UNKNOWN = 0,
		OPUS = 1,
		VP8 = 2,
		VP9 = 3,
		H264 = 4,
		H265 = 5,
		AV1 = 6
	},
	mediaType = {
		AUDIO = 0,
		VIDEO = 1
	},
	encryptorResultCode = {
		SUCCESS = 0,
		ENCRYPTION_FAILURE = 1,
		MISSING_KEY_RATCHET = 2,
		MISSING_CRYPTOR = 3,
		TOO_MANY_ATTEMPTS = 4
	},
	decryptorResultCode = {
		SUCCESS = 0,
		DECRYPTION_FAILURE = 1,
		MISSING_KEY_RATCHET = 2,
		INVALID_NONCE = 3,
		MISSING_CRYPTOR = 4
	},
	loggingSeverity = {
		VERBOSE = 0,
		INFO = 1,
		WARNING = 2,
		ERROR = 3,
		NONE = 4
	}
}
