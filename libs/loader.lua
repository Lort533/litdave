local ffi = require("ffi")
local formats = {
	["Windows"] = "dll",
	["Linux"] = "so",
	["OSX"] = "dylib"
}
local ok, libdave = pcall(module.action, module, "../" .. ffi.os .. "-" .. ffi.arch .. "/libdave." .. formats[ffi.os], ffi.load)

if not ok then
	error("libdave not found")
end

-- See https://github.com/discord/libdave/blob/main/cpp/includes/dave/dave.h for documentation
ffi.cdef[[
//
// Initial stuff
//

typedef struct DAVESessionHandle* DAVESessionHandle;
typedef struct DAVECommitResultHandle* DAVECommitResultHandle;
typedef struct DAVEWelcomeResultHandle* DAVEWelcomeResultHandle;
typedef struct DAVEKeyRatchetHandle* DAVEKeyRatchetHandle;
typedef struct DAVEEncryptorHandle* DAVEEncryptorHandle;
typedef struct DAVEDecryptorHandle* DAVEDecryptorHandle;

typedef enum {
    DAVE_CODEC_UNKNOWN = 0,
    DAVE_CODEC_OPUS = 1,
    DAVE_CODEC_VP8 = 2,
    DAVE_CODEC_VP9 = 3,
    DAVE_CODEC_H264 = 4,
    DAVE_CODEC_H265 = 5,
    DAVE_CODEC_AV1 = 6
} DAVECodec;

typedef enum {
    DAVE_MEDIA_TYPE_AUDIO = 0,
    DAVE_MEDIA_TYPE_VIDEO = 1
} DAVEMediaType;

typedef enum {
    DAVE_ENCRYPTOR_RESULT_CODE_SUCCESS = 0,
    DAVE_ENCRYPTOR_RESULT_CODE_ENCRYPTION_FAILURE = 1,
    DAVE_ENCRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET = 2,
    DAVE_ENCRYPTOR_RESULT_CODE_MISSING_CRYPTOR = 3,
    DAVE_ENCRYPTOR_RESULT_CODE_TOO_MANY_ATTEMPTS = 4,
} DAVEEncryptorResultCode;

typedef enum {
    DAVE_DECRYPTOR_RESULT_CODE_SUCCESS = 0,
    DAVE_DECRYPTOR_RESULT_CODE_DECRYPTION_FAILURE = 1,
    DAVE_DECRYPTOR_RESULT_CODE_MISSING_KEY_RATCHET = 2,
    DAVE_DECRYPTOR_RESULT_CODE_INVALID_NONCE = 3,
    DAVE_DECRYPTOR_RESULT_CODE_MISSING_CRYPTOR = 4
} DAVEDecryptorResultCode;

typedef enum {
    DAVE_LOGGING_SEVERITY_VERBOSE = 0,
    DAVE_LOGGING_SEVERITY_INFO = 1,
    DAVE_LOGGING_SEVERITY_WARNING = 2,
    DAVE_LOGGING_SEVERITY_ERROR = 3,
    DAVE_LOGGING_SEVERITY_NONE = 4
} DAVELoggingSeverity;

typedef void (*DAVEMLSFailureCallback)(const char* source, const char* reason, void* userData);
typedef void (*DAVEPairwiseFingerprintCallback)(const uint8_t* fingerprint, size_t length, void* userData);
typedef void (*DAVEEncryptorProtocolVersionChangedCallback)(void* userData);
typedef void (*DAVELogSinkCallback)(DAVELoggingSeverity severity, const char* file, int line, const char* message);

typedef struct DAVEEncryptorStats {
    uint64_t passthroughCount;
    uint64_t encryptSuccessCount;
    uint64_t encryptFailureCount;
    uint64_t encryptDuration;
    uint64_t encryptAttempts;
    uint64_t encryptMaxAttempts;
    uint64_t encryptMissingKeyCount;
} DAVEEncryptorStats;

typedef struct DAVEDecryptorStats {
    uint64_t passthroughCount;
    uint64_t decryptSuccessCount;
    uint64_t decryptFailureCount;
    uint64_t decryptDuration;
    uint64_t decryptAttempts;
    uint64_t decryptMissingKeyCount;
    uint64_t decryptInvalidNonceCount;
} DAVEDecryptorStats;

//
// Version
//

uint16_t daveMaxSupportedProtocolVersion(void);

//
// Memory Management
//

void daveFree(void* ptr);

//
// Session Management
//

DAVESessionHandle daveSessionCreate(void* context, const char* authSessionId, DAVEMLSFailureCallback callback, void* userData);
void daveSessionDestroy(DAVESessionHandle session);
void daveSessionInit(DAVESessionHandle session, uint16_t version, uint64_t groupId, const char* selfUserId);
void daveSessionReset(DAVESessionHandle session);
void daveSessionSetProtocolVersion(DAVESessionHandle session, uint16_t version);
uint16_t daveSessionGetProtocolVersion(DAVESessionHandle session);
void daveSessionGetLastEpochAuthenticator(DAVESessionHandle session, uint8_t** authenticator, size_t* length);
void daveSessionSetExternalSender(DAVESessionHandle session, const uint8_t* externalSender, size_t length);
void daveSessionAddRecognizedUser(DAVESessionHandle session, const char* userId);
void daveSessionRemoveRecognizedUser(DAVESessionHandle session, const char* userId);
void daveSessionProcessProposals(DAVESessionHandle session, const uint8_t* proposals, size_t length, uint8_t** commitWelcomeBytes, size_t* commitWelcomeBytesLength);
DAVECommitResultHandle daveSessionProcessCommit(DAVESessionHandle session, const uint8_t* commit, size_t length);
DAVEWelcomeResultHandle daveSessionProcessWelcome(DAVESessionHandle session, const uint8_t* welcome, size_t length);
void daveSessionGetMarshalledKeyPackage(DAVESessionHandle session, uint8_t** keyPackage, size_t* length);
DAVEKeyRatchetHandle daveSessionGetKeyRatchet(DAVESessionHandle session, const char* userId);
void daveSessionGetPairwiseFingerprint(DAVESessionHandle session, uint16_t version, const char* userId, DAVEPairwiseFingerprintCallback callback, void* userData);

//
// Key Ratchet
//

void daveKeyRatchetDestroy(DAVEKeyRatchetHandle keyRatchet);

//
// Commit Result
//

bool daveCommitResultIsFailed(DAVECommitResultHandle commitResultHandle);
bool daveCommitResultIsIgnored(DAVECommitResultHandle commitResultHandle);
void daveCommitResultGetRosterMemberIds(DAVECommitResultHandle commitResultHandle, uint64_t** rosterIds, size_t* rosterIdsLength);
void daveCommitResultGetRosterMemberSignature(DAVECommitResultHandle commitResultHandle, uint64_t rosterId, uint8_t** signature, size_t* signatureLength);
void daveCommitResultDestroy(DAVECommitResultHandle commitResultHandle);

//
// Welcome Result
//

void daveWelcomeResultGetRosterMemberIds(DAVEWelcomeResultHandle welcomeResultHandle, uint64_t** rosterIds, size_t* rosterIdsLength);
void daveWelcomeResultGetRosterMemberSignature(DAVEWelcomeResultHandle welcomeResultHandle, uint64_t rosterId, uint8_t** signature, size_t* signatureLength);
void daveWelcomeResultDestroy(DAVEWelcomeResultHandle welcomeResultHandle);

//
// Encryptor
//

DAVEEncryptorHandle daveEncryptorCreate(void);
void daveEncryptorDestroy(DAVEEncryptorHandle encryptor);
void daveEncryptorSetKeyRatchet(DAVEEncryptorHandle encryptor, DAVEKeyRatchetHandle keyRatchet);
void daveEncryptorSetPassthroughMode(DAVEEncryptorHandle encryptor, bool passthroughMode);
void daveEncryptorAssignSsrcToCodec(DAVEEncryptorHandle encryptor, uint32_t ssrc, DAVECodec codecType);
uint16_t daveEncryptorGetProtocolVersion(DAVEEncryptorHandle encryptor);
size_t daveEncryptorGetMaxCiphertextByteSize(DAVEEncryptorHandle encryptor, DAVEMediaType mediaType, size_t frameSize);
bool daveEncryptorHasKeyRatchet(DAVEEncryptorHandle encryptor);
bool daveEncryptorIsPassthroughMode(DAVEEncryptorHandle encryptor);
DAVEEncryptorResultCode daveEncryptorEncrypt(DAVEEncryptorHandle encryptor, DAVEMediaType mediaType, uint32_t ssrc, const uint8_t* frame, size_t frameLength, uint8_t* encryptedFrame, size_t encryptedFrameCapacity, size_t* bytesWritten);
void daveEncryptorSetProtocolVersionChangedCallback( DAVEEncryptorHandle encryptor, DAVEEncryptorProtocolVersionChangedCallback callback, void* userData);
void daveEncryptorGetStats(DAVEEncryptorHandle encryptor, DAVEMediaType mediaType, DAVEEncryptorStats* stats);

//
// Decryptor
//

DAVEDecryptorHandle daveDecryptorCreate(void);
void daveDecryptorDestroy(DAVEDecryptorHandle decryptor);
void daveDecryptorTransitionToKeyRatchet(DAVEDecryptorHandle decryptor, DAVEKeyRatchetHandle keyRatchet);
void daveDecryptorTransitionToPassthroughMode(DAVEDecryptorHandle decryptor, bool passthroughMode);
DAVEDecryptorResultCode daveDecryptorDecrypt(DAVEDecryptorHandle decryptor, DAVEMediaType mediaType, const uint8_t* encryptedFrame, size_t encryptedFrameLength, uint8_t* frame, size_t frameCapacity, size_t* bytesWritten);
size_t daveDecryptorGetMaxPlaintextByteSize(DAVEDecryptorHandle decryptor, DAVEMediaType mediaType, size_t encryptedFrameSize);
void daveDecryptorGetStats(DAVEDecryptorHandle decryptor, DAVEMediaType mediaType, DAVEDecryptorStats* stats);

//
// Logging
//

void daveSetLogSinkCallback(DAVELogSinkCallback callback);
]]

return libdave
