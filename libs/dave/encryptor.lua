local ffi = require("ffi")

function getEncryptorClass(lib, utils)
	local Encryptor = {}

	function Encryptor:new()
		local encryptorHandle = lib.daveEncryptorCreate()
		if encryptorHandle == nil then
			error("Failed to create the encryptor")
		end
		
		local object = {}
		function object:destroy()
			lib.daveEncryptorDestroy(ffi.gc(encryptorHandle, nil))
			utils.destroy_object(self)
			encryptorHandle = nil
		end
		
		function object:setKeyRatchet(keyRatchet)
			local handle = utils.key_ratchet_storage[keyRatchet]
			if handle == nil then
				error("Tried to pass an invalid key ratchet to the encryptor")
			end
			
			lib.daveEncryptorSetKeyRatchet(encryptorHandle, handle)
		end
		
		function object:setPassthroughMode(passthroughMode)
			lib.daveEncryptorSetPassthroughMode(encryptorHandle, passthroughMode)
		end
		
		function object:assignSsrcToCodec(ssrc, codecType) -- to be checked
			lib.daveEncryptorAssignSsrcToCodec(encryptorHandle, ssrc, codecType)
		end
		
		function object:getProtocolVersion()
			return lib.daveEncryptorGetProtocolVersion(encryptorHandle)
		end
		
		function object:getMaxCiphertextByteSize(mediaType, frameSize) -- to be checked
			return lib.daveEncryptorGetMaxCiphertextByteSize(encryptorHandle, mediaType, frameSize)
		end
		
		function object:hasKeyRatchet()
			return lib.daveEncryptorHasKeyRatchet(encryptorHandle)
		end
		
		function object:isPassthroughMode()
			return lib.daveEncryptorIsPassthroughMode(encryptorHandle)
		end
		
		function object:encrypt(mediaType, ssrc, frame)
			local encryptedFrameCapacity = self:getMaxCiphertextByteSize(mediaType, #frame)
			local encryptedFramePointer = ffi.new("unsigned char[?]", encryptedFrameCapacity)
			local lengthPointer = ffi.new("size_t[1]")
			local resultCode = lib.daveEncryptorEncrypt(encryptorHandle, mediaType, ssrc, frame, #frame, encryptedFramePointer, encryptedFrameCapacity, lengthPointer)
			
			local encryptedFrame = utils.ffi_safe_string(encryptedFramePointer, lengthPointer)
			local result = {}
			function result:getFrame()
				return encryptedFrame
			end
			function result:getResultCode()
				return resultCode
			end
			
			return result
		end
		
		function object:setProtocolVersionChangedCallback(callback, userData) -- check
			lib.daveEncryptorSetProtocolVersionChangedCallback(encryptorHandle, callback, userData)
		end
		
		function object:getStats(mediaType)
			local encryptorStatsPointer = ffi.new("DAVEEncryptorStats[1]")
			lib.daveEncryptorGetStats(encryptorHandle, mediaType, encryptorStatsPointer)
			
			if encryptorStatsPointer == nil then
				return nil
			end
			
			local stats = encryptorStatsPointer[0]
			return {
				passthroughCount = stats.passthroughCount,
				encryptSuccessCount = stats.encryptSuccessCount,
				encryptFailureCount = stats.encryptFailureCount,
				encryptDuration = stats.encryptDuration,
				encryptAttempts = stats.encryptAttempts,
				encryptMaxAttempts = stats.encryptMaxAttempts,
				encryptMissingKeyCount = stats.encryptMissingKeyCount
			}
		end
		
		ffi.gc(encryptorHandle, function(handle)
			lib.daveEncryptorDestroy(handle)
			utils.destroy_object(object)
		end)
		return object
	end
	
	return Encryptor
end

return {
	get = getEncryptorClass
}

--[[
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
]]
