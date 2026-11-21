local ffi = require("ffi")

function getDecryptorClass(lib, utils)
	local Decryptor = {}

	function Decryptor:new()
		local decryptorHandle = lib.daveDecryptorCreate()
		if decryptorHandle == nil then
			error("Failed to create the decryptor")
		end
		
		local object = {}
		function object:destroy()
			lib.daveDecryptorDestroy(ffi.gc(decryptorHandle, nil))
			utils.destroy_object(self)
			decryptorHandle = nil
		end
		
		function object:transitionToKeyRatchet(keyRatchet)
			local handle = utils.key_ratchet_storage[keyRatchet]
			if handle == nil then
				error("Tried to pass an invalid key ratchet to the decryptor")
			end
			
			lib.daveDecryptorTransitionToKeyRatchet(decryptorHandle, handle)
		end
		
		function object:transitionToPassthroughMode(passthroughMode)
			lib.daveDecryptorTransitionToPassthroughMode(decryptorHandle, passthroughMode)
		end
		
		function object:getMaxPlaintextByteSize(mediaType, encryptedFrameSize)
			return lib.daveDecryptorGetMaxPlaintextByteSize(decryptorHandle, mediaType, encryptedFrameSize)
		end
		
		function object:decrypt(mediaType, encryptedFrame)
			local frameCapacity = self:getMaxPlaintextByteSize(mediaType, #encryptedFrame)
			local framePointer = ffi.new("unsigned char[?]", frameCapacity)
			local lengthPointer = ffi.new("size_t[1]")
			local resultCode = lib.daveDecryptorDecrypt(decryptorHandle, mediaType, encryptedFrame, #encryptedFrame, framePointer, frameCapacity, lengthPointer)
			
			local frame = utils.ffi_safe_string(framePointer, lengthPointer)
			local result = {}
			function result:getFrame()
				return frame
			end
			function result:getResultCode()
				return resultCode
			end
			
			return result
		end
		
		function object:getStats(mediaType)
			local decryptorStatsPointer = ffi.new("DAVEDecryptorStats[1]")
			lib.daveDecryptorGetStats(decryptorHandle, mediaType, decryptorStatsPointer)
			
			if decryptorStatsPointer == nil then
				return nil
			end
			
			local stats = decryptorStatsPointer[0]
			return {
				passthroughCount = stats.passthroughCount,
				decryptSuccessCount = stats.decryptSuccessCount,
				decryptFailureCount = stats.decryptFailureCount,
				decryptDuration = stats.decryptDuration,
				decryptAttempts = stats.decryptAttempts,
				decryptMissingKeyCount = stats.decryptMissingKeyCount,
				decryptInvalidNonceCount = stats.decryptInvalidNonceCount
			}
		end
		
		ffi.gc(decryptorHandle, function(handle)
			lib.daveDecryptorDestroy(handle)
			utils.destroy_object(object)
		end)
		return object
	end
	
	return Decryptor
end

return {
	get = getDecryptorClass
}

--[[
DAVEDecryptorHandle daveDecryptorCreate(void);
void daveDecryptorDestroy(DAVEDecryptorHandle decryptor);
void daveDecryptorTransitionToKeyRatchet(DAVEDecryptorHandle decryptor, DAVEKeyRatchetHandle keyRatchet);
void daveDecryptorTransitionToPassthroughMode(DAVEDecryptorHandle decryptor, bool passthroughMode);
DAVEDecryptorResultCode daveDecryptorDecrypt(DAVEDecryptorHandle decryptor, DAVEMediaType mediaType, const uint8_t* encryptedFrame, size_t encryptedFrameLength, uint8_t* frame, size_t frameCapacity, size_t* bytesWritten);
size_t daveDecryptorGetMaxPlaintextByteSize(DAVEDecryptorHandle decryptor, DAVEMediaType mediaType, size_t encryptedFrameSize);
void daveDecryptorGetStats(DAVEDecryptorHandle decryptor, DAVEMediaType mediaType, DAVEDecryptorStats* stats);
]]
