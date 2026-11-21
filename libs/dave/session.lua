local ffi = require("ffi")

function getSessionClass(lib, utils)
	local Session = {}

	function Session:new(context, authSessionId, callback, userData)
		local sessionHandle = lib.daveSessionCreate(context, authSessionId, callback, userData)
		if sessionHandle == nil then
			error("Failed to create a session")
		end
		
		local object = {}
		function object:destroy()
			lib.daveSessionDestroy(ffi.gc(sessionHandle, nil))
			utils.destroy_object(self)
			sessionHandle = nil
		end
		
		function object:init(version, groupId, sessionHandleUserId) -- uint16_t version, uint64_t groupId
			if type(groupId) == "string" then
				local temp = 0ULL
				for i = 1, #groupId do
					temp = temp * 10ULL + tonumber(string.sub(groupId, i, i))
				end
				groupId = temp
			end
			
			lib.daveSessionInit(sessionHandle, version, groupId, sessionHandleUserId)
		end
		
		function object:reset()
			lib.daveSessionReset(sessionHandle)
		end
		
		function object:setProtocolVersion(version) -- uint16_t version
			lib.daveSessionSetProtocolVersion(sessionHandle, version)
		end
		
		function object:getProtocolVersion()
			return lib.daveSessionGetProtocolVersion(sessionHandle)
		end
		
		-- void daveSessionGetLastEpochAuthenticator(DAVESessionHandle session, uint8_t** authenticator, size_t* length);
		function object:getLastEpochAuthenticator()
			local authenticatorPointer = ffi.new("unsigned char *[1]")
			local lengthPointer = ffi.new("size_t[1]")
			
			lib.daveSessionGetLastEpochAuthenticator(sessionHandle, authenticatorPointer, lengthPointer)
			return utils.ffi_safe_string(authenticatorPointer, lengthPointer)
		end
		
		function object:setExternalSender(externalSender)
			lib.daveSessionSetExternalSender(sessionHandle, externalSender, #externalSender)
		end
		
		function object:addRecognizedUser(userId)
			lib.daveSessionAddRecognizedUser(sessionHandle, userId)
		end
		
		function object:removeRecognizedUser(userId)
			lib.daveSessionRemoveRecognizedUser(sessionHandle, userId)
		end
		
		-- void daveSessionProcessProposals(DAVESessionHandle session, const uint8_t* proposals, size_t length, uint8_t** commitWelcomeBytes, size_t* commitWelcomeBytesLength);
		function object:processProposals(proposals)
			local commitWelcomeBytesPointer = ffi.new("unsigned char *[1]")
			local lengthPointer = ffi.new("size_t[1]")
			
			lib.daveSessionProcessProposals(sessionHandle, proposals, #proposals, commitWelcomeBytesPointer, lengthPointer)
			
			local commitWelcomeBytes = utils.ffi_safe_string(commitWelcomeBytesPointer, lengthPointer)
			if commitWelcomeBytesPointer ~= nil then
				lib.daveFree(commitWelcomeBytesPointer[0])
			end
			
			return commitWelcomeBytes
		end
		
		function object:processCommit(commit, ignore_result)
			-- DAVECommitResultHandle daveSessionProcessCommit(DAVESessionHandle session, const uint8_t* commit, size_t length);
			local handle = lib.daveSessionProcessCommit(sessionHandle, commit, #commit)
			
			local rosterIds = {}
			local rosterSignatures = {}
			
			local result = {getRosterMemberIds = rosterIds}
			function result:isFailed()
				return true
			end
			function result:isIgnored()
				return true
			end
			function result:getRosterMemberSignature(rosterId)
				return rosterSignatures[rosterId]
			end
			
			if handle ~= nil then
				local rosterIdsPointer = ffi.new("uint64_t*[1]")
				local rosterIdsLengthPointer = ffi.new("size_t[1]")
				lib.daveCommitResultGetRosterMemberIds(handle, rosterIdsPointer, rosterLengthPointer)
				
				if (rosterIdsPointer ~= nil) and (rosterIdsLengthPointer ~= nil) then
					local rosterIdsLength = rosterIdsLengthPointer[0]
					if rosterIdsLength > 0 then
						local rosterIdRaw = rosterIdsPointer[0]
						for index = 0, tonumber(rosterIdsLength - 1) do
							rosterIds[index] = rosterIdRaw[index]
						end
					
						lib.daveFree(rosterIdRaw)
					end
					
					for _, rosterId in pairs(rosterIds) do
						local signaturePointer = ffi.new("unsigned char *[1]")
						local signatureLengthPointer = ffi.new("size_t[1]")
						
						--void daveCommitResultGetRosterMemberSignature(DAVECommitResultHandle commitResultHandle, uint64_t rosterId, uint8_t** signature, size_t* signatureLength);
						lib.daveCommitResultGetRosterMemberSignature(handle, rosterId, signaturePointer, signatureLengthPointer)
						rosterSignatures[rosterId] = utils.ffi_safe_string(signaturePointer, signatureLengthPointer)
						
						if signaturePointer ~= nil then
							lib.daveFree(signaturePointer[0])
						end
					end
				end
				
				local isFailed, isIgnored = lib.daveCommitResultIsFailed(handle), lib.daveCommitResultIsIgnored(handle)
				function result:isFailed()
					return isFailed
				end
				function result:isIgnored()
					return isIgnored
				end
				
				lib.daveCommitResultDestroy(ffi.gc(handle, nil))
			end
			
			return result
		end
		
		function object:processWelcome(welcome)
			-- DAVEWelcomeResultHandle daveSessionProcessWelcome(DAVESessionHandle session, const uint8_t* welcome, size_t length);
			local handle = lib.daveSessionProcessWelcome(sessionHandle, welcome, #welcome)
			if handle == nil then
				return nil
			end
			
			local rosterIds = {}
			local rosterSignatures = {}
			
			local rosterIdsPointer = ffi.new("uint64_t*[1]")
			local rosterIdsLengthPointer = ffi.new("size_t[1]")
			lib.daveWelcomeResultGetRosterMemberIds(handle, rosterIdsPointer, rosterIdsLengthPointer)
			
			if (rosterIdsPointer ~= nil) and (rosterIdsLengthPointer ~= nil) then
				local rosterIdsLength = rosterIdsLengthPointer[0]
				if rosterIdsLength > 0 then
					local rosterIdRaw = rosterIdsPointer[0]
					for index = 0, tonumber(rosterIdsLength - 1) do
						rosterIds[index] = rosterIdRaw[index]
					end
					
					lib.daveFree(rosterIdRaw)
				end
				
				for _, rosterId in pairs(rosterIds) do
					local signaturePointer = ffi.new("unsigned char *[1]")
					local signatureLengthPointer = ffi.new("size_t[1]")
					
					lib.daveWelcomeResultGetRosterMemberSignature(handle, rosterId, signaturePointer, signatureLengthPointer)
					rosterSignatures[rosterId] = utils.ffi_safe_string(signaturePointer, signatureLengthPointer)
					
					if signaturePointer ~= nil then
						lib.daveFree(signaturePointer[0])
					end
				end
			end
			
			lib.daveWelcomeResultDestroy(ffi.gc(handle, nil))
			
			local result = {}
			function result:getRosterMemberIds()
				return rosterIds
			end
			function result:getRosterMemberSignature(rosterId)
				return rosterSignatures[rosterId]
			end
			
			return result
		end
		
		-- void daveSessionGetMarshalledKeyPackage(DAVESessionHandle session, uint8_t** keyPackage, size_t* length);
		function object:getMarshalledKeyPackage()
			local keyPackagePointer = ffi.new("unsigned char *[1]")
			local lengthPointer = ffi.new("size_t[1]")
			
			lib.daveSessionGetMarshalledKeyPackage(sessionHandle, keyPackagePointer, lengthPointer)
			return utils.ffi_safe_string(keyPackagePointer, lengthPointer)
		end
		
		-- DAVEKeyRatchetHandle daveSessionGetKeyRatchet(DAVESessionHandle session, const char* userId);
		function object:getKeyRatchet(userId)
			local handle = lib.daveSessionGetKeyRatchet(sessionHandle, userId)
			if handle == nil then
				return nil
			end
			
			local keyRatchetObject = {}
			function keyRatchetObject:destroy()
				if handle ~= nil then
					lib.daveKeyRatchetDestroy(ffi.gc(handle, nil))
					handle = nil
				end
				
				utils.destroy_object(self)
			end
			
			ffi.gc(handle, function(handle)
				lib.daveKeyRatchetDestroy(handle)
				utils.destroy_object(keyRatchetObject)
			end)
			
			utils.key_ratchet_storage[keyRatchetObject] = handle
			return keyRatchetObject
		end
		
		-- void daveSessionGetPairwiseFingerprint(DAVESessionHandle session, uint16_t version, const char* userId, DAVEPairwiseFingerprintCallback callback, void* userData);
		function object:getPairwiseFingerprint(version, userId, callback, userData)
			lib.daveSessionGetPairwiseFingerprint(sessionHandle, version, userId, function(fingerprint, length)
				callback(utils.ffi_safe_string(fingerprint, length), userData)
			end, userData)
		end
		
		ffi.gc(sessionHandle, function(handle)
			lib.daveSessionDestroy(handle)
			utils.destroy_object(object)
		end)
		return object
	end
	
	return Session
end

return {
	get = getSessionClass
}
