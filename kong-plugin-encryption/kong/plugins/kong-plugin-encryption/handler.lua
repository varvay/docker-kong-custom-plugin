local sodium = require "luasodium"
local cjson = require "cjson"
local redis = require "redis"
local utils = require "kong.plugins.kong-plugin-encryption.utils"

local EncryptionHandler = {
  VERSION  = "0.0.1",
  PRIORITY = 10,
}

function EncryptionHandler:init_worker()
  -- Implement logic for the init_worker phase here (http/stream)
  kong.log.debug("init_worker")
end


function EncryptionHandler:preread(config)
  -- Implement logic for the preread phase here (stream)
  kong.log.debug("preread")
end


function EncryptionHandler:certificate(config)
  -- Implement logic for the certificate phase here (http/stream)
  kong.log.debug("certificate")
end

function EncryptionHandler:rewrite(config)
  -- Implement logic for the rewrite phase here (http)
  kong.log.debug("rewrite")

  -- Expose API /key-exchange
  if ngx.var.uri == "/key-exchange" then

    -- Map request
    local headers = ngx.req.get_headers()
    local device_id = headers["X-Device-ID"]
    local hex_enc_c_pub_k = headers["X-Enc-Public-Key"]
    local bin_enc_c_pub_k = utils.hex2bin(hex_enc_c_pub_k)
    local hex_sign_c_pub_k = headers["X-Sign-Public-Key"]
    local bin_sign_c_pub_k = utils.hex2bin(hex_sign_c_pub_k)

    local bin_sign_s_pub_k, bin_sign_s_priv_k = sodium.crypto_sign_keypair()
    local hex_sign_s_pub_k = utils.bin2hex(bin_sign_s_pub_k)
    local hex_sign_s_priv_k = utils.bin2hex(bin_sign_s_priv_k)
  
    local bin_enc_s_pub_k, bin_enc_s_priv_k = sodium.crypto_box_keypair()
    local hex_enc_s_pub_k = utils.bin2hex(bin_enc_s_pub_k)
    local hex_enc_s_priv_k = utils.bin2hex(bin_enc_s_priv_k)

    -- Store client's keys to Redis
    local keys = ({
      enc_c_pub_k = hex_enc_c_pub_k, 
      sign_c_pub_k = hex_sign_c_pub_k, 
      enc_s_priv_k = hex_enc_s_priv_k, 
      sign_s_priv_k = hex_sign_s_priv_k
    })

    local redis_client =  redis.connect("redis", 6379)
    
    for key, value in pairs(keys) do
      redis_client:hset(device_id, key, value)
    end

    redis_client:quit()
    
    -- Return response to client
    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
      hex_enc_s_public_key = hex_enc_s_pub_k,
      hex_sign_s_public_key = hex_sign_s_pub_k,
      hex_enc_s_private_key = hex_enc_s_priv_k }))
    ngx.exit(ngx.HTTP_OK)

  end

  -- Expose API /verify
  if ngx.var.uri == "/verify" then

    -- Map request
    local headers = ngx.req.get_headers()
    local device_id = headers["X-Device-ID"]
    local hex_c_enc_message = headers["X-Message"]
    local bin_c_enc_message = utils.hex2bin(hex_c_enc_message)
    local hex_in_nonce = headers["X-Nonce"]
    local bin_in_nonce = utils.hex2bin(hex_in_nonce)

    -- Retrieve client's keys from Redis
    local redis_client =  redis.connect("redis", 6379)

    local res, err = redis_client:hgetall(device_id)
    if not res then
      kong.log.error("Failed to retrieve HSET from Redis: ", err)
      return nil, err
    end

    redis_client:quit()

    -- Generate shared key
    local bin_enc_c_pub_k = utils.hex2bin(res["enc_c_pub_k"])
    local bin_enc_s_priv_k = utils.hex2bin(res["enc_s_priv_k"])
    local sharedKey = sodium.crypto_scalarmult(bin_enc_s_priv_k, bin_enc_c_pub_k)

    -- Decrypt request
    local bin_c_signed_message = sodium.crypto_aead_aes256gcm_decrypt(sharedKey, bin_c_enc_message, bin_in_nonce, nil)

    -- Verify signature
    local bin_sign_c_pub_k = utils.hex2bin(res["sign_c_pub_k"])

    local c_verified_message = sodium.crypto_sign_open(bin_c_signed_message, bin_sign_c_pub_k)

    -- Sign response
    local bin_sign_s_priv_k = utils.hex2bin(res["sign_s_priv_k"])

    local s_signed_message = sodium.crypto_sign(c_verified_message, bin_sign_s_priv_k)

    -- Encrypt response
    local nonce = sodium.randombytes_buf(sodium.crypto_aead_aes256gcm_NPUBBYTES)

    local ciphertext = sodium.crypto_aead_aes256gcm_encrypt(sharedKey, s_signed_message, nonce, nil)

    -- Return response to client
    local s_encrypted_message = ciphertext

    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
      message = utils.bin2hex(s_encrypted_message),
      nonce = utils.bin2hex(nonce),
      bin_enc_c_pub_k = utils.bin2hex(bin_enc_c_pub_k),
      bin_enc_s_priv_k = utils.bin2hex(bin_enc_s_priv_k),
    }))
    ngx.exit(ngx.HTTP_OK)
  end
end

function EncryptionHandler:access(config)
  -- Implement logic for the access phase here (http)
  kong.log.debug("access")

  local is_downstream_enc = kong.request.get_header("X-Downstream-Enc")

  kong.service.request.enable_buffering() -- TODO: add handler

  if (is_downstream_enc == "true") then

    -- Map request
    local device_id = kong.request.get_header("X-Device-ID")

    local current_body = kong.request.get_body()
    local nonce = utils.hex2bin(current_body.nonce)
    local ciphertext = utils.hex2bin(current_body.ciphertext)
    kong.log.notice("Downstream encrypted signed message: ", current_body.ciphertext)
    kong.log.notice("Downstream encrypted signed message size: ", #current_body.ciphertext)

    -- Retrieve client's keys from Redis
    local redis_client =  redis.connect("redis", 6379)

    local res, err = redis_client:hgetall(device_id)
    if not res then
      kong.log.error("Failed to retrieve HSET from Redis: ", err)
      return nil, err
    end

    redis_client:quit()

    -- Generate shared key
    local shared_key = sodium.crypto_scalarmult(
      utils.hex2bin(res["enc_s_priv_k"]), utils.hex2bin(res["enc_c_pub_k"]))

    -- Decrypt request
    local signedtext = sodium.crypto_aead_aes256gcm_decrypt(
      shared_key, ciphertext, nonce, nil)
    kong.log.notice("Downstream signed message: ", signedtext)
    kong.log.notice("Downstream signed message size: ", #signedtext)

    -- Verify signature
    local plaintext = sodium.crypto_sign_open(signedtext, utils.hex2bin(res["sign_c_pub_k"]))
    kong.log.notice("Downstream plaintext message: ", plaintext)
    kong.log.notice("Downstream plaintext message size: ", #plaintext)

    -- Replace request body
    kong.service.request.set_raw_body(plaintext)
    kong.service.request.set_header("Content-Type", "application/json")
    kong.service.request.set_header("Content-Length", #plaintext)
  
  end

end

function EncryptionHandler:ws_handshake(config)
  -- Implement logic for the WebSocket handshake here
  kong.log.debug("ws_handshake")
end

function EncryptionHandler:header_filter(config)
  -- Implement logic for the header_filter phase here (http)
  kong.log.debug("header_filter")

  local is_upstream_enc = kong.request.get_header("X-Upstream-Enc")

  if (is_upstream_enc == "true") then

    kong.response.set_header("Content-Type", "application/json; charset=utf-8")

    if (kong.response.get_header("Content-Encoding")) then
      kong.response.clear_header("Content-Encoding")
    end
    if (kong.response.get_header("Content-Length")) then
      kong.response.clear_header("Content-Length")
    end
  end
end

function EncryptionHandler:ws_client_frame(config)
  -- Implement logic for WebSocket client messages here
  kong.log.debug("ws_client_frame")
end

function EncryptionHandler:ws_upstream_frame(config)
  -- Implement logic for WebSocket upstream messages here
  kong.log.debug("ws_upstream_frame")
end

function EncryptionHandler:body_filter(config)
  -- Implement logic for the body_filter phase here (http)
  kong.log.debug("body_filter")

  local is_upstream_enc = kong.request.get_header("X-Upstream-Enc")

  if (is_upstream_enc == "true") then
    -- Map request
    local device_id = kong.request.get_header("X-Device-ID")

    -- Map response
    local plaintext = kong.service.response.get_raw_body()
    kong.log.notice("Upstream plaintext message: ", plaintext)
    kong.log.notice("Upstream plaintext message size: ", #plaintext)

    -- Retrieve client's keys from Redis
    local redis_client =  redis.connect("redis", 6379)

    local res, err = redis_client:hgetall(device_id)
    if not res then
      kong.log.error("Failed to retrieve HSET from Redis: ", err)
      return nil, err
    end

    redis_client:quit()

    -- Generate shared key
    local bin_enc_c_pub_k = utils.hex2bin(res["enc_c_pub_k"])
    local bin_enc_s_priv_k = utils.hex2bin(res["enc_s_priv_k"])
    local shared_key = sodium.crypto_scalarmult(bin_enc_s_priv_k, bin_enc_c_pub_k)


    -- Sign response
    local s_signed_message = sodium.crypto_sign(plaintext, utils.hex2bin(res["sign_s_priv_k"]))
    kong.log.notice("Upstream signed message: ", s_signed_message)
    kong.log.notice("Upstream signed message size: ", #s_signed_message)

    -- Encrypt response
    local nonce = sodium.randombytes_buf(sodium.crypto_aead_aes256gcm_NPUBBYTES)

    local ciphertext = sodium.crypto_aead_aes256gcm_encrypt(shared_key, s_signed_message, nonce, nil)
    kong.log.notice("Upstream encrypted signed message: ", utils.bin2hex(ciphertext))
    kong.log.notice("Upstream encrypted signed message size: ", #ciphertext)

    -- Replace response body
    local result = cjson.encode({
      ciphertext = utils.bin2hex(ciphertext),
      nonce = utils.bin2hex(nonce),
    })

    kong.response.set_raw_body(result)
  end

end

function EncryptionHandler:log(config)
  -- Implement logic for the log phase here (http/stream)
  kong.log.debug("log")
end

function EncryptionHandler:ws_close(config)
  -- Implement logic for WebSocket post-connection here
  kong.log.debug("ws_close")
end

return EncryptionHandler
