local sodium = require "luasodium"
local cjson = require "cjson"
local redis = require "redis"

local HelloHandler = {
  VERSION  = "0.0.1",
  PRIORITY = 10,
}

function HelloHandler:init_worker()
  -- Implement logic for the init_worker phase here (http/stream)
  kong.log("Wasabi: init_worker")
end


function HelloHandler:preread(config)
  -- Implement logic for the preread phase here (stream)
  kong.log("Wasabi: preread")
end


function HelloHandler:certificate(config)
  -- Implement logic for the certificate phase here (http/stream)
  kong.log("Wasabi: certificate")
end

function HelloHandler:rewrite(config)
  -- Implement logic for the rewrite phase here (http)
  kong.log("Wasabi: rewrite")

  local function bin2hex(binary)
    local hex = ""
    for i = 1, #binary do
      local byte = binary:sub(i, i)
      hex = hex .. string.format("%02X", string.byte(byte))
    end
    return hex
  end
  
  local function hex2bin(hex)
    local bin = ""
    for i = 1, #hex, 2 do
      local byte = tonumber(hex:sub(i, i + 1), 16)
      bin = bin .. string.char(byte)
    end
    return bin
  end

  if ngx.var.uri == "/key-exchange" then
    local headers = ngx.req.get_headers()
    local device_id = headers["X-Device-ID"]
    local hex_enc_c_pub_k = headers["X-Enc-Public-Key"]
    local bin_enc_c_pub_k = hex2bin(hex_enc_c_pub_k)
    local hex_sign_c_pub_k = headers["X-Sign-Public-Key"]
    local bin_sign_c_pub_k = hex2bin(hex_sign_c_pub_k)

    local bin_sign_s_pub_k, bin_sign_s_priv_k = sodium.crypto_sign_keypair()
    local hex_sign_s_pub_k = bin2hex(bin_sign_s_pub_k)
    local hex_sign_s_priv_k = bin2hex(bin_sign_s_priv_k)
  
    local bin_enc_s_pub_k, bin_enc_s_priv_k = sodium.crypto_box_keypair()
    local hex_enc_s_pub_k = bin2hex(bin_enc_s_pub_k)
    local hex_enc_s_priv_k = bin2hex(bin_enc_s_priv_k)

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

    -- Genereate shared key
    -- To be implemented
    
    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
      hex_enc_s_public_key = hex_enc_s_pub_k,
      hex_sign_s_public_key = hex_sign_s_pub_k,
      hex_enc_s_private_key = hex_enc_s_priv_k }))
    ngx.exit(ngx.HTTP_OK)
  end

  if ngx.var.uri == "/verify" then
    local headers = ngx.req.get_headers()
    local device_id = headers["X-Device-ID"]
    local hex_c_enc_message = headers["X-Message"]
    local bin_c_enc_message = hex2bin(hex_c_enc_message)
    local hex_in_nonce = headers["X-Nonce"]
    local bin_in_nonce = hex2bin(hex_in_nonce)

    kong.log("Wasabi Device ID: ", device_id)
    kong.log("Wasabi Request Message: ", hex_c_enc_message)
    local redis_client =  redis.connect("redis", 6379)
    local res, err = redis_client:hgetall(device_id)
    kong.log("Wasabi: ", res)
    kong.log("Wasabi: ", err)
    if not res then
      ngx.log(ngx.ERR, "Failed to retrieve HSET from Redis: ", err)
      return nil, err
    end
    redis_client:quit()
    kong.log("Wasabi: ", res["enc_c_pub_k"])
    for field, value in pairs(res) do
      kong.log("Wasabi: ", field)
      kong.log("Wasabi: ", value)
    end

    local bin_enc_c_pub_k = hex2bin(res["enc_c_pub_k"])
    local bin_enc_s_priv_k = hex2bin(res["enc_s_priv_k"])
    local sharedKey = sodium.crypto_scalarmult(bin_enc_s_priv_k, bin_enc_c_pub_k)

    local bin_c_signed_message = sodium.crypto_aead_aes256gcm_decrypt(sharedKey, bin_c_enc_message, bin_in_nonce, nil)

    local bin_sign_c_pub_k = hex2bin(res["sign_c_pub_k"])

    local c_verified_message = sodium.crypto_sign_open(bin_c_signed_message, bin_sign_c_pub_k)

    kong.log("Wasabi: ", c_verified_message)

    local bin_sign_s_priv_k = hex2bin(res["sign_s_priv_k"])

    local s_signed_message = sodium.crypto_sign(c_verified_message, bin_sign_s_priv_k)

    local nonce = sodium.randombytes_buf(sodium.crypto_aead_aes256gcm_NPUBBYTES)

    kong.log("Wasabi nonce: ", bin2hex(nonce))
    kong.log("Wasabi sharedKey: ", bin2hex(sharedKey))

    local ciphertext = sodium.crypto_aead_aes256gcm_encrypt(sharedKey, s_signed_message, nonce, nil)
    local s_encrypted_message = ciphertext

    kong.log("Wasabi s_signed_message: ", bin2hex(s_signed_message))
    kong.log("Wasabi s_encrypted_message: ", bin2hex(s_encrypted_message))

    ngx.status = 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode({
      message = bin2hex(s_encrypted_message),
      nonce = bin2hex(nonce),
      bin_enc_c_pub_k = bin2hex(bin_enc_c_pub_k),
      bin_enc_s_priv_k = bin2hex(bin_enc_s_priv_k),
    }))
    ngx.exit(ngx.HTTP_OK)
  end
end

function HelloHandler:access(config)
  -- Implement logic for the access phase here (http)
  kong.log("Wasabi: access")
end

function HelloHandler:ws_handshake(config)
  -- Implement logic for the WebSocket handshake here
  kong.log("Wasabi: ws_handshake")
end

function HelloHandler:header_filter(config)
  -- Implement logic for the header_filter phase here (http)
  kong.log("Wasabi: header_filter")
end

function HelloHandler:ws_client_frame(config)
  -- Implement logic for WebSocket client messages here
  kong.log("Wasabi: ws_client_frame")
end

function HelloHandler:ws_upstream_frame(config)
  -- Implement logic for WebSocket upstream messages here
  kong.log("Wasabi: ws_upstream_frame")
end

function HelloHandler:body_filter(config)
  -- Implement logic for the body_filter phase here (http)
  kong.log("Wasabi: body_filter")
end

function HelloHandler:log(config)
  -- Implement logic for the log phase here (http/stream)
  kong.log("Wasabi: log")
end

function HelloHandler:ws_close(config)
  -- Implement logic for WebSocket post-connection here
  kong.log("Wasabi: ws_close")
end

-- return the created table, so that Kong can execute it
return HelloHandler
