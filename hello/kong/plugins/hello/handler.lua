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
