rockspec_format = "3.0"
package = "kong-plugin-hello"
version = "0.0.1-1"
source = {
   url = "git+https://github.com/varvay/helloworld.git",
}
description = {
   homepage = "https://github.com/varvay/helloworld",
   license = "*** please specify a license ***",
}
dependencies = {
   "lua >= 5.1",
}
build = {
   type = "builtin",
   modules = {
      ["kong.plugins.kong-plugin-hello.handler"] = "kong/plugins/hello/handler.lua",
      ["kong.plugins.kong-plugin-hello.schema"] = "kong/plugins/hello/schema.lua",
   }
}
