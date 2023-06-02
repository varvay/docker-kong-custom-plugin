# Welcome
This project is a runnable Hello World Kong project using Docker and custom Lua plugin

## References
Here are listed the references you can read for further details. Also by the time you find this project, the stacks used might be outdated already
* [Kong Docs - Develop Custom Plugins](https://docs.konghq.com/gateway/latest/plugin-development/)

## Stacks
Here are listed the stacks used,
* Docker ─ v20.10.21
* Kong ─ v3.3.0
* Lua ─ v5.4.6
* LuaRocks ─ v3.9.2

## Folder Structure
```
<root> ─ root folder
├── hello
    ├── kong
        ├── handler.lua
        ├── schema.lua
    ├── kong-plugin-hello-0.0.1-1.all.rock
    ├── kong-plugin-hello-0.0.1-1.rockspec
├── docker-compose.yml
├── Dockerfile
├── kong.yaml
├── README.md
```

## How To
Before jumping to running the project, here are listed the pre-requisite you need to fulfill that aren't part of the scope of this project and document,
* You should have Lua installed on your machine. I'm recommending to use at least Lua v5.1.x
* You should have LuaRocks installed on your machine. I'm recommending to use at least LuaRock v3.x.x
* You should have Docker installed on your machine. I'm recommending to use latest Docker version

Follow these steps to start and run the project,
1. build Lua plugin. Actually this step should be able to be included during the Docker image build, but somehow blocked due to an error. As a temporary workaround, this step will be done manually
   1. move to `<root>/hello/` directory to build the Lua plugin using LuaRocks
   2. execute command `sudo luarocks make`. Sudo in this case probably required so LuaRocks can write into LuaRocks's library directory
   3. execute command `luarocks pack kong-plugin-hello 0.0.1-1` to pack the Lua library so later can be installed during spinning up the Docker container. The output of this command would be an `all.rock` file e.g. `kong-plugin-hello-0.0.1-1.all.rock`
2. build Docker image
   1. move to `/<root>/` directory to build the Docker image
   2. execute command `docker build . -t kong-custom-plugin`
3. run Docker container
   1. execute command `docker compose up --build`

## Testing
Here are REST APIs that you can hit to test the Kong,
* retrieve Kong route configuration ─ `curl --location 'http://localhost:8081/routes'`
* accessing GitHub public API through gateway ─ `curl --location 'http://localhost:8080/github/users/octocat'`