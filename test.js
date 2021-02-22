const requestHandlerAuthenticate = require("./component.request.handler.secure.authenticate.js");
const delegate = require("component.delegate");
const utils = require("utils");
const request = require("component.request");
const logging = require("logging");
logging.config.add("Request Handler Secure Authenticate");

( async() => {

    let securedRequest = { name: "localhost", port: 3000, path: "/secure" };
    let unsecuredRequest = { name: "localhost", port: 4000, path: "/unsecure" };

    delegate.register("component.request.handler.secure", `${securedRequest.port}${securedRequest.path}`, ({ privateKey, hashedPassphrase, token }) => {
        if (token && privateKey && hashedPassphrase){
            return { 
                headers: { "Content-Type":"text/plain" },
                statusCode: 200, 
                statusMessage: "Success",
                data: "Success"
            };
        }
        return { 
            headers: { "Content-Type":"text/plain" },
            statusCode: 401, 
            statusMessage: "Failed",
            data: "Failed"
        };
    });
    delegate.register("component.request.handler.secure", `${unsecuredRequest.port}${unsecuredRequest.path}`, ({ privateKey, hashedPassphrase, token }) => {
        if (token){
            return {
                headers: { "Content-Type":"text/plain" },
                statusCode: 500, 
                statusMessage: "Failed",
                data: "Failed"
            };
        }
        return { 
            headers: { "Content-Type":"text/plain" },
            statusCode: 200, 
            statusMessage: "Success",
            data: "Success"
        };
    });

    //Secure
    const { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    await requestHandlerAuthenticate.handle({
        host: securedRequest.name,
        port: securedRequest.port,
        path: securedRequest.path,
        hashedPassphrase,
        hashedPassphraseSalt
    });
    //Unsecure
    await requestHandlerAuthenticate.handle({
        host: unsecuredRequest.name,
        port: unsecuredRequest.port,
        path: unsecuredRequest.path,
    });

    //Authentication Required Success Test
    let results = await request.send({ 
        host: securedRequest.name,
        port: securedRequest.port,
        path: securedRequest.path,
        method: "GET",
        headers: {
            username: "marchuanv",
            fromhost: "localhost",
            fromport: 6000,
            passphrase: "secure1"
        }, 
        data: "",
        retryCount: 1
    });
    if (results.statusCode !== 200 || results.statusMessage === "Failed"){
        throw "Authentication Required Success Test Failed";
    }

    //Authentication Required Fail Test
    results = await request.send({ 
        host: securedRequest.name,
        port: securedRequest.port,
        path: securedRequest.path,
        method: "GET",
        headers: { 
            username: "marchuanv",
            fromhost: "localhost",
            fromport: 6000,
            passphrase: "secure2"
        }, 
        data: "",
        retryCount: 1
    });
    if (results.statusCode !== 401 || results.statusMessage !== "Failed"){
        throw "Authentication Required Fail Test Failed";
    }

    //Authentication Not Required Test
    results = await request.send({ 
        host: unsecuredRequest.name,
        port: unsecuredRequest.port,
        path: unsecuredRequest.path,
        method: "GET",
        headers: { 
            username: "marchuanv",
            fromhost: "localhost",
            fromport: 6000
        }, 
        data: "",
        retryCount: 1
    });
    if (results.statusCode !== 200){
        throw "Authentication Not Required Test Failed";
    }

    process.exit();

})().catch((err)=>{
    console.error(err);
});