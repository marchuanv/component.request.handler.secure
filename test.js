const requestHandlerAuthenticate = require("./component.request.handler.secure.authenticate.js");
const delegate = require("component.delegate");
const utils = require("utils");
const unsecureRequest = require("component.request.unsecure");
const secureRequest = require("component.request.secure");
const logging = require("logging");
logging.config.add("Request Handler Secure Authenticate");

( async() => {

    let securedRequest = { name: "localhost", port: 3000, path: "/secure" };
    let unsecuredRequest = { name: "localhost", port: 4000, path: "/unsecure" };
    let context = "component.request.handler.secure";
    
    delegate.register(context, `${securedRequest.port}${securedRequest.path}`, ({  headers, session, data }) => {
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

    delegate.register(context, `${unsecuredRequest.port}${unsecuredRequest.path}`, ({ headers, session, data }) => {
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

    //Secure Request Authentication Required Success Test
    let results = await secureRequest.send({ 
        host: securedRequest.name,
        port: securedRequest.port,
        path: securedRequest.path,
        method: "GET",
        username: "marchuanv",
        fromhost: "localhost",
        fromport: 6000,
        passphrase: "secure1",
        data: ""
    });
    if (results.statusCode !== 200 || results.statusMessage === "Failed"){
        throw "Secure Request Authentication Required Success Test";
    }

    //Secure Request Authentication Required Fail Test
    results = await secureRequest.send({ 
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
        throw "Secure Request Authentication Required Fail Test";
    }

    //Authentication Not Required Test
    results = await unsecureRequest.send({ 
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