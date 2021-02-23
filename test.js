const requestHandlerSecure = require("./component.request.handler.secure.js");
const delegate = require("component.delegate");
const utils = require("utils");
const unsecureRequest = require("component.request.unsecure");
const secureRequest = require("component.request.secure");
const logging = require("logging");
logging.config.add("Request Handler Secure");

( async() => {

    let securedRequest = { name: "localhost", port: 3000, path: "/secure" };
    let unsecuredRequest = { name: "localhost", port: 4000, path: "/unsecure" };
    let context = "component.request.handler.secure";
    
    delegate.register(context, `${securedRequest.port}${securedRequest.path}`, ({  headers, session, data }) => {
        if (session.token){
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
        return { 
            headers: { "Content-Type":"text/plain" },
            statusCode: 200, 
            statusMessage: "Success",
            data: "Success"
        };
    });

    //Secure
    const { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    await requestHandlerSecure.handle({
        host: securedRequest.name,
        port: securedRequest.port,
        path: securedRequest.path,
        hashedPassphrase,
        hashedPassphraseSalt
    });

    //Unsecure
    await requestHandlerSecure.handle({
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
        data: "sensitive data"
    });
    if (results.statusCode !== 200 || results.statusMessage === "Failed"){
        throw "Secure Request Authentication Required Success Test";
    }

    //Authentication Required Test
    results = await unsecureRequest.send({ 
        host: unsecuredRequest.name,
        port: unsecuredRequest.port,
        path: unsecuredRequest.path,
        method: "GET",
        username: "marchuanv",
        fromhost: "localhost",
        fromport: 6000,
        data: ""
    });
    if (results.statusCode !== 401){
        throw "Authentication Required Test Failed";
    }

    process.exit();

})().catch((err)=>{
    console.error(err);
});