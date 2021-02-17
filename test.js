const requestHandlerAuthenticate = require("./component.request.handler.secure.authenticate.js");
const delegate = require("component.delegate");
const utils = require("utils");
const request = require("component.request");
const logging = require("logging");
logging.config.add("Request Handler Secure Authenticate");
( async() => {

    delegate.register("component.request.handler.secure", "3000/test", ({ privateKey, hashedPassphrase }) => {
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
        host: "localhost",
        port: 3000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });

    //Unsecure
    await requestHandlerAuthenticate.handle({
        host: "localhost",
        port: 4000,
        path: "/test"
    });

    //Authentication Required Success Test
    let results = await request.send({ 
        host: "localhost",
        port: 3000,
        path: "/authenticate",
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
    if (results.statusCode !== 200){
        throw "Authentication Required Success Test Failed";
    }

    //Authentication Required Fail Test
    results = await request.send({ 
        host: "localhost",
        port: 3000,
        path: "/authenticate",
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
    if (results.statusCode !== 401){
        throw "Authentication Required Fail Test Failed";
    }

    //Authentication Not Required Test
    await request.send({
        host: "localhost",
        port: 4000,
        path: "/test",
        method: "GET",
        headers: { 
            username: "marchuanv",
            fromhost: "localhost",
            fromport: 6000
        }, 
        data: "",
        retryCount: 1
    });

})().catch((err)=>{
    console.error(err);
});