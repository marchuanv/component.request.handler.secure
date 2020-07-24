const requestHandlerLogin = require("./component.request.handler.secure.authenticate.js");
const delegate = require("component.delegate");
const utils = require("utils");
( async() => {

    delegate.register("component.request.handler.secure", "3000/test", () => {
        let statusMessage = "Success";
        return { 
            headers: { "Content-Type":"text/plain" },
            statusCode: 200, 
            statusMessage,
            data: statusMessage
        };
    });

    delegate.register("component.request.handler.secure", "3000/authenticate", () => {
        let statusMessage = "Success";
        return { 
            headers: { "Content-Type":"text/plain" },
            statusCode: 200, 
            statusMessage,
            data: "authenticated"
        };
    });

    //Secure
    const { hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase("secure1");
    await requestHandlerLogin.handle({
        privateHost: "localhost",
        privatePort: 3000,
        publicHost: "localhost",
        publicPort: 3000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });
    await requestHandlerLogin.handle({
        privateHost: "localhost",
        privatePort: 4000,
        publicHost: "localhost",
        publicPort: 4000,
        path: "/test",
        hashedPassphrase,
        hashedPassphraseSalt
    });

    //Unsecure
    await requestHandlerLogin.handle({
        privateHost: "localhost",
        privatePort: 5000,
        publicHost: "localhost",
        publicPort: 5000,
        path: "/test"
    });

})().catch((err)=>{
    console.error(err);
});