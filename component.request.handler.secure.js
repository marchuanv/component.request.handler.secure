const utils = require("utils");
const component = require("component");
component.load(module).then( async ({ requestHandlerSecure }) => {
    requestHandlerSecure.receiveDependantComponentNotifications(async ({ session, request, route }) => {
        if (!route.issecure) {  // this module does not handle unsecure routes
            return;
        }
        let { passphrase, encryptionkey, token } = request.headers;
        delete request.headers["passphrase"];
        delete request.headers["encryptionkey"];
        delete request.headers["token"];

        //see if the initial session setup by the user component has gone trough the secure component as well
        const componentTracking = requestHandlerSecure.getCallstack(session.component.tracking.id, false);
        if (componentTracking.find(ct => ct.componentName === requestHandlerSecure.name)) { //if has gone through the security component then there should be a token
            if (!session.token) {
                return {
                    headers: { "Content-Type":"text/plain" },
                    statusCode: 401,
                    statusMessage: "Unauthorised",
                    data: "session has no authorisation token"
                };
            }
            //need to reassure that the token is still in the headers
            if (!token) {
                return {
                    headers: { "Content-Type":"text/plain" },
                    statusCode: 401,
                    statusMessage: "Unauthorised",
                    data: "missing authorisation token in request headers"
                };
            }
            if (userSession.token !== token) {
                return {
                    headers: { "Content-Type":"text/plain" },
                    statusCode: 401,
                    statusMessage: "Unauthorised",
                    data: "unauthorised token"
                };
            }
        } else { //On first request for secure route
            if (!passphrase) {
                return {
                    headers: { "Content-Type":"text/plain" },
                    statusCode: 401,
                    statusMessage: "Unauthorised",
                    data: "missing passphrase in request headers"
                };
            }
            if (!encryptionkey) {
                return {
                    headers: { "Content-Type":"text/plain" },
                    statusCode: 401,
                    statusMessage: "Unauthorised",
                    data: "missing encryptionkey in request headers"
                };
            }
            const results = utils.hashPassphrase(passphrase, route.hashedPassphraseSalt);
            if (results.hashedPassphrase === route.hashedPassphrase){
                requestHandlerSecure.log(`session ${session.Id} is authenticated.`);
                const { publicKey, privateKey } = utils.generatePublicPrivateKeys(results.hashedPassphrase);
                session.publicKey = publicKey;
                session.privateKey = privateKey;
                session.token = utils.encryptToBase64Str(utils.getJSONString({ username: session.username, fromhost: session.fromhost, fromport: session.fromport }), publicKey);
                session.encryptionkey = {
                    local: utils.stringToBase64(publicKey),
                    remote: utils.base64ToString(encryptionkey || "") 
                };
                session.hashedPassphrase = results.hashedPassphrase;
            } else {
                return {
                    headers: { 
                        "Content-Type":"text/plain"
                    },
                    statusCode: 401,
                    statusMessage:"Unauthorised",
                    data: "invalid cridentials"
                };
            }
        }
        if (request.data){
            const requestUrl = `${route.host}:${route.port}${route.path}`;
            requestHandlerSecure.log(`decrypting data received from ${requestUrl}`);
            request.data = utils.decryptFromBase64Str(request.data, session.privateKey, session.hashedPassphrase);
        }
        const res = await requestHandlerSecure.notifyDependantComponents({ session, data: request.data });
        if (res.headers){
            res.headers.token = session.token;
            res.headers.encryptionkey = session.encryptionkey.local;
            if (res.data && session.encryptionkey.remote){
                const encryptedData = utils.encryptToBase64Str(res.data, session.encryptionkey.remote);
                if (encryptedData){
                    res.data = encryptedData;
                } else {
                    return {
                        headers: { "Content-Type":"text/plain" },
                        statusCode: 400,
                        statusMessage:"400 Bad Request",
                        data: "400 Bad Request failed to encrypt data"
                    };
                }
            }
            return res;
        } else {
            return {
                headers: { "Content-Type":"text/plain" },
                statusCode: 500,
                statusMessage:"Internal Server Error",
                data: "calling module responded with no headers"
            };
        }
    });
});