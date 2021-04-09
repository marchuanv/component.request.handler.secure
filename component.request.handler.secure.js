const utils = require("utils");
const component = require("component");
component.load(module).then( async ({ requestHandlerSecure }) => {
    const { channel } = requestHandlerSecure.config;
    requestHandlerSecure.subscribe( { channel }, async ({ session, data, headers, route }) => {
        const requestUrl = `${route.host}:${route.port}${route.path}`;
        let { passphrase, encryptionkey, token } = headers;
        encryptionkey = utils.base64ToString(encryptionkey || "");
        delete headers["passphrase"];
        delete headers["encryptionkey"];
        delete headers["token"];
        if (session.encryptionkey) {
            session.encryptionkey.remote = encryptionkey;
            if (data){
                requestHandlerSecure.log(`decrypting data received from ${requestUrl}`);
                data = utils.decryptFromBase64Str(data, session.privateKey, session.hashedPassphrase);
            }
        }
        if (passphrase) {
            const results = utils.hashPassphrase(passphrase, route.hashedPassphraseSalt);
            if (results.hashedPassphrase ===  route.hashedPassphrase){
                requestHandlerSecure.log(`session ${session.Id} is authenticated.`);
                const { publicKey, privateKey } = utils.generatePublicPrivateKeys(results.hashedPassphrase);
                session.publicKey = publicKey;
                session.privateKey = privateKey;
                session.token = utils.encryptToBase64Str(utils.getJSONString({ username: session.username, fromhost: session.fromhost, fromport: session.fromport }), publicKey);
                session.encryptionkey = {
                    local: utils.stringToBase64(publicKey),
                    remote: encryptionkey 
                };
                session.hashedPassphrase = results.hashedPassphrase;
                token = session.token;
            } else {
                return {
                    headers: { 
                        "Content-Type":"text/plain"
                    },
                    statusCode: 401,
                    statusMessage:"Unauthorised",
                    data: "passphrase or token required"
                };
            }
        } else if (!token) {
            return {
                headers: { 
                    "Content-Type":"text/plain"
                },
                statusCode: 401,
                statusMessage:"Unauthorised",
                data: "passphrase or token required"
            };
        } else if (session.token !== token) {
            return {
                headers: { 
                    "Content-Type":"text/plain"
                },
                statusCode: 401,
                statusMessage:"Unauthorised",
                data: "passphrase or token required"
            };
        }
        const res = await requestHandlerSecure.publish({ name }, { data });
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
        }
        return res;
    });
});