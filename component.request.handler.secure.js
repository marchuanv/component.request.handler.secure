const utils = require("utils");
const requestHandlerUser = require("component.request.handler.user");
const delegate = require("component.delegate");
const logging = require("logging");
logging.config.add("Request Handler Secure");

module.exports = { 
    handle: (context, options) => {
        const name = `${options.port}${options.path}`;
        requestHandlerUser.handle("component.request.handler.secure", options);
        delegate.register("component.request.handler.secure", name, async ({ session, headers, data }) => {
            const requestUrl = `${options.host}:${options.port}${options.path}`;
            let { passphrase, encryptionkey, token } = headers;
            delete headers["passphrase"];
            delete headers["encryptionkey"];
            delete headers["token"];

            if (session.encryptionkey) {
                if (encryptionkey){
                    if (!session.encryptionkey.remote) {
                        session.encryptionkey.remote = encryptionkey;
                    }
                }
                if (data){
                    logging.write("Request Handler Secure",`decrypting data received from ${requestUrl}`);
                    data = utils.decryptFromBase64Str(data, session.privateKey, session.hashedPassphrase);
                }
            }
           
            if (passphrase) {
                const results = utils.hashPassphrase(passphrase, options.hashedPassphraseSalt);
                if (results.hashedPassphrase ===  options.hashedPassphrase){
                    logging.write("Request Handler Secure",`session ${session.Id} is authenticated.`);
                    const { publicKey, privateKey } = utils.generatePublicPrivateKeys(results.hashedPassphrase);
                    session.publicKey = publicKey;
                    session.privateKey = privateKey;
                    session.token = utils.encryptToBase64Str(utils.getJSONString({ username: session.username, fromhost: session.fromhost, fromport: session.fromport }), publicKey);
                    session.encryptionkey = {
                        local: utils.stringToBase64(publicKey),
                        remote: utils.base64ToString(encryptionkey) 
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
            const res = await delegate.call({ context, name }, { session, data });
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
    }
};