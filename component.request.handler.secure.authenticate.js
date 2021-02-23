const utils = require("utils");
const requestHandlerUser = require("component.request.handler.user");
const delegate = require("component.delegate");
const logging = require("logging");
logging.config.add("Request Handler Secure Authenticate");

module.exports = { 
    handle: (options) => {
        if (options.path.indexOf("authenticate") > -1){
            throw new Error("invalid options, the authenticate path is reserved.");
        }
        const name = `${options.port}${options.path}`;
        requestHandlerUser.handle(options);
        //This is a passthrough the component.request.handler.secure component needs to check the headers for security and decide
        delegate.register(`component.request.handler.secure.authenticate`, name, async ({ session, headers, data }) => {
            let { passphrase, encryptionkey, token } = headers;
            delete headers["passphrase"];
            delete headers["encryptionkey"];
            delete headers["token"];
            if (passphrase){
                const results = utils.hashPassphrase(passphrase, options.hashedPassphraseSalt);
                if (results.hashedPassphrase ===  options.hashedPassphrase){
                    logging.write("Request Handler Secure Authenticate",`session ${session.Id} is authenticated.`);
                    const { publicKey, privateKey } = utils.generatePublicPrivateKeys(results.hashedPassphrase);
                    session.publicKey = publicKey;
                    session.privateKey = privateKey;
                    session.token = utils.encryptToBase64Str(utils.getJSONString({ username: session.username, fromhost: session.fromhost, fromport: session.fromport }), publicKey);
                    session.encryptionkey = {
                        local: utils.stringToBase64(publicKey),
                        remote: encryptionkey
                    };
                    session.hashedPassphrase = results.hashedPassphrase;
                }
                return {
                    headers: { 
                        "Content-Type":"text/plain",
                        token: session.token,
                        encryptionkey: session.encryptionkey.local
                    },
                    statusCode: 200,
                    statusMessage:"Authorised",
                    data: ""
                };
            }
            if (session.token !== token){
                return {
                    headers: { 
                        "Content-Type":"text/plain"
                    },
                    statusCode: 401,
                    statusMessage:"Unauthorised",
                    data: ""
                };
            }
            if (session.encryptionkey && !session.encryptionkey.remote){
                session.encryptionkey.remote = encryptionkey;
            }
            return await delegate.call({ context: "component.request.handler.secure", name }, { session, headers, data });
        });
    }
};