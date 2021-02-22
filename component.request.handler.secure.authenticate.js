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
        delegate.register(`component.request.handler.secure.authenticate`, name, async ({ headers, data, port }) => {
            let { username, passphrase, fromhost, fromport } = headers;
            const sessionName = `${username}_${options.host}_${port}`;
            if (passphrase){
                const results = utils.hashPassphrase(passphrase, options.hashedPassphraseSalt);
                if (results.hashedPassphrase ===  options.hashedPassphrase){
                    logging.write("Request Handler Secure Authenticate",`${sessionName} is authenticated.`);
                    const { publicKey, privateKey } = utils.generatePublicPrivateKeys(results.hashedPassphrase);
                    const token = utils.encryptToBase64Str(utils.getJSONString({ username , fromhost, fromport }), publicKey);
                    const encryptionkey = utils.stringToBase64(publicKey);
                    const hashedPassphrase = results.hashedPassphrase;
                    return await delegate.call({ context: "component.request.handler.secure", name }, { headers, data, privateKey, hashedPassphrase, port, encryptionkey, token });
                }
            }
            return await delegate.call({ context: "component.request.handler.secure", name }, { headers, data, port });
        });
    }
};