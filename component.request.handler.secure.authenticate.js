const utils = require("utils");
const crypto = require("crypto");
const requestHandlerUser = require("component.request.handler.user");
const delegate = require("component.delegate");
const logging = require("logging");
logging.config.add("Request Handler Secure Authenticate");

const stringToBase64 = (str) => {
    return Buffer.from(str, "utf8").toString("base64");
}

const encryptToBase64Str = (dataStr, encryptionkey) => {
    const dataBuf = Buffer.from(dataStr, "utf8");
    return crypto.publicEncrypt( { 
        key: encryptionkey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, dataBuf).toString("base64");
}

const generateKeys = (passphrase) => {
    return crypto.generateKeyPairSync('rsa', { modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem'},
        privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
    });
};

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
                    const { publicKey, privateKey } = generateKeys(results.hashedPassphrase);
                    headers.token = encryptToBase64Str(utils.getJSONString({ username , fromhost, fromport }), publicKey);
                    headers.encryptionkey = stringToBase64(publicKey);
                    return await delegate.call({ context: "component.request.handler.secure", name }, { headers, data, privateKey, hashedPassphrase: results.hashedPassphrase, port });
                }
            }
            return await delegate.call({ context: "component.request.handler.secure", name }, { headers, data, port });
        });
    }
};