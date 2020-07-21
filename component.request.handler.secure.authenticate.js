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
        const newOptions = JSON.parse(JSON.stringify(options));
        newOptions.path = "/authenticate";
        delegate.register("component.request.handler.secure.authenticate", "authenticate", async ({ headers, data, privatePort }) => {
            if (options.privatePort === privatePort){
                if (!newOptions.hashedPassphrase || !newOptions.hashedPassphraseSalt){
                    const statusMessage = "Success";
                    return { 
                        headers: { "Content-Type":"text/plain" },
                        statusCode: 200, 
                        statusMessage,
                        data: statusMessage
                    };
                }
                let { username, passphrase, fromhost, fromport } = headers;
                const sessionName = `${username}_${newOptions.publicHost}_${newOptions.publicPort}`;
                if (passphrase){
                    const results = utils.hashPassphrase(passphrase, newOptions.hashedPassphraseSalt);
                    if (results.hashedPassphrase ===  newOptions.hashedPassphrase){
                        logging.write("Request Handler Secure Authenticate",`${sessionName} is authenticated.`);
                        const { publicKey, privateKey } = generateKeys(results.hashedPassphrase);
                        headers.token = encryptToBase64Str(utils.getJSONString({ username , fromhost, fromport }), publicKey);
                        headers.encryptionkey = stringToBase64(publicKey);
                        return await delegate.call({context: "component.request.handler.secure"}, { headers, data, privateKey, hashedPassphrase: results.hashedPassphrase });
                    }
                }
                logging.write("Request Handler Secure Authenticate",`failed to authenticate ${sessionName}.`);
                const statusMessage = "Unauthorised";
                return { 
                    headers: { "Content-Type":"text/plain" },
                    statusCode: 401, 
                    statusMessage,
                    data: statusMessage
                };
            }
        });
        requestHandlerUser.handle(newOptions);
    }
};