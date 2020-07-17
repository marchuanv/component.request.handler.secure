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
    sessions: [],
    handle: (callingModule, options) => {
        const newOptions = JSON.parse(JSON.stringify(options));
        newOptions.path = "/authenticate";
        const thisModule =  `component.request.handler.secure.authenticate.${newOptions.publicPort}`;
        delegate.register(thisModule, async ({ headers, data }) => {
            let { username, passphrase, fromhost, fromport } = headers;
            const sessionName = `${username}_${newOptions.publicHost}_${newOptions.publicPort}`;
            if (passphrase){
                const results = utils.hashPassphrase(passphrase, newOptions.hashedPassphraseSalt);
                if (results.hashedPassphrase ===  newOptions.hashedPassphrase){
                    logging.write("Request Handler Secure Authenticate",`${sessionName} is authenticated.`);
                    const { publicKey, privateKey } = generateKeys(results.hashedPassphrase);
                    headers.token = encryptToBase64Str(utils.getJSONString({ username , fromhost, fromport }), publicKey);
                    headers.encryptionkey = stringToBase64(publicKey);
                    return await delegate.call(callingModule, { headers, data, privateKey });
                }
            }
            const statusMessage = "Unauthorised";
            logging.write("Request Handler Secure Authenticate",`failed to authenticate ${sessionName}.`);
            return { 
                headers: { "Content-Type":"text/plain", "Content-Length": Buffer.byteLength(statusMessage) },
                statusCode: 401, 
                statusMessage,
                data: statusMessage
            };
        });
        requestHandlerUser.handle(thisModule, newOptions);
    }
};