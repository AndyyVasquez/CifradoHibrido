const express = require('express');
const crypto = require('crypto');
const app = express();
const cors = require('cors');
app.use(cors());
app.use(express.json());

const {publicKey, privateKey} = crypto.generateKeyPairSync('rsa',{
    modulusLength: 2048,
    publicKeyEncoding: {type: 'spki', format: 'pem'},
    privateKeyEncoding: {type: 'pkcs8', format: 'pem'}
});

app.get('/api/public-key', (req, res) => {
    res.json({publicKey});
});

app.post('/api/secure-message', (req, res)=> {
    const {encryptedMessage, encryptedKey, iv} =req.body;

    try{
        const decryptedKey = crypto.privateDecrypt(
            {key: privateKey, padding : crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash: 'sha256' },
            Buffer.from(encryptedKey, 'base64')
        );

        const decipher = crypto.createDecipheriv(
          'aes-256-cbc',
          decryptedKey,
          Buffer.from(iv, 'base64')
        );

        let decrypted =decipher.update(Buffer.from(encryptedMessage, 'base64'), 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        console.log("Mensaje desencriptado correctamente:", decrypted);
        res.status(200).send("Mensaje recibido");
    } catch(error){
        console.error("Error al desencriptar el mensaje:", error.message);
        res.status(400).send("Error al desencriptar el mensaje");
    }
});

app.listen(3000, () => console.log("Servidor corriendo"))