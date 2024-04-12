import express from "express";
import multer from "multer";
import fs from 'fs';
import { plainAddPlaceholder } from '@signpdf/placeholder-plain';
import { P12Signer } from '@signpdf/signer-p12';
import signpdf from '@signpdf/signpdf';
import axios from 'axios';

import forge from 'node-forge';

const app = express();
const upload = multer({ storage: multer.memoryStorage(), });

app.post("/signPDF", upload.single('pdfFile'), async (req, res) => {
    // Decodificar el PDF base64
    const pdfBuffer = req.file.buffer;
    try {
        //Create the p12 buffer
        const privateKey = forge.pki.privateKeyFromPem(fs.readFileSync('./certificates/key_audit.pem'));
        const certificate = forge.pki.certificateFromPem(fs.readFileSync('./certificates/certificates.pem'));
        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, [certificate], 'jFkfsr80xebZcOzBK3lh', { algorithm: '3des' });
        const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
        const p12Buffer = Buffer.from(p12Der, 'binary');

        // certificate.p12 is the certificate that is going to be used to sign
        //const certificateBuffer = fs.readFileSync('./certificates/cert_audit.p12');

        const signer = new P12Signer(p12Buffer);
        signer.options.passphrase = "jFkfsr80xebZcOzBK3lh";

        // The PDF needs to have a placeholder for a signature to be signed.
        const pdfWithPlaceholder = plainAddPlaceholder({
            pdfBuffer
        });

        // pdfWithPlaceholder is now a modified buffer that is ready to be signed.
        const signedPdf = await signpdf.default.sign(pdfWithPlaceholder, signer);
        console.log(signedPdf);
        // signedPdf is a Buffer of an electronically signed PDF. Store it.
        const targetPath = `./output/typescript.pdf`;
        fs.writeFileSync(targetPath, signedPdf);
        res.send(signedPdf);
    } catch (error) {
        console.log(error);
    }


})

//Aqui enviamos el archivo a la función lamda
app.post("/signPDFile", upload.single('pdfFile'), async (req, res) => {
    const base64File = req.file.buffer.toString('base64');

    try {
        // Hacer la solicitud HTTP POST a tu función Lambda local usando Axios
        const response = await axios.post('http://localhost:3000/poc/sign-pdf', base64File, {
            headers: {
                'Content-Type': 'application/pdf' // Asegúrate de establecer el tipo de contenido adecuado
            }
        });

        // Verificar si la solicitud fue exitosa
        if (response.status !== 200) {
            throw new Error('Error al invocar la función Lambda:', response.statusText);
        }

        // Devolver la respuesta de la función Lambda
        res.send(response.data);
    } catch (error) {
        console.error('Error al invocar la función Lambda:', error);
        throw error;
    }
})

app.listen(3100, () => {
    console.log("Listening in port 3000");
})