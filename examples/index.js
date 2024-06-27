const KeyProtectV2 = require('@ibm-cloud/ibm-key-protect/ibm-key-protect-api/v2')
const { IamAuthenticator } = require('@ibm-cloud/ibm-key-protect/auth')

const express = require('express')
const app = express()

const envConfigs = {
    apiKey: process.env.IBMCLOUD_API_KEY,
    iamAuthUrl: "https://iam.cloud.ibm.com",
    serviceUrl: "https://us-south.kms.cloud.ibm.com",
    bluemixInstance: process.env.BLUEMIX_INSTANCE,
}

const authenticator = new IamAuthenticator({
    apikey: envConfigs.apiKey,
    url: envConfigs.iamAuthUrl,
})

const keyProtectClient = new KeyProtectV2({
    authenticator,
    serviceUrl: envConfigs.serviceUrl,
})

app.get('/keys', async function (req, res) {
    let response

    response = await keyProtectClient.getKeys({
        bluemixInstance: envConfigs.bluemixInstance,
    })
    console.log('Get keys result:')
    for(let resource of response.result.resources) {
        console.log(resource)
    }

    res.send(response.result.resources)
})

app.get('/adapters', async function (req, res) {
    let response

    response = await keyProtectClient.getKmipAdapters({
        bluemixInstance: envConfigs.bluemixInstance,
    })
    console.log('Get adapters result:')
    for(let resource of response.result.resources) {
        console.log(resource)
    }

    res.send(response.result.resources)
})

app.get('/adapters', async function (req, res) {
    let response

    response = await keyProtectClient.getKmipAdapters({
        bluemixInstance: envConfigs.bluemixInstance,
    })
    console.log('Get adapters result:')
    for(let resource of response.result.resources) {
        console.log(resource)
    }

    res.send(response.result.resources)
})

app.get('/adapters/:adapterId', async function (req, res) {
    let response

    response = await keyProtectClient.getKmipAdapter({
        bluemixInstance: envConfigs.bluemixInstance,
        id: req.params.adapterId,
    })
    console.log('Get adapter result:')
    for(let resource of response.result.resources) {
        console.log(resource)
    }

    res.send(response.result.resources)
})

app.get('/adapters/:adapterId/certificates', async function (req, res) {
    let response

    response = await keyProtectClient.getKmipClientCertificates({
        bluemixInstance: envConfigs.bluemixInstance,
        adapterId: req.params.adapterId,
    })
    console.log('Get certificates result:')
    for(let resource of response.result.resources) {
        console.log(resource)
    }

    res.send(response.result.resources)
})

app.post('/adapters/', async function (req, res) {
    let response

    response = await keyProtectClient.getKmipClientCertificates({
        bluemixInstance: envConfigs.bluemixInstance,
        adapterId: req.params.adapterId,
    })
    console.log('Get certificates result:')
    for(let resource of response.result.resources) {
        console.log(resource)
    }

    res.send(response.result.resources)
})


app.get('/keys/:id', async function (req, res) {
    let response
    response = await keyProtectClient.getKey({
        bluemixInstance: envConfigs.bluemixInstance,
        id: req.params.id,
    })

    console.log('Get key result:')
    console.log(response.result)

    res.send(response.result)
})

app.get('/keys/:id/version', async function (req, res) {
    let response

    response = await keyProtectClient.getKeyVersions({
        bluemixInstance: envConfigs.bluemixInstance,
        id: req.params.id,
    })

    console.log('Get key version result:')
    console.log(response.result)

    res.send(response.result)
})

app.listen(3000)