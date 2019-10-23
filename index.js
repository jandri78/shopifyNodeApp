const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = 'read_products';
const forwardingAddress = "https://678df57c.ngrok.io"; // Replace this with your HTTPS Forwarding address

app.get('/', (req, res) => {
  res.send('Hello World!');
});

//The install route
app.get('/shopify', (req, res) => {
  const shop = req.query.shop;
  if (shop) {
    const state = nonce();
    const redirectUri = forwardingAddress + '/shopify/callback';
    const installUrl = 'https://' + shop +
      '/admin/oauth/authorize?client_id=' + apiKey +
      '&scope=' + scopes +
      '&state=' + state +
      '&redirect_uri=' + redirectUri;

    res.cookie('state', state);
    res.redirect(installUrl);
  } else {
    return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
  }
});



app.listen(3000, () => {
  console.log('Example app listening on port 3000!');
});

//Test 
app.get('/shop', (req, res) => {
    const shopinfoUrl = 'https://93010d8991a3b890a9c18e32c975b7ba:f222c4861876e3521288ade0e0ba703e@dev-jandri.myshopify.com/admin/api/2019-07/shop.json';
    res.redirect(shopinfoUrl);

  });


//#################
app.get('/shopify/callback', (req, res) => {
  const { shop, hmac, code, state } = req.query;
  const stateCookie = cookie.parse(req.headers.cookie).state;

  if (state !== stateCookie) {
    return res.status(403).send('Request origin cannot be verified');
  }

  if (shop && hmac && code) {
    // DONE: Validate request is from Shopify
    const map = Object.assign({}, req.query);
    delete map['signature'];
    delete map['hmac'];
    const message = querystring.stringify(map);
    const providedHmac = Buffer.from(hmac, 'utf-8');
    const generatedHash = Buffer.from(
      crypto
        .createHmac('sha256', apiSecret)
        .update(message)
        .digest('hex'),
        'utf-8'
      );
    let hashEquals = false;

    try {
      hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
    } catch (e) {
      hashEquals = false;
    };

    if (!hashEquals) {
      return res.status(400).send('HMAC validation failed');
    }

    // DONE: Exchange temporary code for a permanent access token
    const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
    const accessTokenPayload = {
      client_id: apiKey,
      client_secret: apiSecret,
      code,
    };

    request.post(accessTokenRequestUrl, { json: accessTokenPayload })
    .then((accessTokenResponse) => {
      const accessToken = accessTokenResponse.access_token;

      // res.status(200).send("Got an access token, let's do something with it");
      const shopRequestUrl = 'https://' + shop + '/admin/api/2019-10/shop.json';
      const shopRequestHeaders = {
        'X-Shopify-Access-Token': accessToken,
      };
      
      request.get(shopRequestUrl, { headers: shopRequestHeaders })
      .then((shopResponse) => {
        
        console.log(shopResponse);
        res.status(200).send(shopResponse);
        res.end(shopResponse);
      })
      .catch((error) => {
        res.status(error.statusCode).send(error.error.error_description);
      });
      
    })
    .catch((error) => {
      res.status(error.statusCode).send(error.error.error_description);
    });

  } else {
    res.status(400).send('Required parameters missing');
  }
});


//Test Webhook 
app.post('/data', (req, res) => {
  console.log(req.body)
  res.status(200).send("Webhook !!!!");
 console.log("arrived")

});