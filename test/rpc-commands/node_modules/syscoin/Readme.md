# node-syscoin 

node-syscoin is a simple wrapper for the Syscoin client's JSON-RPC API.

The API is equivalent to the API document [here](https://en.bitcoin.it/wiki/Original_Syscoin_client/API_Calls_list).
The methods are exposed as lower camelcase methods on the `syscoin.Client`
object, or you may call the API directly using the `cmd` method.

## Install

`npm install syscoin`

## Examples

### Create client
```js
// all config options are optional
var client = new syscoin.Client({
  host: 'localhost',
  port: 8368,
  user: 'username',
  pass: 'password',
  timeout: 180000
});
```

### Create a new offer

```js
client.offerNew('category/subcategory', 'offer title', 1, 100, 'offer description', function(err, result, resHeaders) {
  if (err) return console.log(err);
  console.log('Offer key:', result[1]);
});
```
### Create a new offer directly using `cmd`

```js
client.cmd('offernew', 'category/subcategory', 'offer title', 1, 100, 'offer description', function(err, result, resHeaders) {
  if (err) return console.log(err);
  console.log('Offer key:', result[1]);
});
```

### Batch multiple RPC calls into single HTTP request

```js
var batch = [];
for (var i = 0; i < 10; ++i) {
  batch.push({
    method: 'getnewaddress',
    params: ['myaccount']
  });
}
client.cmd(batch, function(err, address, resHeaders) {
  if (err) return console.log(err);
  console.log('Address:', address);
});
```

## SSL
See [Enabling SSL on original bitcoin client](https://en.bitcoin.it/wiki/Enabling_SSL_on_original_client_daemon).

If you're using this to connect to syscoind across a network it is highly
recommended to enable `ssl`, otherwise an attacker may intercept your RPC credentials
resulting in theft of your syscoins.

When enabling `ssl` by setting the configuration option to `true`, the `sslStrict`
option (verifies the server certificate) will also be enabled by default. It is
highly recommended to specify the `sslCa` as well, even if your syscoind has
a certificate signed by an actual CA, to ensure you are connecting
to your own syscoind.

```js
var client = new syscoin.Client({
  host: 'localhost',
  port: 8332,
  user: 'username',
  pass: 'password',
  ssl: true,
  sslStrict: true,
  sslCa: fs.readFileSync(__dirname + '/myca.cert')
});
```
