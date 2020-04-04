# ccxt-pkcs11-test
## Install and configure softhsm2
* install softhsm2 package `sudo apt install softhsm2`
* create `$HOME/.config/softhsm2/softhsm2.conf` config file with this content

```ini
# SoftHSM v2 configuration file

directories.tokendir = /your-home-dir/.config/softhsm2/tokens
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = INFO

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = true

```
* create token folder `$HOME/.config/softhsm2/tokens`
* initialize token `softhsm2-util --init-token --slot 0 --label "My token 1"`

## Testing with binance futures testnet
* Add your secret key to soft-token using apikey as label:
`node addsecret.js apikey secretkey`
* List your key:
`node listsecret.js apikey`
* Get balance:
`node index.js --test --futures binance apikey`
* Remove key from sotf-token:
`node removesecret.js apikey`